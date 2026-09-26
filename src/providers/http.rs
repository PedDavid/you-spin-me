//! Probes for GitHub and Cloudflare. Provider hosts are fixed here, never
//! taken from an `ApiKey`, so a spec cannot send a key somewhere else.

use std::time::Duration;

use async_trait::async_trait;
use jiff::Timestamp;
use reqwest::StatusCode;
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use url::Url;

use super::{ProbeError, ProbeResult, Prober};
use crate::crd::Provider;

const GITHUB_API: &str = "https://api.github.com/";
const CLOUDFLARE_API: &str = "https://api.cloudflare.com/client/v4/";
const EXPIRATION_HEADER: &str = "github-authentication-token-expiration";

pub struct HttpProber {
    http: reqwest::Client,
    github: Url,
    cloudflare: Url,
}

impl HttpProber {
    pub fn new() -> anyhow::Result<Self> {
        HttpProber::with_endpoints(GITHUB_API.parse()?, CLOUDFLARE_API.parse()?)
    }

    /// Custom endpoints, for tests.
    pub fn with_endpoints(github: Url, cloudflare: Url) -> anyhow::Result<Self> {
        Ok(HttpProber {
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .redirect(reqwest::redirect::Policy::none())
                .user_agent(concat!("you-spin-me/", env!("CARGO_PKG_VERSION")))
                .build()?,
            github,
            cloudflare,
        })
    }

    async fn github(&self, key: &SecretString) -> Result<ProbeResult, ProbeError> {
        #[derive(Deserialize)]
        struct User {
            login: String,
        }
        let res = self
            .http
            .get(self.github.join("user").expect("static path"))
            .bearer_auth(key.expose_secret())
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .send()
            .await
            .map_err(|e| ProbeError::Unavailable(e.without_url().to_string()))?;
        let expires_at = res
            .headers()
            .get(EXPIRATION_HEADER)
            .and_then(|v| v.to_str().ok())
            .and_then(parse_github_expiration);
        match res.status() {
            StatusCode::OK => {
                let user: User = res
                    .json()
                    .await
                    .map_err(|e| ProbeError::Unavailable(e.to_string()))?;
                Ok(ProbeResult {
                    expires_at,
                    identity: Some(user.login),
                })
            }
            // 403 also means rate limiting or a blocked request, so it says
            // nothing about the key. Tokens that cannot read /user (GitHub
            // App tokens) need "skip verification".
            StatusCode::FORBIDDEN => Err(ProbeError::Unavailable(
                "GitHub returned 403 Forbidden (rate limit, or a token without access to /user; skip verification for those)".into(),
            )),
            StatusCode::UNAUTHORIZED => Err(ProbeError::Rejected(
                "GitHub returned 401 Bad credentials".into(),
            )),
            s => Err(ProbeError::Unavailable(format!("GitHub returned {s}"))),
        }
    }

    async fn cloudflare(&self, key: &SecretString) -> Result<ProbeResult, ProbeError> {
        #[derive(Deserialize)]
        struct Envelope {
            #[serde(default)]
            success: bool,
            result: Option<Verify>,
            #[serde(default)]
            errors: Vec<CfError>,
        }
        #[derive(Deserialize)]
        struct Verify {
            id: Option<String>,
            status: String,
            expires_on: Option<Timestamp>,
        }
        #[derive(Deserialize)]
        struct CfError {
            message: String,
        }
        let res = self
            .http
            .get(
                self.cloudflare
                    .join("user/tokens/verify")
                    .expect("static path"),
            )
            .bearer_auth(key.expose_secret())
            .send()
            .await
            .map_err(|e| ProbeError::Unavailable(e.without_url().to_string()))?;
        let status = res.status();
        if status.is_server_error() {
            return Err(ProbeError::Unavailable(format!(
                "Cloudflare returned {status}"
            )));
        }
        let body: Envelope = res
            .json()
            .await
            .map_err(|e| ProbeError::Unavailable(format!("Cloudflare response: {e}")))?;
        match body.result {
            Some(v) if body.success && v.status == "active" => Ok(ProbeResult {
                expires_at: v.expires_on,
                identity: v.id.map(|id| format!("token {id}")),
            }),
            Some(v) => Err(ProbeError::Rejected(format!(
                "Cloudflare reports the token as {}",
                v.status
            ))),
            None => {
                let detail = body
                    .errors
                    .iter()
                    .map(|e| e.message.as_str())
                    .collect::<Vec<_>>()
                    .join("; ");
                Err(ProbeError::Rejected(format!(
                    "Cloudflare returned {status}: {detail} (account-owned tokens cannot be verified here; skip verification for those)"
                )))
            }
        }
    }
}

/// Parses `2027-09-06 12:00:00 UTC` or `2025-09-05 17:55:53 +0500`.
pub fn parse_github_expiration(value: &str) -> Option<Timestamp> {
    let value = value.trim();
    let normalized = match value.strip_suffix(" UTC") {
        Some(v) => format!("{v} +0000"),
        None => value.to_string(),
    };
    jiff::fmt::strtime::parse("%Y-%m-%d %H:%M:%S %z", &normalized)
        .ok()?
        .to_timestamp()
        .ok()
}

#[async_trait]
impl Prober for HttpProber {
    async fn probe(
        &self,
        provider: Provider,
        key: &SecretString,
    ) -> Result<Option<ProbeResult>, ProbeError> {
        match provider {
            Provider::Generic => Ok(None),
            Provider::Github => self.github(key).await.map(Some),
            Provider::Cloudflare => self.cloudflare(key).await.map(Some),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn prober(server: &MockServer) -> HttpProber {
        let base: Url = format!("{}/", server.uri()).parse().unwrap();
        HttpProber::with_endpoints(
            base.join("gh/").unwrap(),
            base.join("cf/client/v4/").unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn parses_github_expiration_formats() {
        assert_eq!(
            parse_github_expiration("2027-09-06 12:00:00 UTC")
                .unwrap()
                .to_string(),
            "2027-09-06T12:00:00Z"
        );
        assert_eq!(
            parse_github_expiration("2025-09-05 17:55:53 +0500")
                .unwrap()
                .to_string(),
            "2025-09-05T12:55:53Z"
        );
        assert!(parse_github_expiration("garbage").is_none());
    }

    #[tokio::test]
    async fn github_reports_login_and_expiry() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/gh/user"))
            .and(header("Authorization", "Bearer ghp_x"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header(EXPIRATION_HEADER, "2099-01-02 03:04:05 UTC")
                    .set_body_json(json!({"login": "octocat", "id": 1})),
            )
            .mount(&server)
            .await;
        let r = prober(&server)
            .await
            .probe(Provider::Github, &SecretString::from("ghp_x"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(r.identity.as_deref(), Some("octocat"));
        assert_eq!(r.expires_at.unwrap().to_string(), "2099-01-02T03:04:05Z");
    }

    #[tokio::test]
    async fn github_keeps_an_expiry_in_the_next_minutes() {
        let server = MockServer::start().await;
        let soon = Timestamp::now() + jiff::SignedDuration::from_mins(2);
        let header_value = soon.strftime("%Y-%m-%d %H:%M:%S UTC").to_string();
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header(EXPIRATION_HEADER, header_value.as_str())
                    .set_body_json(json!({"login": "octocat"})),
            )
            .mount(&server)
            .await;
        let r = prober(&server)
            .await
            .probe(Provider::Github, &SecretString::from("x"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(r.expires_at.unwrap().as_second(), soon.as_second());
    }

    #[tokio::test]
    async fn github_403_does_not_verify_the_key() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(403)
                    .insert_header("x-ratelimit-remaining", "0")
                    .set_body_json(json!({"message": "API rate limit exceeded"})),
            )
            .mount(&server)
            .await;
        let err = prober(&server)
            .await
            .probe(Provider::Github, &SecretString::from("anything"))
            .await
            .unwrap_err();
        assert!(matches!(err, ProbeError::Unavailable(_)), "{err}");
    }

    #[tokio::test]
    async fn github_rejects_bad_credentials() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(401).set_body_json(json!({"message": "Bad credentials"})),
            )
            .mount(&server)
            .await;
        let err = prober(&server)
            .await
            .probe(Provider::Github, &SecretString::from("bad"))
            .await
            .unwrap_err();
        assert!(matches!(err, ProbeError::Rejected(_)));
    }

    #[tokio::test]
    async fn cloudflare_active_token() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/cf/client/v4/user/tokens/verify"))
            .and(header("Authorization", "Bearer cf_x"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "success": true,
                "errors": [],
                "messages": [{"code": 10000, "message": "This API Token is valid and active"}],
                "result": {"id": "ed17574386854bf78a67040be0a770b0", "status": "active",
                           "not_before": "2018-07-01T05:20:00Z", "expires_on": "2099-01-01T00:00:00Z"}
            })))
            .mount(&server)
            .await;
        let r = prober(&server)
            .await
            .probe(Provider::Cloudflare, &SecretString::from("cf_x"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(r.expires_at.unwrap().to_string(), "2099-01-01T00:00:00Z");
        assert_eq!(
            r.identity.as_deref(),
            Some("token ed17574386854bf78a67040be0a770b0")
        );
    }

    #[tokio::test]
    async fn cloudflare_rejections() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(header("Authorization", "Bearer disabled"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "success": true, "errors": [], "result": {"id": "a", "status": "disabled"}
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(header("Authorization", "Bearer invalid"))
            .respond_with(ResponseTemplate::new(401).set_body_json(json!({
                "success": false, "errors": [{"code": 1000, "message": "Invalid API Token"}], "result": null
            })))
            .mount(&server)
            .await;
        let p = prober(&server).await;
        let err = p
            .probe(Provider::Cloudflare, &SecretString::from("disabled"))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("disabled"), "{err}");
        let err = p
            .probe(Provider::Cloudflare, &SecretString::from("invalid"))
            .await
            .unwrap_err();
        assert!(matches!(err, ProbeError::Rejected(_)));
        assert!(err.to_string().contains("Invalid API Token"), "{err}");
        assert!(!err.to_string().contains("invalid\""));
    }

    #[tokio::test]
    async fn generic_has_no_probe() {
        let p = HttpProber::new().unwrap();
        assert_eq!(
            p.probe(Provider::Generic, &SecretString::from("x"))
                .await
                .unwrap(),
            None
        );
    }
}

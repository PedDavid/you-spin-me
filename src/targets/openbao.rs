//! OpenBao KV v2 writer.
//!
//! Needs only `create` and `patch` on `<mount>/data/<path>`: existing
//! secrets are updated with `PATCH` (other keys at the path are kept), and
//! a missing path (404) is created with `POST`. Response bodies of writes are
//! never parsed, and nothing is ever read from `data/` or `metadata/`.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use reqwest::{Method, StatusCode};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tracing::{debug, info};
use url::Url;
use zeroize::Zeroizing;

use super::{TargetError, TargetWriter};
use crate::config::OpenBaoConfig;
use crate::crd::{OpenBaoTarget, TargetSpec};

const TOKEN_MARGIN: Duration = Duration::from_secs(30);

pub enum Auth {
    /// Kubernetes auth method with a projected ServiceAccount token.
    Kubernetes {
        mount: String,
        role: String,
        jwt_file: PathBuf,
    },
    /// A static token read from a file (development).
    TokenFile(PathBuf),
}

struct CachedToken {
    token: SecretString,
    expires: Option<Instant>,
}

pub struct OpenBao {
    addr: Url,
    http: reqwest::Client,
    auth: Auth,
    token: Mutex<Option<CachedToken>>,
}

#[derive(Serialize)]
struct WriteBody<'a> {
    data: BTreeMap<&'a str, &'a str>,
}

#[derive(Deserialize)]
struct LoginResponse {
    auth: LoginAuth,
}

#[derive(Deserialize)]
struct LoginAuth {
    client_token: SecretString,
    #[serde(default)]
    lease_duration: u64,
}

#[derive(Deserialize)]
struct ErrorResponse {
    #[serde(default)]
    errors: Vec<String>,
}

impl OpenBao {
    pub fn new(addr: Url, auth: Auth, ca_pem: Option<&[u8]>) -> anyhow::Result<Self> {
        let mut builder = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none());
        if let Some(pem) = ca_pem {
            builder = builder.add_root_certificate(reqwest::Certificate::from_pem(pem)?);
        }
        Ok(OpenBao {
            addr,
            http: builder.build()?,
            auth,
            token: Mutex::new(None),
        })
    }

    pub fn from_config(cfg: &OpenBaoConfig) -> anyhow::Result<Option<Self>> {
        let Some(addr) = cfg.openbao_addr.clone() else {
            return Ok(None);
        };
        let auth = match &cfg.openbao_token_file {
            Some(path) => Auth::TokenFile(path.clone()),
            None => Auth::Kubernetes {
                mount: cfg.openbao_auth_mount.clone(),
                role: cfg.openbao_role.clone(),
                jwt_file: cfg.openbao_jwt_file.clone(),
            },
        };
        let ca = match &cfg.openbao_ca_file {
            Some(p) => Some(
                std::fs::read(p).map_err(|e| anyhow::anyhow!("reading {}: {e}", p.display()))?,
            ),
            None => None,
        };
        Ok(Some(OpenBao::new(addr, auth, ca.as_deref())?))
    }

    fn url(&self, segments: &[&str]) -> Result<Url, TargetError> {
        let mut url = self.addr.clone();
        {
            let mut path = url
                .path_segments_mut()
                .map_err(|_| TargetError::Store("invalid OpenBao address".into()))?;
            path.pop_if_empty().push("v1");
            for segment in segments {
                for part in segment.split('/').filter(|p| !p.is_empty()) {
                    path.push(part);
                }
            }
        }
        Ok(url)
    }

    async fn token(&self) -> Result<Zeroizing<String>, TargetError> {
        let mut cached = self.token.lock().await;
        if let Some(t) = cached.as_ref()
            && t.expires.is_none_or(|e| Instant::now() + TOKEN_MARGIN < e)
        {
            return Ok(Zeroizing::new(t.token.expose_secret().to_string()));
        }
        let fresh = self.login().await?;
        let value = Zeroizing::new(fresh.token.expose_secret().to_string());
        *cached = Some(fresh);
        Ok(value)
    }

    async fn invalidate(&self) {
        *self.token.lock().await = None;
    }

    async fn login(&self) -> Result<CachedToken, TargetError> {
        match &self.auth {
            Auth::TokenFile(path) => {
                let token = tokio::fs::read_to_string(path).await.map_err(|e| {
                    TargetError::Store(format!("reading OpenBao token {}: {e}", path.display()))
                })?;
                Ok(CachedToken {
                    token: SecretString::from(token.trim()),
                    expires: None,
                })
            }
            Auth::Kubernetes {
                mount,
                role,
                jwt_file,
            } => {
                let jwt =
                    Zeroizing::new(tokio::fs::read_to_string(jwt_file).await.map_err(|e| {
                        TargetError::Store(format!(
                            "reading ServiceAccount token {}: {e}",
                            jwt_file.display()
                        ))
                    })?);
                let url = self.url(&["auth", mount, "login"])?;
                let res = self
                    .http
                    .post(url)
                    .json(&serde_json::json!({ "role": role, "jwt": jwt.trim() }))
                    .send()
                    .await
                    .map_err(|e| TargetError::Store(format!("OpenBao login failed: {e}")))?;
                if !res.status().is_success() {
                    return Err(error_from(res, "OpenBao login").await);
                }
                let body: LoginResponse = res
                    .json()
                    .await
                    .map_err(|e| TargetError::Store(format!("OpenBao login response: {e}")))?;
                info!(role = %role, lease_secs = body.auth.lease_duration, "logged in to OpenBao");
                Ok(CachedToken {
                    token: body.auth.client_token,
                    expires: (body.auth.lease_duration > 0)
                        .then(|| Instant::now() + Duration::from_secs(body.auth.lease_duration)),
                })
            }
        }
    }

    async fn send(
        &self,
        method: Method,
        url: &Url,
        content_type: &str,
        body: &[u8],
    ) -> Result<reqwest::Response, TargetError> {
        let token = self.token().await?;
        self.http
            .request(method, url.clone())
            .header("X-Vault-Token", token.as_str())
            .header("Content-Type", content_type)
            .body(body.to_vec())
            .send()
            .await
            .map_err(|e| TargetError::Store(format!("OpenBao request failed: {}", e.without_url())))
    }

    /// Writes one key of a KV v2 secret, keeping the other keys.
    pub async fn write_key(
        &self,
        target: &OpenBaoTarget,
        value: &SecretString,
    ) -> Result<(), TargetError> {
        let url = self.url(&[&target.mount, "data", &target.path])?;
        let body = Zeroizing::new(
            serde_json::to_vec(&WriteBody {
                data: BTreeMap::from([(target.key.as_str(), value.expose_secret())]),
            })
            .map_err(|e| TargetError::Store(e.to_string()))?,
        );
        let mut retried_login = false;
        loop {
            let res = self
                .send(Method::PATCH, &url, "application/merge-patch+json", &body)
                .await?;
            let status = res.status();
            debug!(target = %target.reference(), %status, "OpenBao PATCH");
            match status {
                s if s.is_success() => return Ok(()),
                StatusCode::NOT_FOUND => {
                    let res = self
                        .send(Method::POST, &url, "application/json", &body)
                        .await?;
                    if res.status().is_success() {
                        return Ok(());
                    }
                    return Err(error_from(res, "OpenBao create").await);
                }
                StatusCode::FORBIDDEN
                    if !retried_login && matches!(self.auth, Auth::Kubernetes { .. }) =>
                {
                    // The cached token may have been revoked or expired early.
                    retried_login = true;
                    self.invalidate().await;
                    continue;
                }
                _ => return Err(error_from(res, "OpenBao write").await),
            }
        }
    }
}

async fn error_from(res: reqwest::Response, action: &str) -> TargetError {
    let status = res.status();
    let detail = res
        .json::<ErrorResponse>()
        .await
        .ok()
        .map(|e| e.errors.join("; "))
        .filter(|d| !d.is_empty())
        .unwrap_or_else(|| status.canonical_reason().unwrap_or("error").to_lowercase());
    TargetError::Store(format!("{action} returned {}: {detail}", status.as_u16()))
}

#[async_trait]
impl TargetWriter for OpenBao {
    async fn write(&self, target: &TargetSpec, value: &SecretString) -> Result<(), TargetError> {
        match &target.openbao {
            Some(t) => self.write_key(t, value).await,
            None => Err(TargetError::Unconfigured),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn target() -> OpenBaoTarget {
        OpenBaoTarget {
            mount: "secret".into(),
            path: "ci/renovate".into(),
            key: "token".into(),
        }
    }

    fn token_file(dir: &std::path::Path, content: &str) -> PathBuf {
        let p = dir.join("token");
        std::fs::write(&p, content).unwrap();
        p
    }

    fn tmpdir() -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("ysm-test-{}", crate::web::auth::random_token()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[tokio::test]
    async fn patches_existing_secret() {
        let server = MockServer::start().await;
        Mock::given(method("PATCH"))
            .and(path("/v1/secret/data/ci/renovate"))
            .and(header("X-Vault-Token", "root"))
            .and(header("Content-Type", "application/merge-patch+json"))
            .and(body_json(serde_json::json!({"data": {"token": "s3cr3t"}})))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"data": {"version": 2}})),
            )
            .expect(1)
            .mount(&server)
            .await;
        let dir = tmpdir();
        let bao = OpenBao::new(
            server.uri().parse().unwrap(),
            Auth::TokenFile(token_file(&dir, "root\n")),
            None,
        )
        .unwrap();
        bao.write_key(&target(), &SecretString::from("s3cr3t"))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn creates_missing_secret_with_post() {
        let server = MockServer::start().await;
        Mock::given(method("PATCH"))
            .respond_with(
                ResponseTemplate::new(404).set_body_json(serde_json::json!({"errors": []})),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/secret/data/ci/renovate"))
            .and(body_json(serde_json::json!({"data": {"token": "s3cr3t"}})))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;
        let dir = tmpdir();
        let bao = OpenBao::new(
            server.uri().parse().unwrap(),
            Auth::TokenFile(token_file(&dir, "root")),
            None,
        )
        .unwrap();
        bao.write_key(&target(), &SecretString::from("s3cr3t"))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn kubernetes_login_is_cached_and_retried_once_on_403() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/auth/kubernetes/login"))
            .and(body_json(
                serde_json::json!({"role": "you-spin-me", "jwt": "sa-jwt"}),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "auth": {"client_token": "t1", "lease_duration": 3600}
            })))
            .expect(2)
            .mount(&server)
            .await;
        // First PATCH is rejected (stale token), the retry succeeds.
        Mock::given(method("PATCH"))
            .respond_with(
                ResponseTemplate::new(403)
                    .set_body_json(serde_json::json!({"errors": ["permission denied"]})),
            )
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .respond_with(ResponseTemplate::new(200))
            .expect(2)
            .mount(&server)
            .await;
        let dir = tmpdir();
        let bao = OpenBao::new(
            server.uri().parse().unwrap(),
            Auth::Kubernetes {
                mount: "kubernetes".into(),
                role: "you-spin-me".into(),
                jwt_file: token_file(&dir, "sa-jwt\n"),
            },
            None,
        )
        .unwrap();
        bao.write_key(&target(), &SecretString::from("a"))
            .await
            .unwrap();
        // Uses the cached token: no third login.
        bao.write_key(&target(), &SecretString::from("b"))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn errors_carry_openbao_message_but_never_the_value() {
        let server = MockServer::start().await;
        Mock::given(method("PATCH"))
            .respond_with(ResponseTemplate::new(403).set_body_json(
                serde_json::json!({"errors": ["1 error occurred:\n\t* permission denied\n\n"]}),
            ))
            .mount(&server)
            .await;
        let dir = tmpdir();
        let bao = OpenBao::new(
            server.uri().parse().unwrap(),
            Auth::TokenFile(token_file(&dir, "root")),
            None,
        )
        .unwrap();
        let err = bao
            .write_key(&target(), &SecretString::from("super-secret-value"))
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("403"), "{err}");
        assert!(err.contains("permission denied"), "{err}");
        assert!(!err.contains("super-secret-value"));
    }

    #[test]
    fn urls_are_built_from_segments() {
        let bao = OpenBao::new(
            "https://bao.example:8200/".parse().unwrap(),
            Auth::TokenFile("/x".into()),
            None,
        )
        .unwrap();
        assert_eq!(
            bao.url(&["secret", "data", "/a/b c/"]).unwrap().as_str(),
            "https://bao.example:8200/v1/secret/data/a/b%20c"
        );
    }
}

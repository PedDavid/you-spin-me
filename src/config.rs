//! Command-line flags, each also settable through a `YSM_*` environment variable.

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Parser;
use jiff::SignedDuration;
use url::Url;

use crate::duration;
use crate::schedule::Thresholds;
use crate::validation::PathAllowList;

#[derive(Parser, Debug, Clone)]
#[command(
    name = "you-spin-me",
    version,
    about = "Inventory and rotation of external API keys"
)]
pub struct Config {
    /// Address for the UI.
    #[arg(long, env = "YSM_LISTEN", default_value = "0.0.0.0:8080")]
    pub listen: SocketAddr,

    /// Address for /metrics, /healthz and /readyz (no auth).
    #[arg(long, env = "YSM_METRICS_LISTEN", default_value = "0.0.0.0:9090")]
    pub metrics_listen: SocketAddr,

    /// Namespace holding the ApiKeys. Defaults to the pod's own namespace.
    #[arg(long, env = "YSM_NAMESPACE")]
    pub namespace: Option<String>,

    /// Public URL of the UI, e.g. https://keys.example.com. Used for the OIDC
    /// redirect, the Origin check on POSTs and links in alerts.
    #[arg(long, env = "YSM_PUBLIC_URL", default_value = "http://localhost:8080")]
    pub public_url: Url,

    /// Default warning threshold before a key's deadline.
    #[arg(long, env = "YSM_WARN_BEFORE", default_value = "14d", value_parser = parse_duration)]
    pub warn_before: SignedDuration,

    /// Default critical threshold before a key's deadline.
    #[arg(long, env = "YSM_CRITICAL_BEFORE", default_value = "5d", value_parser = parse_duration)]
    pub critical_before: SignedDuration,

    /// Comma-separated OpenBao path globs (`<mount>/data/<path>`, policy
    /// syntax) that targets may use. Only for early feedback: the OpenBao
    /// policy is the real boundary.
    #[arg(
        long,
        env = "YSM_ALLOWED_PATHS",
        default_value = "*",
        value_delimiter = ','
    )]
    pub allowed_paths: Vec<String>,

    #[command(flatten)]
    pub auth: AuthConfig,

    #[command(flatten)]
    pub openbao: OpenBaoConfig,

    /// Serve sample data from memory, without Kubernetes or OpenBao. Uses
    /// --insecure-dev-auth unless OIDC is configured. For trying out the UI only.
    #[arg(long, env = "YSM_DEMO")]
    pub demo: bool,

    /// Log as JSON.
    #[arg(long, env = "YSM_LOG_JSON")]
    pub log_json: bool,
}

#[derive(clap::Args, Debug, Clone)]
pub struct AuthConfig {
    /// OIDC issuer URL.
    #[arg(long, env = "YSM_OIDC_ISSUER")]
    pub oidc_issuer: Option<Url>,

    #[arg(long, env = "YSM_OIDC_CLIENT_ID")]
    pub oidc_client_id: Option<String>,

    /// File containing the OIDC client secret.
    #[arg(long, env = "YSM_OIDC_CLIENT_SECRET_FILE")]
    pub oidc_client_secret_file: Option<PathBuf>,

    /// Space-separated scopes to request besides `openid`.
    #[arg(long, env = "YSM_OIDC_SCOPES", default_value = "profile email groups")]
    pub oidc_scopes: String,

    /// ID token claim holding the user's groups or roles.
    #[arg(long, env = "YSM_ADMIN_CLAIM", default_value = "groups")]
    pub admin_claim: String,

    /// Value of the admin claim that grants admin rights.
    #[arg(long, env = "YSM_ADMIN_VALUE", default_value = "you-spin-me-admins")]
    pub admin_value: String,

    /// Session lifetime.
    #[arg(long, env = "YSM_SESSION_TTL", default_value = "8h", value_parser = parse_duration)]
    pub session_ttl: SignedDuration,

    /// If set, recording or rotating a key requires a login no older than
    /// this (step-up auth).
    #[arg(long, env = "YSM_STEP_UP_MAX_AGE", value_parser = parse_duration)]
    pub step_up_max_age: Option<SignedDuration>,

    /// File containing at least 64 random bytes (raw or base64) used to
    /// encrypt session cookies. Random per process if unset, which logs
    /// everyone out on restart.
    #[arg(long, env = "YSM_COOKIE_KEY_FILE")]
    pub cookie_key_file: Option<PathBuf>,

    /// Skip OIDC and treat every visitor as an admin. Never use in production.
    #[arg(long, env = "YSM_INSECURE_DEV_AUTH")]
    pub insecure_dev_auth: bool,
}

#[derive(clap::Args, Debug, Clone)]
pub struct OpenBaoConfig {
    /// OpenBao address, e.g. https://openbao.openbao.svc:8200.
    #[arg(long, env = "YSM_OPENBAO_ADDR")]
    pub openbao_addr: Option<Url>,

    /// Mount path of the Kubernetes auth method.
    #[arg(long, env = "YSM_OPENBAO_AUTH_MOUNT", default_value = "kubernetes")]
    pub openbao_auth_mount: String,

    /// Role to log in with.
    #[arg(long, env = "YSM_OPENBAO_ROLE", default_value = "you-spin-me")]
    pub openbao_role: String,

    /// ServiceAccount token presented to the Kubernetes auth method.
    #[arg(
        long,
        env = "YSM_OPENBAO_JWT_FILE",
        default_value = "/var/run/secrets/openbao/token"
    )]
    pub openbao_jwt_file: PathBuf,

    /// Use a static token from this file instead of Kubernetes auth (development).
    #[arg(long, env = "YSM_OPENBAO_TOKEN_FILE")]
    pub openbao_token_file: Option<PathBuf>,

    /// Extra PEM CA bundle for OpenBao's TLS certificate.
    #[arg(long, env = "YSM_OPENBAO_CA_FILE")]
    pub openbao_ca_file: Option<PathBuf>,
}

fn parse_duration(s: &str) -> Result<SignedDuration, String> {
    duration::parse(s).map_err(|e| e.to_string())
}

impl Config {
    pub fn thresholds(&self) -> Thresholds {
        Thresholds {
            warn_before: self.warn_before,
            critical_before: self.critical_before,
        }
    }

    pub fn allowed_paths(&self) -> PathAllowList {
        PathAllowList::new(self.allowed_paths.iter().cloned())
    }

    /// `scheme://host[:port]` of the public URL, as sent in `Origin` headers.
    pub fn public_origin(&self) -> String {
        self.public_url.origin().ascii_serialization()
    }

    /// The namespace to watch: the flag, else the pod's own namespace.
    pub fn resolve_namespace(&self) -> anyhow::Result<String> {
        if let Some(ns) = &self.namespace {
            return Ok(ns.clone());
        }
        const SA_NAMESPACE: &str = "/var/run/secrets/kubernetes.io/serviceaccount/namespace";
        std::fs::read_to_string(SA_NAMESPACE)
            .map(|s| s.trim().to_string())
            .map_err(|e| anyhow::anyhow!("--namespace not set and {SA_NAMESPACE} unreadable: {e}"))
    }

    /// Absolute URL for a path under the public URL.
    pub fn url_for(&self, path: &str) -> String {
        let base = self.public_url.as_str().trim_end_matches('/');
        format!("{base}{path}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_parse() {
        let cfg = Config::try_parse_from(["you-spin-me"]).unwrap();
        assert_eq!(cfg.thresholds(), Thresholds::default());
        assert!(cfg.allowed_paths().allows("secret/data/x"));
        assert_eq!(cfg.public_origin(), "http://localhost:8080");
        assert_eq!(cfg.url_for("/keys/a"), "http://localhost:8080/keys/a");
    }

    #[test]
    fn allowed_paths_split_on_commas() {
        let cfg = Config::try_parse_from([
            "you-spin-me",
            "--allowed-paths",
            "secret/data/ci/*,kv/data/+/api/*",
        ])
        .unwrap();
        let allowed = cfg.allowed_paths();
        assert!(allowed.allows("kv/data/home/api/x"));
        assert!(!allowed.allows("secret/data/other"));
    }
}

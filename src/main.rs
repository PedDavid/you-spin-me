use std::sync::Arc;

use anyhow::Context;
use axum_extra::extract::cookie::Key;
use base64::Engine as _;
use clap::Parser;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use you_spin_me::config::Config;
use you_spin_me::demo;
use you_spin_me::k8s::KubeRepository;
use you_spin_me::metrics::Metrics;
use you_spin_me::repo::{MemoryRepository, Repository};
use you_spin_me::web::auth::AuthMode;
use you_spin_me::web::{self, AppState};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cfg = Config::parse();
    init_tracing(cfg.log_json);

    let repo: Arc<dyn Repository> = if cfg.demo {
        warn!("demo mode: serving sample data from memory");
        Arc::new(MemoryRepository::new(demo::sample_keys(
            jiff::Timestamp::now(),
        )))
    } else {
        let namespace = cfg.resolve_namespace()?;
        let client = kube::Client::try_default()
            .await
            .context("connecting to Kubernetes")?;
        info!(%namespace, "watching ApiKeys");
        KubeRepository::start(client, &namespace, cfg.allowed_paths())
    };
    let metrics = Metrics::new(repo.clone(), cfg.thresholds());
    let demo_dev_auth = cfg.demo && cfg.auth.oidc_issuer.is_none();
    let auth = AuthMode::from_config(&cfg.auth, &cfg.public_url, demo_dev_auth)?;
    let cookie_key = load_cookie_key(&cfg)?;

    let ops = web::ops_router(repo.clone(), metrics.clone());
    let state = AppState::new(cfg.clone(), repo, metrics, auth, cookie_key);
    let app = web::router(state);

    let ui_listener = tokio::net::TcpListener::bind(cfg.listen).await?;
    let ops_listener = tokio::net::TcpListener::bind(cfg.metrics_listen).await?;
    info!(ui = %cfg.listen, ops = %cfg.metrics_listen, "listening");
    tokio::select! {
        r = axum::serve(ui_listener, app).with_graceful_shutdown(shutdown()) => r?,
        r = axum::serve(ops_listener, ops).with_graceful_shutdown(shutdown()) => r?,
    }
    Ok(())
}

fn init_tracing(json: bool) {
    let filter = EnvFilter::try_from_env("YSM_LOG")
        .unwrap_or_else(|_| EnvFilter::new("info,tower_http=info,kube=warn"));
    let builder = tracing_subscriber::fmt().with_env_filter(filter);
    if json {
        builder.json().init();
    } else {
        builder.init();
    }
}

fn load_cookie_key(cfg: &Config) -> anyhow::Result<Key> {
    let Some(path) = &cfg.auth.cookie_key_file else {
        warn!("no --cookie-key-file: sessions will not survive a restart");
        return Ok(Key::generate());
    };
    let raw = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let trimmed = String::from_utf8_lossy(&raw).trim().to_string();
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(&trimmed)
        .ok()
        .filter(|b| b.len() >= 64)
        .unwrap_or(raw);
    Key::try_from(bytes.as_slice())
        .map_err(|_| anyhow::anyhow!("cookie key must be at least 64 bytes (raw or base64)"))
}

async fn shutdown() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        if let Ok(mut s) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            s.recv().await;
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = term => {},
    }
}

//! Shared test harness for the HTTP tests.
#![allow(dead_code)]

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, header};
use axum::response::IntoResponse;
use axum_extra::extract::PrivateCookieJar;
use axum_extra::extract::cookie::{Cookie, Key};
use clap::Parser;
use http_body_util::BodyExt;

use you_spin_me::config::Config;
use you_spin_me::crd::{ApiKey, ApiKeySpec, OpenBaoTarget, TargetSpec};
use you_spin_me::metrics::Metrics;
use you_spin_me::providers::NoProbe;
use you_spin_me::repo::{MemoryRepository, Repository};
use you_spin_me::rotation::Rotator;
use you_spin_me::targets::{MemoryWriter, TargetWriter};
use you_spin_me::web::auth::{AuthMode, SESSION_COOKIE, Session};
use you_spin_me::web::{AppState, router};

pub const ORIGIN: &str = "http://localhost:8080";

pub struct Harness {
    pub app: Router,
    pub repo: Arc<MemoryRepository>,
    pub key: Key,
}

pub fn harness(dev_auth: bool) -> Harness {
    harness_with(dev_auth, Arc::new(MemoryWriter::default()))
}

pub fn harness_with(dev_auth: bool, writer: Arc<dyn TargetWriter>) -> Harness {
    harness_args(dev_auth, writer, &[])
}

pub fn harness_args(
    dev_auth: bool,
    writer: Arc<dyn TargetWriter>,
    extra: &[&'static str],
) -> Harness {
    let mut args = vec!["you-spin-me"];
    args.extend_from_slice(extra);
    if dev_auth {
        args.push("--insecure-dev-auth");
    } else {
        args.extend([
            "--oidc-issuer",
            "https://idp.example.com",
            "--oidc-client-id",
            "you-spin-me",
        ]);
    }
    let cfg = Config::try_parse_from(args).unwrap();
    let repo = Arc::new(MemoryRepository::new([ApiKey::new(
        "renovate",
        ApiKeySpec {
            display_name: Some("Renovate token".into()),
            renew_url: Some("https://github.com/settings/tokens".into()),
            targets: vec![TargetSpec {
                openbao: Some(OpenBaoTarget {
                    mount: "secret".into(),
                    path: "ci/renovate".into(),
                    key: "token".into(),
                }),
            }],
            consumers: vec!["GitHub Actions secret".into()],
            ..Default::default()
        },
    )]));
    let dyn_repo: Arc<dyn Repository> = repo.clone();
    let metrics = Metrics::new(dyn_repo.clone(), cfg.thresholds());
    let auth = AuthMode::from_config(&cfg.auth, &cfg.public_url, false).unwrap();
    let key = Key::generate();
    let rotator = Arc::new(Rotator::new(
        dyn_repo.clone(),
        writer,
        Arc::new(NoProbe),
        metrics.clone(),
        cfg.allowed_paths(),
    ));
    let state = AppState::new(cfg, dyn_repo, metrics, auth, rotator, key.clone());
    Harness {
        app: router(state),
        repo,
        key,
    }
}

pub fn session(admin: bool) -> Session {
    let now = jiff::Timestamp::now().as_second();
    Session {
        sub: "u1".into(),
        name: if admin { "alice" } else { "bob" }.into(),
        admin,
        csrf: "csrf-token".into(),
        auth_time: Some(now),
        exp: now + 3600,
    }
}

/// Encrypts a session exactly as the login callback does.
pub fn session_cookie(key: &Key, session: &Session) -> String {
    let jar = PrivateCookieJar::new(key.clone()).add(Cookie::new(
        SESSION_COOKIE,
        serde_json::to_string(session).unwrap(),
    ));
    let res = (jar, ()).into_response();
    let set_cookie = res.headers()[header::SET_COOKIE].to_str().unwrap();
    set_cookie.split(';').next().unwrap().to_string()
}

pub async fn body(res: axum::response::Response) -> String {
    String::from_utf8(res.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap()
}

pub fn rotate_request(cookie: &str, csrf: &str, value: &str) -> Request<Body> {
    let body: String = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("_csrf", csrf)
        .append_pair("key", value)
        .finish();
    Request::post("/keys/renovate/rotate")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, cookie)
        .header(header::ORIGIN, ORIGIN)
        .header("hx-request", "true")
        .body(Body::from(body))
        .unwrap()
}

//! HTTP-level tests of the UI router: auth, CSRF, Origin checks and pages.

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use axum::response::IntoResponse;
use axum_extra::extract::PrivateCookieJar;
use axum_extra::extract::cookie::{Cookie, Key};
use clap::Parser;
use http_body_util::BodyExt;
use tower::ServiceExt;

use you_spin_me::config::Config;
use you_spin_me::crd::{ApiKey, ApiKeySpec};
use you_spin_me::metrics::Metrics;
use you_spin_me::repo::{MemoryRepository, Repository};
use you_spin_me::web::auth::{AuthMode, SESSION_COOKIE, Session};
use you_spin_me::web::{AppState, router};

const ORIGIN: &str = "http://localhost:8080";

struct Harness {
    app: Router,
    repo: Arc<MemoryRepository>,
    key: Key,
}

fn harness(dev_auth: bool) -> Harness {
    let mut args = vec!["you-spin-me"];
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
            ..Default::default()
        },
    )]));
    let dyn_repo: Arc<dyn Repository> = repo.clone();
    let metrics = Metrics::new(dyn_repo.clone(), cfg.thresholds());
    let auth = AuthMode::from_config(&cfg.auth, &cfg.public_url, false).unwrap();
    let key = Key::generate();
    let state = AppState::new(cfg, dyn_repo, metrics, auth, key.clone());
    Harness {
        app: router(state),
        repo,
        key,
    }
}

fn session(admin: bool) -> Session {
    let now = jiff::Timestamp::now().as_second();
    Session {
        sub: "u1".into(),
        name: if admin { "alice" } else { "bob" }.into(),
        admin,
        csrf: "csrf-token".into(),
        auth_time: now,
        exp: now + 3600,
    }
}

/// Encrypts a session exactly as the login callback does.
fn session_cookie(key: &Key, session: &Session) -> String {
    let jar = PrivateCookieJar::new(key.clone()).add(Cookie::new(
        SESSION_COOKIE,
        serde_json::to_string(session).unwrap(),
    ));
    let res = (jar, ()).into_response();
    let set_cookie = res.headers()[header::SET_COOKIE].to_str().unwrap();
    set_cookie.split(';').next().unwrap().to_string()
}

async fn body(res: axum::response::Response) -> String {
    String::from_utf8(res.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap()
}

fn record_request(cookie: Option<&str>, origin: Option<&str>, csrf: &str) -> Request<Body> {
    let mut req = Request::post("/keys/renovate/record")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    if let Some(c) = cookie {
        req = req.header(header::COOKIE, c);
    }
    if let Some(o) = origin {
        req = req.header(header::ORIGIN, o);
    }
    req.body(Body::from(format!(
        "_csrf={csrf}&rotated_at=2026-01-01&expires_at=2026-12-31"
    )))
    .unwrap()
}

#[tokio::test]
async fn unauthenticated_users_are_sent_to_login() {
    let h = harness(false);
    let res = h
        .app
        .oneshot(Request::get("/keys/renovate").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        res.headers()[header::LOCATION],
        "/auth/login?next=%2Fkeys%2Frenovate"
    );
}

#[tokio::test]
async fn htmx_requests_get_hx_redirect() {
    let h = harness(false);
    let res = h
        .app
        .oneshot(
            Request::get("/?q=x")
                .header("hx-request", "true")
                .header("hx-current-url", "http://localhost:8080/?q=x")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(res.headers()["hx-redirect"], "/auth/login?next=%2F");
}

#[tokio::test]
async fn logged_in_users_see_pages_with_security_headers() {
    let h = harness(false);
    let cookie = session_cookie(&h.key, &session(false));
    let res = h
        .app
        .oneshot(
            Request::get("/")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let csp = res.headers()[header::CONTENT_SECURITY_POLICY]
        .to_str()
        .unwrap();
    assert!(csp.contains("script-src 'self'"));
    assert_eq!(res.headers()[header::CACHE_CONTROL], "no-store");
    let html = body(res).await;
    assert!(html.contains("Renovate token"));
    // Viewers get no admin actions.
    assert!(!html.contains("Record rotation"));
}

#[tokio::test]
async fn tampered_session_cookie_is_rejected() {
    let h = harness(false);
    let res = h
        .app
        .oneshot(
            Request::get("/")
                .header(header::COOKIE, format!("{SESSION_COOKIE}=forged"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn record_requires_same_origin() {
    let h = harness(false);
    let cookie = session_cookie(&h.key, &session(true));
    for origin in [None, Some("https://evil.example")] {
        let res = h
            .app
            .clone()
            .oneshot(record_request(Some(&cookie), origin, "csrf-token"))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN, "origin {origin:?}");
    }
    assert!(h.repo.get("renovate").unwrap().status.is_none());
}

#[tokio::test]
async fn record_requires_csrf_token() {
    let h = harness(false);
    let cookie = session_cookie(&h.key, &session(true));
    let res = h
        .app
        .oneshot(record_request(Some(&cookie), Some(ORIGIN), "wrong"))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    assert!(h.repo.get("renovate").unwrap().status.is_none());
}

#[tokio::test]
async fn record_requires_admin() {
    let h = harness(false);
    let cookie = session_cookie(&h.key, &session(false));
    let res = h
        .app
        .oneshot(record_request(Some(&cookie), Some(ORIGIN), "csrf-token"))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    assert!(h.repo.get("renovate").unwrap().status.is_none());
}

#[tokio::test]
async fn admin_can_record_rotation() {
    let h = harness(false);
    let cookie = session_cookie(&h.key, &session(true));
    let res = h
        .app
        .oneshot(record_request(Some(&cookie), Some(ORIGIN), "csrf-token"))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        res.headers()[header::LOCATION],
        "/keys/renovate?notice=recorded"
    );
    let status = h.repo.get("renovate").unwrap().status.clone().unwrap();
    assert_eq!(status.rotated_by.as_deref(), Some("alice"));
    assert_eq!(
        status.expires_at.unwrap().0.to_string(),
        "2026-12-31T00:00:00Z"
    );
    assert_eq!(h.repo.events()[0].1.reason, "Recorded");
}

#[tokio::test]
async fn htmx_filter_returns_fragment_with_oob_chips() {
    let h = harness(true);
    let res = h
        .app
        .oneshot(
            Request::get("/?q=renov&state=unknown")
                .header("hx-request", "true")
                .header("hx-target", "keys-table")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let html = body(res).await;
    assert!(!html.contains("<html"));
    assert!(html.contains("Renovate token"));
    assert!(html.contains(r#"id="state-chips""#));
    assert!(html.contains(r#"hx-swap-oob="true""#));
}

#[tokio::test]
async fn unknown_key_is_404_and_assets_are_served() {
    let h = harness(true);
    let res = h
        .app
        .clone()
        .oneshot(Request::get("/keys/nope").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    let res = h
        .app
        .oneshot(
            Request::get("/assets/js/app.js")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert!(
        res.headers()[header::CONTENT_TYPE]
            .to_str()
            .unwrap()
            .contains("javascript")
    );
}

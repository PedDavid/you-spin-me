//! HTTP-level tests of the UI router: auth, CSRF, Origin checks and pages.

mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use tower::ServiceExt;

use common::*;
use you_spin_me::crd::Actor;
use you_spin_me::repo::Repository;
use you_spin_me::targets::MemoryWriter;
use you_spin_me::web::auth::SESSION_COOKIE;

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
    // The audit identity is the stable subject; the name is only a label.
    assert_eq!(status.rotated_by, Some(Actor::new("u1", "alice")));
    assert_eq!(status.history[0].by.sub, "u1");
    assert_eq!(
        status.expires_at.unwrap().0.to_string(),
        "2026-12-31T00:00:00Z"
    );
    assert_eq!(h.repo.events()[0].1.reason, "Recorded");
}

#[tokio::test]
async fn recording_needs_a_recent_login_with_step_up() {
    let h = harness_args(
        false,
        Arc::new(MemoryWriter::default()),
        &["--step-up-max-age", "15m"],
    );
    let mut stale = session(true);
    stale.auth_time = stale.auth_time.map(|t| t - 20 * 60);
    let res = h
        .app
        .clone()
        .oneshot(record_request(
            Some(&session_cookie(&h.key, &stale)),
            Some(ORIGIN),
            "csrf-token",
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        res.headers()[header::LOCATION],
        "/auth/login?reauth=true&next=%2Fkeys%2Frenovate%3Fnotice%3Dreauth"
    );
    assert!(h.repo.get("renovate").unwrap().status.is_none());
    assert!(h.repo.events().is_empty());

    let fresh = session(true);
    let res = h
        .app
        .oneshot(record_request(
            Some(&session_cookie(&h.key, &fresh)),
            Some(ORIGIN),
            "csrf-token",
        ))
        .await
        .unwrap();
    assert_eq!(
        res.headers()[header::LOCATION],
        "/keys/renovate?notice=recorded"
    );
    assert!(h.repo.get("renovate").unwrap().status.is_some());
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

#[tokio::test]
async fn rotate_requires_admin() {
    let h = harness(false);
    let cookie = session_cookie(&h.key, &session(false));
    let res = h
        .app
        .oneshot(rotate_request(&cookie, "csrf-token", "new"))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    assert!(h.repo.get("renovate").unwrap().status.is_none());
}

#[tokio::test]
async fn rotate_errors_are_rendered_into_the_dialog() {
    let writer = Arc::new(MemoryWriter::default());
    writer.fail(
        "openbao/secret/ci/renovate#token",
        "OpenBao write returned 403: permission denied",
    );
    let h = harness_with(false, writer);
    let cookie = session_cookie(&h.key, &session(true));
    let res = h
        .app
        .clone()
        .oneshot(rotate_request(&cookie, "csrf-token", "value"))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert!(!res.headers().contains_key("hx-trigger"));
    let html = body(res).await;
    assert!(html.contains("Some targets failed"));
    assert!(html.contains("permission denied"));

    let res = h
        .app
        .oneshot(rotate_request(&cookie, "csrf-token", "   "))
        .await
        .unwrap();
    let html = body(res).await;
    assert!(html.contains("Nothing was written"));
    assert!(html.contains("the key is empty"));
}

#[tokio::test]
async fn unsafe_renew_urls_are_not_rendered_as_links() {
    use you_spin_me::crd::{ApiKey, ApiKeySpec};
    let h = harness(true);
    h.repo.insert(ApiKey::new(
        "evil",
        ApiKeySpec {
            renew_url: Some("javascript:alert(document.cookie)".into()),
            ..Default::default()
        },
    ));
    for path in ["/", "/keys/evil"] {
        let res = h
            .app
            .clone()
            .oneshot(Request::get(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let html = body(res).await;
        assert!(!html.contains("javascript:"), "{path}");
    }
}

#[tokio::test]
async fn search_returns_matching_keys_for_the_palette() {
    let h = harness(true);
    let res = h
        .app
        .clone()
        .oneshot(Request::get("/search?q=renov").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let html = body(res).await;
    assert!(html.contains(r#"href="/keys/renovate""#));
    assert!(html.contains("Renovate token"));

    let res = h
        .app
        .oneshot(Request::get("/search?q=zzz").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert!(!body(res).await.contains("menuitem"));
}

#[tokio::test]
async fn step_up_requires_a_recent_login_to_rotate() {
    let writer = Arc::new(MemoryWriter::default());
    let h = harness_args(false, writer.clone(), &["--step-up-max-age", "10m"]);
    let mut stale = session(true);
    stale.auth_time = stale.auth_time.map(|t| t - 3600);
    let cookie = session_cookie(&h.key, &stale);
    let res = h
        .app
        .clone()
        .oneshot(rotate_request(&cookie, "csrf-token", "value"))
        .await
        .unwrap();
    let html = body(res).await;
    assert!(html.contains("Please log in again"), "{html}");
    assert!(html.contains("/auth/login?reauth=1&amp;next=/keys/renovate"));
    assert!(writer.writes().is_empty());

    let fresh = session_cookie(&h.key, &session(true));
    let res = h
        .app
        .oneshot(rotate_request(&fresh, "csrf-token", "value"))
        .await
        .unwrap();
    assert!(body(res).await.contains("Key rotated"));
    assert_eq!(writer.writes().len(), 1);
}

fn on_demand_key() -> you_spin_me::crd::ApiKey {
    use you_spin_me::crd::{ApiKey, ApiKeySpec, Lifecycle};
    ApiKey::new(
        "adhoc",
        ApiKeySpec {
            lifecycle: Lifecycle::OnDemand,
            renew_url: Some("https://github.com/settings/personal-access-tokens/new".into()),
            ..Default::default()
        },
    )
}

fn opened_request(name: &str, cookie: &str, csrf: &str) -> Request<Body> {
    Request::post(format!("/keys/{name}/opened"))
        .header(
            header::CONTENT_TYPE,
            "application/x-www-form-urlencoded;charset=UTF-8",
        )
        .header(header::COOKIE, cookie)
        .header(header::ORIGIN, ORIGIN)
        .body(Body::from(format!("_csrf={csrf}")))
        .unwrap()
}

#[tokio::test]
async fn opening_an_on_demand_key_is_audited_for_any_user() {
    let h = harness(false);
    h.repo.insert(on_demand_key());
    // Viewers can open the create page too; it is their click that is recorded.
    let cookie = session_cookie(&h.key, &session(false));

    let res = h
        .app
        .clone()
        .oneshot(opened_request("adhoc", &cookie, "wrong"))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);

    let res = h
        .app
        .clone()
        .oneshot(opened_request("adhoc", &cookie, "csrf-token"))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    let status = h.repo.get("adhoc").unwrap().status.clone().unwrap();
    assert_eq!(status.last_used_by, Some(Actor::new("u1", "bob")));
    assert_eq!(h.repo.events()[0].1.reason, "CreatePageOpened");

    // Managed keys are not audited this way.
    let res = h
        .app
        .oneshot(opened_request("renovate", &cookie, "csrf-token"))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn on_demand_keys_show_create_instead_of_rotation_actions() {
    let h = harness(true);
    h.repo.insert(on_demand_key());
    let res = h
        .app
        .clone()
        .oneshot(Request::get("/keys/adhoc").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let html = body(res).await;
    assert!(
        html.contains(r#"data-track-open="/keys/adhoc/opened""#),
        "{html}"
    );
    assert!(html.contains("Last opened"));
    assert!(!html.contains("Record rotation"));
    assert!(!html.contains(r#"data-dialog-open="rotate-dialog""#));

    let res = h
        .app
        .oneshot(
            Request::get("/?state=on-demand")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let html = body(res).await;
    assert!(html.contains("never stored"));
    assert!(!html.contains("Renovate token"));
}

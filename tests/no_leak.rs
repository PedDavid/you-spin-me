//! The submitted key must reach OpenBao and appear nowhere else. In its own
//! test binary because it installs a TRACE-level log subscriber.

mod common;

use std::sync::Arc;

use axum::http::StatusCode;
use tower::ServiceExt;

use common::*;
use you_spin_me::repo::Repository;
use you_spin_me::targets::openbao::{Auth, OpenBao};

#[derive(Clone, Default)]
struct LogBuffer(Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for LogBuffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// End to end: form post → Rotator → real OpenBao HTTP client → mock
/// OpenBao. The key must reach OpenBao, and appear nowhere else: not in the
/// response, the status, the events or the logs (captured at TRACE).
#[tokio::test(flavor = "current_thread")]
async fn rotated_key_reaches_openbao_and_nowhere_else() {
    use wiremock::matchers::{body_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const SECRET: &str = "ghp_SuperSecretValue123";
    let logs = LogBuffer::default();
    let writer = logs.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(move || writer.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);
    // Other tests may already have cached "no interest" for our callsites.
    tracing::callsite::rebuild_interest_cache();

    let server = MockServer::start().await;
    Mock::given(method("PATCH"))
        .and(path("/v1/secret/data/ci/renovate"))
        .and(body_json(serde_json::json!({"data": {"token": SECRET}})))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;
    let dir = std::env::temp_dir().join(format!("ysm-web-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("token"), "root").unwrap();
    let bao = OpenBao::new(
        server.uri().parse().unwrap(),
        Auth::TokenFile(dir.join("token")),
        None,
    )
    .unwrap();

    let h = harness_with(false, Arc::new(bao));
    let cookie = session_cookie(&h.key, &session(true));
    let res = h
        .app
        .oneshot(rotate_request(&cookie, "csrf-token", SECRET))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.headers()["hx-trigger"], "rotation-complete");
    let html = body(res).await;
    assert!(html.contains("Key rotated"), "{html}");
    assert!(html.contains("GitHub Actions secret"));
    assert!(!html.contains(SECRET));

    let key = h.repo.get("renovate").unwrap();
    let status = key.status.clone().unwrap();
    assert_eq!(status.rotated_by.as_deref(), Some("alice"));
    assert!(!serde_json::to_string(&*key).unwrap().contains(SECRET));
    assert!(!format!("{:?}", h.repo.events()).contains(SECRET));

    let logs = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    assert!(
        logs.contains("key submitted"),
        "expected rotation logs, got:\n{logs}"
    );
    assert!(!logs.contains(SECRET), "key leaked into logs:\n{logs}");
}

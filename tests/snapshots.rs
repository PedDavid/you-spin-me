//! Rendered HTML of each page of the demo app, pinned with insta. Review
//! changes with `cargo insta review`.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

async fn render(uri: &str, headers: &[(&str, &str)], status: StatusCode) -> String {
    let mut req = Request::get(uri);
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let res = common::demo_app()
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(res.status(), status, "{uri}");
    common::body(res).await
}

/// The asset hash changes with every CSS or JS edit; keep it out of the
/// snapshots so they only move when the markup does.
fn assert_html(name: &str, html: String) {
    let mut settings = insta::Settings::clone_current();
    settings.add_filter(r"\?v=[0-9a-f]+", "?v=[hash]");
    settings.bind(|| insta::assert_snapshot!(name, html));
}

#[tokio::test]
async fn index() {
    assert_html("index", render("/", &[], StatusCode::OK).await);
}

#[tokio::test]
async fn index_dark_with_palette() {
    let html = render(
        "/",
        &[("cookie", "ysm_theme=dark; ysm_palette=violet")],
        StatusCode::OK,
    )
    .await;
    assert_html("index_dark_violet", html);
}

#[tokio::test]
async fn filtered_table_for_htmx() {
    let html = render(
        "/?state=expired&sort=name",
        &[("hx-request", "true"), ("hx-target", "keys-table")],
        StatusCode::OK,
    )
    .await;
    assert_html("table_expired", html);
}

#[tokio::test]
async fn detail_with_rotation() {
    let html = render("/keys/renovate-github", &[], StatusCode::OK).await;
    assert_html("detail_renovate_github", html);
}

#[tokio::test]
async fn detail_on_demand() {
    let html = render("/keys/github-repo-migration", &[], StatusCode::OK).await;
    assert_html("detail_github_repo_migration", html);
}

#[tokio::test]
async fn search_results() {
    assert_html("search_empty", render("/search", &[], StatusCode::OK).await);
    let html = render("/search?q=github", &[], StatusCode::OK).await;
    assert_html("search_github", html);
}

#[tokio::test]
async fn not_found() {
    let html = render("/keys/nope", &[], StatusCode::NOT_FOUND).await;
    assert_html("not_found", html);
}

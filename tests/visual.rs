//! Pixel screenshots of the `--demo` UI in Chromium, compared with the PNGs in
//! `tests/screenshots/`. The browser talks to the router in-process (no
//! socket), with the clock pinned like the HTML snapshots.
//!
//! They need Playwright's Chromium, so plain `cargo test` skips them:
//! `make visual` runs them and `make visual-update` rewrites the baselines.
//! Baselines are rendered on CI's Linux runner (fonts and antialiasing differ
//! between machines): take them from the `screenshots` artifact of the CI
//! workflow, run by hand with "update screenshots" ticked.

mod common;

use std::path::PathBuf;

use axum::http::header;
use axum::routing::get;
use playwright_rs::protocol::{
    AddStyleTagOptions, BrowserContextOptions, Cookie, Page, Playwright, Viewport,
};
use playwright_rs::{Animations, ScreenshotAssertionOptions, expect, expect_page};

const ORIGIN: &str = "https://ysm.test";

/// Dialogs and the palette animate in with `@starting-style`; a screenshot
/// taken during that would catch them half-faded. Served from the app's own
/// origin because its CSP (`style-src 'self'`) refuses inline styles.
const NO_MOTION: &str = "*, *::before, *::after, ::backdrop { \
    transition: none !important; animation: none !important; }";
const NO_MOTION_PATH: &str = "/__test/no-motion.css";

/// A browser page with the app routed in, holding on to what keeps it alive.
struct Ui {
    page: Page,
    _playwright: Playwright,
}

async fn open(path: &str, cookies: &[(&str, &str)]) -> Ui {
    let playwright = Playwright::launch().await.expect("launch Playwright");
    let browser = playwright
        .chromium()
        .launch()
        .await
        .expect("launch Chromium (run `make visual-browsers`?)");
    let context = browser
        .new_context_with_options(
            BrowserContextOptions::builder()
                .viewport(Viewport {
                    width: 1280,
                    height: 800,
                })
                .device_scale_factor(1.0)
                .locale("en-US".into())
                .timezone_id("UTC".into())
                .reduced_motion("reduce".into())
                .build(),
        )
        .await
        .unwrap();
    let cookies: Vec<Cookie> = cookies
        .iter()
        .map(|(name, value)| {
            let mut c = Cookie::new(*name, *value);
            c.domain = "ysm.test".into();
            c.path = "/".into();
            c
        })
        .collect();
    context.add_cookies(&cookies).await.unwrap();
    let app = common::demo_app().route(
        NO_MOTION_PATH,
        get(|| async { ([(header::CONTENT_TYPE, "text/css")], NO_MOTION) }),
    );
    context
        .route_service(&format!("{ORIGIN}/**"), app)
        .await
        .unwrap();
    let page = context.new_page().await.unwrap();
    page.goto(&format!("{ORIGIN}{path}"), None).await.unwrap();
    page.add_style_tag(
        AddStyleTagOptions::builder()
            .url(format!("{ORIGIN}{NO_MOTION_PATH}"))
            .build(),
    )
    .await
    .unwrap();
    Ui {
        page,
        _playwright: playwright,
    }
}

/// Compares the viewport with `tests/screenshots/{name}.png`. A missing
/// baseline fails rather than being written, unless `UPDATE_SNAPSHOTS` is set;
/// the capture is kept next to it as `{name}-actual.png` either way.
async fn assert_screenshot(page: &Page, name: &str) {
    let dir: PathBuf = [env!("CARGO_MANIFEST_DIR"), "tests", "screenshots"]
        .iter()
        .collect();
    let baseline = dir.join(format!("{name}.png"));
    let update = std::env::var_os("UPDATE_SNAPSHOTS").is_some();
    let options = |update| {
        ScreenshotAssertionOptions::builder()
            .animations(Animations::Disabled)
            .update_snapshots(update)
            .build()
    };
    if !update && !baseline.exists() {
        let actual = dir.join(format!("{name}-actual.png"));
        let _ = expect_page(page)
            .to_have_screenshot(&actual, Some(options(true)))
            .await;
        panic!(
            "no baseline at {}; the capture is in {}",
            baseline.display(),
            actual.display()
        );
    }
    if let Err(e) = expect_page(page)
        .to_have_screenshot(&baseline, Some(options(update)))
        .await
    {
        panic!("{name}: {e}");
    }
}

#[tokio::test]
#[ignore = "needs a Playwright browser: make visual"]
async fn keys_table() {
    let ui = open("/", &[]).await;
    assert_screenshot(&ui.page, "keys").await;
}

#[tokio::test]
#[ignore = "needs a Playwright browser: make visual"]
async fn keys_table_dark_violet() {
    let ui = open("/", &[("ysm_theme", "dark"), ("ysm_palette", "violet")]).await;
    assert_screenshot(&ui.page, "keys-dark-violet").await;
}

#[tokio::test]
#[ignore = "needs a Playwright browser: make visual"]
async fn detail_dark() {
    let ui = open("/keys/renovate-github", &[("ysm_theme", "dark")]).await;
    assert_screenshot(&ui.page, "detail-dark").await;
}

#[tokio::test]
#[ignore = "needs a Playwright browser: make visual"]
async fn detail_on_demand() {
    let ui = open("/keys/github-repo-migration", &[]).await;
    assert_screenshot(&ui.page, "detail-on-demand").await;
}

#[tokio::test]
#[ignore = "needs a Playwright browser: make visual"]
async fn rotate_dialog() {
    let ui = open("/keys/renovate-github", &[]).await;
    ui.page
        .locator("[data-dialog-open=rotate-dialog]")
        .click(None)
        .await
        .unwrap();
    expect(ui.page.locator("#rotate-title"))
        .to_be_visible()
        .await
        .unwrap();
    assert_screenshot(&ui.page, "rotate").await;
}

#[tokio::test]
#[ignore = "needs a Playwright browser: make visual"]
async fn filtered_by_state() {
    let ui = open("/", &[]).await;
    ui.page
        .locator(".state-chip[data-state=expired]")
        .click(None)
        .await
        .unwrap();
    // Wait for htmx to swap in the filtered table and the updated chips.
    expect(
        ui.page
            .locator(".state-chip[data-state=expired][data-active=true]"),
    )
    .to_be_visible()
    .await
    .unwrap();
    assert_screenshot(&ui.page, "filtered-expired").await;
}

#[tokio::test]
#[ignore = "needs a Playwright browser: make visual"]
async fn command_palette() {
    let ui = open("/", &[]).await;
    ui.page.keyboard().press("Control+k", None).await.unwrap();
    expect(ui.page.locator("#command-results [role=menuitem]").first())
        .to_be_visible()
        .await
        .unwrap();
    assert_screenshot(&ui.page, "command-palette").await;
}

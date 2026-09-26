//! Installs the browsers matching the Playwright driver that `playwright-rs`
//! pins, so the crate version in Cargo.lock decides both.
//!
//! cargo run --example install-browsers -- chromium [--with-deps]

use playwright_rs::{install_browsers, install_browsers_with_deps};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let browsers: Vec<&str> = args
        .iter()
        .map(String::as_str)
        .filter(|a| *a != "--with-deps")
        .collect();
    let browsers = (!browsers.is_empty()).then_some(browsers.as_slice());
    if args.iter().any(|a| a == "--with-deps") {
        install_browsers_with_deps(browsers).await?;
    } else {
        install_browsers(browsers).await?;
    }
    Ok(())
}

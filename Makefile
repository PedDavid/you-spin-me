# Tailwind v4 standalone CLI (no Node.js needed):
# https://github.com/tailwindlabs/tailwindcss/releases/tag/v4.3.3
TAILWIND ?= tailwindcss

.PHONY: css crd check demo

css: ## Rebuild assets/dist/app.css from assets/app.css and the templates
	$(TAILWIND) -i assets/app.css -o assets/dist/app.css --minify

crd: ## Regenerate the CRD from the Rust types
	cargo run --quiet --bin crdgen > deploy/crds/apikeys.yaml

check: ## What CI runs
	cargo fmt --check
	cargo clippy --all-targets --locked -- -D warnings
	cargo test --locked

demo: ## Run the UI with sample data and no auth
	cargo run -- --demo

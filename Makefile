# Tailwind v4 standalone CLI (no Node.js needed):
# https://github.com/tailwindlabs/tailwindcss/releases/tag/v4.3.3
TAILWIND ?= tailwindcss

.PHONY: css crd check demo helm-lint

css: ## Rebuild assets/dist/app.css from assets/app.css and the templates
	$(TAILWIND) -i assets/app.css -o assets/dist/app.css --minify

crd: ## Regenerate the CRD (and the chart's copy) from the Rust types
	cargo run --quiet --bin crdgen > deploy/crds/apikeys.yaml
	cp deploy/crds/apikeys.yaml deploy/helm/you-spin-me/crds/apikeys.yaml

check: ## What CI runs
	cargo fmt --check
	cargo clippy --all-targets --locked -- -D warnings
	cargo test --locked

demo: ## Run the UI with sample data and no auth
	cargo run -- --demo

helm-lint: ## Lint and render the chart
	helm lint deploy/helm/you-spin-me --set oidc.issuer=https://idp.example.com
	helm template ysm deploy/helm/you-spin-me --set oidc.issuer=https://idp.example.com \
	  --set openbao.addr=https://bao:8200 --set prometheusRule.enabled=true --set serviceMonitor.enabled=true >/dev/null

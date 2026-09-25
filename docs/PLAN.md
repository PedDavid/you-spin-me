# you-spin-me — implementation plan

A self-hosted, Kubernetes-native inventory of external API keys: what each key
is for, how it is set up, when it expires, where to renew it and where it has to
be updated. It never stores or reads keys back. On rotation it passes the new
key once through to OpenBao and forgets it. Kubernetes workloads get the key
from OpenBao through the External Secrets Operator (or similar), never from this
app. Expiry is exported as Prometheus metrics, so alerting lives in
Alertmanager, next to everything else.

## 1. Decisions

| Topic | Decision |
|---|---|
| Scope | API keys only (no certificates, SSH keys, domains) |
| Platform | Kubernetes only. CRD group `you-spin-me.prdv.cloud`; all `ApiKey`s in one namespace |
| Inventory (source of truth) | A git repo of `ApiKey` custom resources, applied by GitOps (Argo CD / Flux) |
| Rotation state | CRD `.status`, written by the app. Nothing is stored in OpenBao metadata or Secret annotations |
| Storage target | OpenBao KV v2 only. No Kubernetes Secret adapter: the app has no RBAC on `secrets` at all, and ESO syncs OpenBao into Kubernetes Secrets |
| Key handling | Strictly write-only. The app never reads keys back from any store. On submit it may call the provider's API **once** to detect expiry or validate the key |
| Auth | OIDC login. Everyone who logs in can view; only admins (group claim) can rotate or edit state |
| Language | Rust |
| UI | Pages rendered on the server with askama templates, Tailwind, Basecoat (shadcn/ui look without React) and htmx. Ships as a single binary |
| Alerting | Prometheus metrics plus a shipped `PrometheusRule`: warning at 14 days, critical at 5 days (both overridable per key). The app has no notifier of its own |

## 2. Architecture

```
            git (ApiKey YAML)
                   │  Argo CD / Flux
                   ▼
   ┌──────── Kubernetes API ────────┐
   │  ApiKey CRs (spec from git,    │
   │  status written by app)        │
   └──────┬─────────────────▲───────┘
    watch │                 │ patch apikeys/status
          ▼                 │
   ┌─────────────────────────────────┐        ┌───────────────┐
   │ you-spin-me (single binary)     │──────▶ │ OIDC provider │
   │  • reflector cache of ApiKeys   │        └───────────────┘
   │  • axum: UI + /metrics + health │  probe ┌───────────────┐
   │  • rotation service ────────────┼──────▶ │ GitHub, CF, … │
   └───────┬─────────────────┬───────┘  once  └───────────────┘
                   │ KV v2 PATCH (write-only policy)
                   ▼
             OpenBao KV v2                      Prometheus ◀── /metrics
                   │ read (ESO's own policy)         │
                   ▼                            Alertmanager
      External Secrets Operator ──▶ Kubernetes Secret ──▶ workloads
                                    (Reloader restarts them)
```

- **One replica.** Writes happen only when an admin takes an action, so there is
  no reconcile loop to coordinate and no leader election is needed. Metrics are
  computed from the reflector cache each time Prometheus scrapes.
- **No database.** Spec comes from git, state lives in `.status`, and sessions are
  encrypted cookies.

## 3. The `ApiKey` resource

Group and version: `you-spin-me.prdv.cloud/v1alpha1`. A project subdomain under
`prdv.cloud` leaves room for other projects' CRDs.
The resource is namespaced, and all `ApiKey`s live in one namespace: the app's
own namespace by default, or a dedicated one set in the Helm values. The app
only watches that namespace, so a namespaced Role is enough (no ClusterRole).

```yaml
apiVersion: you-spin-me.prdv.cloud/v1alpha1
kind: ApiKey
metadata:
  name: renovate-github
  namespace: you-spin-me
spec:
  displayName: Renovate – GitHub token
  provider: github              # selects the expiry probe; "generic" = no probe
  owner: david
  renewUrl: https://github.com/settings/personal-access-tokens
  setup:
    permissions:                # free text, shown as badges
      - "contents: read"
      - "pull_requests: write"
    notes: |
      Fine-grained PAT, resource owner = my org, all repos.
  rotation:
    maxAge: 90d                 # optional policy → rotateBy = lastRotated + maxAge
    warnBefore: 14d             # optional per-key thresholds (defaults: 14d / 5d),
    criticalBefore: 5d          # exported as metrics for the alert rules
  targets:                      # written automatically on rotation
    - openbao:
        mount: secret
        path: ci/renovate
        key: token
  # Kubernetes consumers are wired up outside this app, e.g. an ExternalSecret
  # reading secret/ci/renovate#token into the renovate namespace.
  consumers:                    # places to update by hand, shown as a checklist
    - "GitHub Actions secret RENOVATE_TOKEN in PedDavid/infra"
status:                         # written only by the app
  lastRotated: "2026-09-20T10:12:00Z"
  rotatedBy: david@example.com
  expiresAt: "2026-12-19T00:00:00Z"   # effective expiry
  expiresAtSource: probe              # probe | manual | none
  manualExpiresAt: null
  probe:
    at: "2026-09-20T10:12:00Z"
    identity: "PedDavid"              # e.g. token owner, never the key itself
  targets:
    - ref: openbao/secret/ci/renovate#token
      lastWritten: "2026-09-20T10:12:01Z"
      result: ok                      # ok | failed
      message: ""
  history:                            # bounded, last 10 rotations
    - at: "2026-09-20T10:12:00Z"
      by: david@example.com
      expiresAt: "2026-12-19T00:00:00Z"
  conditions:
    - type: Valid                     # spec checks: targets allowed, provider known, …
      status: "True"
```

Notes:
- The CRD **must** use the `status` subresource, so GitOps applies of `spec`
  never overwrite `.status` and the app only needs `patch` on `apikeys/status`.
  Argo CD and Flux both ignore `.status` differences.
- The effective **deadline** is `min(expiresAt, lastRotated + maxAge)`. Keys that
  never expire still get a deadline from `maxAge`.
- The CRD YAML is generated from Rust types (`kube` `CustomResource` derive plus
  `schemars`) by a `crdgen` binary, and CI checks that the committed CRD is up to date.
- **Recovering from a lost cluster:** `.status` is not in git, so rebuilding the
  cluster loses rotation state. Affected keys show *unknown* state, an alert
  fires, and an admin re-records the dates with the **Record rotation** action
  (section 6). This is accepted, given the decision to keep state in the CRD only.

## 4. Handling keys (write-only)

Rules the code has to follow:

1. The key arrives in one `POST` (a password field with `autocomplete="off"`) and is
   parsed straight into `secrecy::SecretString`. It is zeroed on drop, cannot be
   printed with `Debug` or `Display`, and is never cloned into a plain `String`.
2. Request bodies are never logged: the `tower-http` trace layer logs method,
   path, status and latency only. Error pages never echo form input.
3. The key's lifetime is one request: optional probe, then write to the targets,
   then drop. There is no cache, queue or retry state holding it. If a target
   fails, htmx swaps only the result panel, so the value stays in the browser's
   input and the admin can resubmit it.
4. Responses carry `Cache-Control: no-store` and a strict CSP (`script-src 'self'`,
   with htmx and Basecoat JS vendored). POSTs need a CSRF token and a same-origin
   `Origin` header.
5. Audit trail: a structured log line and a Kubernetes `Event` on the `ApiKey`
   (who, which key, which targets, result). The key value never appears.

### 4.1 Storage targets

```rust
#[async_trait]
pub trait Target: Send + Sync {
    fn reference(&self) -> String;               // e.g. "openbao/secret/ci/renovate#token"
    async fn write(&self, key: &SecretString) -> Result<(), TargetError>;
}
```

**OpenBao KV v2**
- Authenticates with the Kubernetes auth method (the projected ServiceAccount token).
- Writes with `PATCH /v1/<mount>/data/<path>`, so other keys at that path are kept.
  The response only contains version metadata. If the path does not exist yet
  (404), the app falls back to `POST` to create it.
- Policy (shipped as an example):
  ```hcl
  path "secret/data/ci/*" { capabilities = ["create", "patch"] }
  # no read, no list, no metadata access
  ```
  The paths are only examples. The app accepts any `mount`/`path` (several mounts
  are fine) and **the OpenBao policy is the boundary**. Grant only the paths
  intended for this app: anyone who can merge an `ApiKey` can point the app at a
  path, and the app would overwrite the key there. That can't leak anything, but
  it could break another service.
- Optional `allowedPaths` globs in the Helm values (default: allow everything).
  They only give earlier feedback: a path outside them sets `Valid=False` when
  the CR is applied, instead of failing with a 403 during rotation.
- Check-and-set (CAS) is not used, because it would need to read the metadata.
  The app's policy and ESO's read policy are separate, so the app can never read
  what it wrote.
- A thin client built on `reqwest` (three endpoints) rather than the `vaultrs`
  crate, to keep dependencies small and control exactly what gets deserialized.

**Why there is no Kubernetes Secret target**
- A Kubernetes `patch` response always contains the whole Secret, including
  `data`, so write access to a Secret is effectively read access. OpenBao gives
  real write-only access.
- The app then needs no RBAC on `secrets` in any namespace, and there's no
  GitOps conflict over who owns a Secret's `data`.
- The `Target` trait stays, so other write-only stores can be added later.

**Getting the new key to workloads (documented, not implemented)**
- ESO `ExternalSecret`s read from OpenBao with their own policy. The new key is
  picked up at the next `refreshInterval`. Expiry alerts give days of warning,
  so an interval of e.g. 1h is fine.
- Stakater Reloader (or similar) restarts workloads when their Secret changes.
- The rotate dialog's checklist ends with *revoke the old key*, to be done once
  consumers have picked up the new one.

### 4.2 Expiry probes

```rust
#[async_trait]
pub trait Provider: Send + Sync {
    fn id(&self) -> &'static str;
    async fn probe(&self, key: &SecretString) -> Result<ProbeResult, ProbeError>;
}

pub struct ProbeResult {
    pub expires_at: Option<Timestamp>,
    pub identity: Option<String>,   // shown in UI and status, never the key
}
```

- Runs before any target write. If the probe fails (invalid or revoked key), the
  rotation is aborted and nothing is written, unless the admin ticks *skip
  verification*.
- Expiry priority: the probed value if there is one, otherwise the date the admin
  entered. If both exist and differ, the UI shows a warning.
- Initial providers (exact endpoints to be confirmed during implementation):
  - `generic`: no probe; the admin enters the expiry by hand (optional).
  - `github`: `GET /user`, reading the `github-authentication-token-expiration`
    response header for PATs, and the login name as identity.
  - `cloudflare`: `GET /client/v4/user/tokens/verify`, reading the status and
    expiry of the token.
- Probes only call a fixed list of provider hosts. The host is never taken from
  the CR.

## 5. Authentication and authorization

- OIDC authorization code flow with PKCE (`openidconnect` crate). Configured with
  issuer URL, client ID and secret (mounted from the app's own Secret), and redirect URL.
- After login, a small session (`sub`, display name, `is_admin`, expiry) is stored
  in an **encrypted, signed cookie** (`axum-extra` `PrivateCookieJar`), set
  `HttpOnly`, `Secure`, `SameSite=Lax`, with a short lifetime (e.g. 8h). There is
  no server-side session store.
- Admin is decided by a configurable claim and value (default `groups` contains
  `you-spin-me-admins`).
- Viewers can see the list, details, renew links and metrics. Admins can also
  rotate and record rotations.
- Could add later: step-up authentication for rotation (OIDC `max_age`), forcing
  a fresh login before any write.
- `/metrics` and `/healthz` are served on a separate port with no auth, for
  Prometheus and the kubelet.

## 6. UI

Pages are rendered on the server with askama. Tailwind v4 is built with the
standalone CLI (no Node.js), components come from Basecoat, htmx handles partial
updates, and Lucide icons are inline SVG. Every asset is embedded in the binary.

**Keys table (`/`)**
- Columns: name, provider badge, owner, expiry (relative time plus a colour
  badge: ok / warning ≤ warnBefore / critical ≤ criticalBefore / expired /
  unknown), last rotated, targets
  (✓ n / ✗ n), actions (**Renew ↗** opens `renewUrl`; **Rotate** for admins).
- Sorted by deadline by default. Search and filters (status, provider, owner)
  run on the server through `hx-get`, with `hx-push-url` so filtered views can be
  linked.

**Key detail (`/keys/{namespace}/{name}`)**
- Setup and permissions, notes, renew link, targets with the result of the last
  write, consumer checklist, rotation history and conditions.

**Rotate dialog (admin)**
1. Open the renew link (new tab).
2. Paste the key. Optionally enter an expiry date (`<input type="date">`) and
   tick *skip verification*.
3. Submit. The result panel shows the probe result, then each target's result,
   then the checklist of places to update by hand.

**Record rotation (admin)**
- Sets `lastRotated` and `expiresAt` without submitting a key. Used for keys with
  no targets, and for recovering after a cluster rebuild.

**Themes:** shadcn-compatible colour themes as CSS variables, plus light and dark.
The choice is stored in a cookie. A ⌘K command palette (`<dialog>` plus htmx
search) is planned for M4.

## 7. Metrics and alerts

Served on `:9090/metrics` with the `prometheus-client` crate. Labels on every key
metric: `namespace`, `name`, `provider`, `owner`.

| Metric | Type | Meaning |
|---|---|---|
| `youspinme_apikey_info{…, display_name, renew_url}` | gauge = 1 | Metadata used in alert annotations |
| `youspinme_apikey_expiry_timestamp_seconds` | gauge | Effective `expiresAt` (omitted if unknown) |
| `youspinme_apikey_rotate_by_timestamp_seconds` | gauge | `lastRotated + maxAge` (omitted if no policy) |
| `youspinme_apikey_deadline_timestamp_seconds` | gauge | The earlier of the two; the one to alert on |
| `youspinme_apikey_last_rotated_timestamp_seconds` | gauge | |
| `youspinme_apikey_warn_before_seconds` | gauge | Per-key `warnBefore` (default 14d, configurable) |
| `youspinme_apikey_critical_before_seconds` | gauge | Per-key `criticalBefore` (default 5d, configurable) |
| `youspinme_apikey_state_known` | gauge 0/1 | 0 if there is no deadline at all |
| `youspinme_apikey_target_healthy{target}` | gauge 0/1 | Result of the last write per target |
| `youspinme_rotations_total{result}` | counter | |
| `youspinme_probe_requests_total{provider,result}` | counter | |

Shipped `PrometheusRule` (Helm-toggleable):

```yaml
# warning between warnBefore and criticalBefore, critical inside criticalBefore,
# so each key has only one of the two firing at a time
- alert: ApiKeyExpiringSoon
  expr: |
    (youspinme_apikey_deadline_timestamp_seconds - time())
      < youspinme_apikey_warn_before_seconds
    and (youspinme_apikey_deadline_timestamp_seconds - time())
      >= youspinme_apikey_critical_before_seconds
  labels: { severity: warning }
  annotations:
    summary: "API key {{ $labels.name }} is due in {{ $value | humanizeDuration }}"
    runbook_url: "https://<app-url>/keys/{{ $labels.namespace }}/{{ $labels.name }}"
- alert: ApiKeyExpiringVerySoon
  expr: |
    (youspinme_apikey_deadline_timestamp_seconds - time())
      < youspinme_apikey_critical_before_seconds
    and (youspinme_apikey_deadline_timestamp_seconds - time()) > 0
  labels: { severity: critical }
- alert: ApiKeyExpired
  expr: youspinme_apikey_deadline_timestamp_seconds - time() <= 0
  labels: { severity: critical }
- alert: ApiKeyStateUnknown
  expr: youspinme_apikey_state_known == 0
  for: 1h
  labels: { severity: info }
- alert: ApiKeyTargetWriteFailed
  expr: youspinme_apikey_target_healthy == 0
  labels: { severity: warning }
```

A Grafana dashboard JSON (keys by deadline, recent rotations) comes in M4.

## 8. Project layout

```
Cargo.toml
src/
  main.rs            # config, tracing, spawns web + metrics servers
  config.rs          # env/flags (figment or clap)
  crd.rs             # ApiKey spec/status types (CustomResource + JsonSchema)
  bin/crdgen.rs      # prints the CRD YAML
  k8s/
    store.rs         # reflector cache of ApiKeys
    status.rs        # status patches, Events
  rotation.rs        # probe → targets → status, orchestration
  targets/{mod,openbao}.rs
  providers/{mod,generic,github,cloudflare}.rs
  metrics.rs         # collector computing gauges from the store at scrape time
  web/
    mod.rs           # router, middleware (trace, CSP, CSRF, no-store)
    auth.rs          # OIDC flow, session cookie, Admin extractor
    pages.rs         # handlers
templates/           # askama templates (base, table, detail, dialogs, partials)
assets/
  app.css            # Tailwind entry: @import basecoat, theme variables
  vendor/            # htmx.min.js, basecoat JS (pinned, checked in)
deploy/
  crds/apikeys.yaml  # generated
  helm/you-spin-me/  # Deployment, SA, RBAC, Service, ServiceMonitor, PrometheusRule
  examples/          # sample ApiKeys, OpenBao policy, Argo ignoreDifferences
Dockerfile           # tailwind build → cargo build (musl) → distroless/static
```

Main crates: `tokio`, `axum`, `axum-extra`, `tower-http`, `askama`, `kube`
(runtime, derive), `k8s-openapi`, `schemars`, `serde`, `openidconnect`,
`reqwest` (rustls), `secrecy`, `zeroize`, `prometheus-client`, `tracing`, and
`jiff` or `chrono` (whichever `k8s-openapi` uses).

Kept a single crate until there is a reason to split it.

## 9. Milestones

**M0 – Skeleton**
- Cargo project, CI (fmt, clippy `-D warnings`, tests, CRD drift check), Dockerfile, Helm chart skeleton.
- `ApiKey` types, `crdgen`, example resources.

**M1 – Useful without handling any keys**
- Reflector, keys table and detail pages, Basecoat + Tailwind pipeline, themes (light/dark).
- OIDC login and the admin role.
- **Record rotation** action (status patch, Event, audit log).
- Metrics, `PrometheusRule`, ServiceMonitor.
- *After M1 the app is already a working expiry tracker with alerts.*

**M2 – Rotation through OpenBao**
- Rotate dialog, `SecretString` handling, `generic` provider.
- OpenBao KV v2 target (Kubernetes auth, PATCH with POST fallback), example policy.
- Example ESO `ExternalSecret` and Reloader setup in `deploy/examples/`.
- `Valid` condition checks (target path matches `allowedPaths`), CSRF and CSP hardening.
- Tests: target against an OpenBao dev server in CI, a check that the policy
  denies reads, and a check that the key value never appears in logs.

**M3 – Probes**
- `github` and `cloudflare` probes, handling mismatches with the manually entered expiry.

**M4 – Polish**
- ⌘K palette, more themes, Grafana dashboard.
- Step-up auth for rotation, more providers as needed.

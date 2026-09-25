//! Page handlers.

use askama::Template;
use axum::Form;
use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum_extra::extract::CookieJar;
use jiff::Timestamp;
use jiff::civil::Date;
use jiff::tz::TimeZone;
use secrecy::SecretString;
use serde::Deserialize;

use super::auth::{Admin, AuthMode, Session, User};
use super::views::{KeyDetail, KeyRow, fmt_date, state_label};
use super::{AppError, AppState};
use crate::rotation::{self, ProbeOutcome, RecordError, RotateOutcome, RotateRequest};
use crate::schedule::State as KeyState;

/// Data shared by every full page.
pub struct Layout {
    pub title: String,
    pub user: String,
    pub admin: bool,
    pub csrf: String,
    pub asset_version: String,
    pub dark: bool,
    pub palette: String,
    pub dev_auth: bool,
}

pub const PALETTES: [&str; 5] = ["neutral", "blue", "green", "orange", "violet"];

impl Layout {
    fn new(
        state: &AppState,
        session: &Session,
        jar: &CookieJar,
        title: impl Into<String>,
    ) -> Layout {
        let palette = jar
            .get("ysm_palette")
            .map(|c| c.value().to_string())
            .filter(|p| PALETTES.contains(&p.as_str()))
            .unwrap_or_else(|| "neutral".into());
        Layout {
            title: title.into(),
            user: session.name.clone(),
            admin: session.admin,
            csrf: session.csrf.clone(),
            asset_version: state.inner.asset_version.clone(),
            dark: jar.get("ysm_theme").is_some_and(|c| c.value() == "dark"),
            palette,
            dev_auth: matches!(state.inner.auth, AuthMode::InsecureDev { .. }),
        }
    }
}

#[derive(Deserialize, Default, Clone)]
pub struct Filters {
    #[serde(default)]
    pub q: String,
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub provider: String,
    #[serde(default)]
    pub sort: String,
}

pub struct StateCount {
    pub state: &'static str,
    pub label: &'static str,
    pub count: usize,
    pub active: bool,
}

#[derive(Template)]
#[template(path = "index.html")]
struct IndexPage {
    layout: Layout,
    rows: Vec<KeyRow>,
    total: usize,
    matching: usize,
    counts: Vec<StateCount>,
    providers: Vec<String>,
    filters: Filters,
    oob: bool,
}

#[derive(Template)]
#[template(path = "partials/keys_table.html")]
struct KeysTable {
    rows: Vec<KeyRow>,
    total: usize,
    matching: usize,
    counts: Vec<StateCount>,
    filters: Filters,
    /// Also re-render the state chips as an htmx out-of-band swap.
    oob: bool,
}

fn is_htmx(headers: &HeaderMap, target: &str) -> bool {
    headers.contains_key("hx-request")
        && headers
            .get("hx-target")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|t| t == target)
}

pub async fn index(
    State(state): State<AppState>,
    User(session): User,
    jar: CookieJar,
    headers: HeaderMap,
    Query(filters): Query<Filters>,
) -> Result<Response, AppError> {
    let now = Timestamp::now();
    let thresholds = state.inner.cfg.thresholds();
    let all: Vec<KeyRow> = state
        .inner
        .repo
        .list()
        .iter()
        .map(|k| KeyRow::new(k, thresholds, now))
        .collect();
    let total = all.len();
    let wanted_state = KeyState::parse(&filters.state);

    let mut providers: Vec<String> = all.iter().map(|r| r.provider.clone()).collect();
    providers.sort();
    providers.dedup();

    let searched: Vec<KeyRow> = all
        .into_iter()
        .filter(|r| filters.q.is_empty() || r.matches(&filters.q))
        .filter(|r| filters.provider.is_empty() || r.provider == filters.provider)
        .collect();
    let matching = searched.len();
    let counts = KeyState::ALL
        .iter()
        .map(|s| StateCount {
            state: s.as_str(),
            label: state_label(*s),
            count: searched.iter().filter(|r| r.state == *s).count(),
            active: wanted_state == Some(*s),
        })
        .collect();
    let mut rows: Vec<KeyRow> = searched
        .into_iter()
        .filter(|r| wanted_state.is_none_or(|s| r.state == s))
        .collect();
    sort_rows(&mut rows, &filters.sort);

    if is_htmx(&headers, "keys-table") {
        return Ok(Html(
            KeysTable {
                rows,
                total,
                matching,
                counts,
                filters,
                oob: true,
            }
            .render()?,
        )
        .into_response());
    }
    Ok(Html(
        IndexPage {
            layout: Layout::new(&state, &session, &jar, "API keys"),
            rows,
            total,
            matching,
            counts,
            providers,
            filters,
            oob: false,
        }
        .render()?,
    )
    .into_response())
}

fn sort_rows(rows: &mut [KeyRow], sort: &str) {
    match sort {
        "name" => rows.sort_by(|a, b| {
            a.display_name
                .to_lowercase()
                .cmp(&b.display_name.to_lowercase())
        }),
        "rotated" => rows.sort_by(|a, b| a.last_rotated.cmp(&b.last_rotated)),
        // Default: most urgent first, unknown deadlines after known ones.
        _ => rows.sort_by(|a, b| match (a.deadline, b.deadline) {
            (Some(x), Some(y)) => x.cmp(&y),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => a.name.cmp(&b.name),
        }),
    }
}

#[derive(Template)]
#[template(path = "detail.html")]
struct DetailPage {
    layout: Layout,
    key: KeyDetail,
    can_rotate: bool,
    probe_supported: bool,
    notice: String,
    today: String,
}

#[derive(Deserialize, Default)]
pub struct DetailQuery {
    #[serde(default)]
    notice: String,
}

pub async fn detail(
    State(state): State<AppState>,
    User(session): User,
    jar: CookieJar,
    Path(name): Path<String>,
    Query(q): Query<DetailQuery>,
) -> Result<Response, AppError> {
    let key = state
        .inner
        .repo
        .get(&name)
        .ok_or_else(|| AppError::NotFound(format!("no API key named {name:?}")))?;
    let now = Timestamp::now();
    let detail = KeyDetail::new(&key, state.inner.cfg.thresholds(), now);
    let notice = match q.notice.as_str() {
        "recorded" => "Rotation recorded.",
        _ => "",
    };
    Ok(Html(
        DetailPage {
            layout: Layout::new(&state, &session, &jar, detail.row.display_name.clone()),
            can_rotate: !key.spec.targets.is_empty(),
            probe_supported: key.spec.provider != crate::crd::Provider::Generic,
            key: detail,
            notice: notice.to_string(),
            today: fmt_date(now),
        }
        .render()?,
    )
    .into_response())
}

#[derive(Deserialize)]
pub struct RecordForm {
    #[serde(rename = "_csrf")]
    csrf: Option<String>,
    rotated_at: String,
    #[serde(default)]
    expires_at: String,
}

/// Parses an `<input type="date">` value as midnight UTC.
pub fn parse_date(value: &str) -> Result<Option<Timestamp>, AppError> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    let date: Date = value
        .parse()
        .map_err(|_| AppError::BadRequest(format!("invalid date {value:?}")))?;
    let ts = date
        .to_zoned(TimeZone::UTC)
        .map_err(|e| AppError::BadRequest(e.to_string()))?
        .timestamp();
    Ok(Some(ts))
}

pub async fn record(
    State(state): State<AppState>,
    Admin(session): Admin,
    headers: HeaderMap,
    Path(name): Path<String>,
    Form(form): Form<RecordForm>,
) -> Result<Response, AppError> {
    session.check_csrf(&headers, form.csrf.as_deref())?;
    let now = Timestamp::now();
    let rotated_at = match parse_date(&form.rotated_at)? {
        // Recording "today" means now, so the deadline is exact.
        Some(d) if fmt_date(d) == fmt_date(now) => now,
        Some(d) => d,
        None => now,
    };
    let expires_at = parse_date(&form.expires_at)?;
    rotation::record(
        state.inner.repo.as_ref(),
        &name,
        &session.name,
        rotated_at,
        expires_at,
        now,
    )
    .await
    .map_err(|e| match e {
        RecordError::Repo(crate::repo::RepoError::NotFound(_)) => AppError::NotFound(e.to_string()),
        RecordError::Repo(_) => AppError::Internal(e.to_string()),
        _ => AppError::BadRequest(e.to_string()),
    })?;
    state.inner.metrics.rotation("recorded");
    Ok(Redirect::to(&format!("/keys/{}?notice=recorded", urlencode(&name))).into_response())
}

pub fn urlencode(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

#[derive(Deserialize)]
pub struct RotateForm {
    #[serde(rename = "_csrf")]
    csrf: Option<String>,
    key: SecretString,
    #[serde(default)]
    expires_at: String,
    #[serde(default)]
    skip_verification: Option<String>,
}

#[derive(Template)]
#[template(path = "partials/rotate_result.html")]
struct RotateResult {
    name: String,
    error: String,
    outcome: Option<RotateOutcome>,
    consumers: Vec<String>,
}

impl RotateResult {
    fn probe_line(&self) -> String {
        match self.outcome.as_ref().map(|o| &o.probe) {
            Some(ProbeOutcome::Checked(r)) => {
                let who = r
                    .identity
                    .as_deref()
                    .map(|i| format!("belongs to {i}"))
                    .unwrap_or_else(|| "is valid".into());
                let expiry = r
                    .expires_at
                    .map(|e| format!(", expires {}", fmt_date(e)))
                    .unwrap_or_else(|| ", no expiry reported".into());
                format!("Checked with the provider: the key {who}{expiry}.")
            }
            Some(ProbeOutcome::Skipped) => "Verification skipped.".into(),
            _ => String::new(),
        }
    }
}

pub async fn rotate(
    State(state): State<AppState>,
    Admin(session): Admin,
    headers: HeaderMap,
    Path(name): Path<String>,
    Form(form): Form<RotateForm>,
) -> Result<Response, AppError> {
    session.check_csrf(&headers, form.csrf.as_deref())?;
    let consumers = state
        .inner
        .repo
        .get(&name)
        .map(|k| k.spec.consumers.clone())
        .unwrap_or_default();
    let mut result = RotateResult {
        name: name.clone(),
        error: String::new(),
        outcome: None,
        consumers,
    };
    let manual_expires_at = match parse_date(&form.expires_at) {
        Ok(d) => d,
        Err(e) => {
            result.error = e.to_string();
            return Ok(Html(result.render()?).into_response());
        }
    };
    let request = RotateRequest {
        value: form.key,
        actor: session.name.clone(),
        manual_expires_at,
        skip_verification: form.skip_verification.is_some(),
    };
    // Errors are rendered into the dialog (htmx only swaps 2xx responses).
    match state.inner.rotator.rotate(&name, request).await {
        Ok(outcome) => {
            let completed = outcome.completed;
            result.outcome = Some(outcome);
            let html = Html(result.render()?);
            if completed {
                Ok(([("HX-Trigger", "rotation-complete")], html).into_response())
            } else {
                Ok(html.into_response())
            }
        }
        Err(e) => {
            result.error = e.to_string();
            Ok(Html(result.render()?).into_response())
        }
    }
}

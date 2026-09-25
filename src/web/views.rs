//! View models: `ApiKey`s turned into pre-formatted rows for the templates.

use jiff::{SignedDuration, Timestamp};

use crate::crd::{ApiKey, ExpirySource, HistoryKind, TargetResult};
use crate::duration::humanize;
use crate::k8s::VALID_CONDITION;
use crate::schedule::{DeadlineKind, Schedule, State, Thresholds};

pub fn fmt_date(t: Timestamp) -> String {
    t.strftime("%Y-%m-%d").to_string()
}

pub fn fmt_datetime(t: Timestamp) -> String {
    t.strftime("%Y-%m-%d %H:%M UTC").to_string()
}

/// "in 12d", "3d ago", "now".
pub fn relative(t: Timestamp, now: Timestamp) -> String {
    let d = t.duration_since(now);
    if d.abs() < SignedDuration::from_secs(60) {
        "now".into()
    } else if d.is_positive() {
        format!("in {}", humanize(d))
    } else {
        format!("{} ago", humanize(d))
    }
}

pub fn state_label(state: State) -> &'static str {
    match state {
        State::Expired => "Expired",
        State::Critical => "Critical",
        State::Warning => "Due soon",
        State::Unknown => "Unknown",
        State::Ok => "OK",
    }
}

#[derive(Clone, Debug)]
pub struct KeyRow {
    pub name: String,
    pub display_name: String,
    pub provider: String,
    pub owner: String,
    pub state: State,
    pub deadline: Option<Timestamp>,
    pub deadline_date: String,
    pub deadline_rel: String,
    pub deadline_kind: &'static str,
    pub last_rotated: Option<Timestamp>,
    pub last_rotated_rel: String,
    pub targets_total: usize,
    pub targets_failed: usize,
    pub renew_url: Option<String>,
    pub valid: bool,
}

impl KeyRow {
    pub fn new(key: &ApiKey, thresholds: Thresholds, now: Timestamp) -> KeyRow {
        let schedule = Schedule::compute(key, thresholds);
        let status = key.status.as_ref();
        let deadline = schedule.deadline.map(|(d, _)| d);
        KeyRow {
            name: key.name().to_string(),
            display_name: key.display_name().to_string(),
            provider: key.spec.provider.as_str().to_string(),
            owner: key.spec.owner.clone().unwrap_or_default(),
            state: schedule.state(now),
            deadline,
            deadline_date: deadline.map(fmt_date).unwrap_or_default(),
            deadline_rel: deadline
                .map(|d| relative(d, now))
                .unwrap_or_else(|| "—".into()),
            deadline_kind: match schedule.deadline {
                Some((_, DeadlineKind::Expiry)) => "expiry",
                Some((_, DeadlineKind::MaxAge)) => "max age",
                None => "",
            },
            last_rotated: schedule.last_rotated,
            last_rotated_rel: schedule
                .last_rotated
                .map(|t| relative(t, now))
                .unwrap_or_else(|| "never".into()),
            targets_total: key.spec.targets.len(),
            targets_failed: status
                .map(|s| {
                    s.targets
                        .iter()
                        .filter(|t| t.result == TargetResult::Failed)
                        .count()
                })
                .unwrap_or(0),
            renew_url: key.spec.renew_url.clone(),
            valid: key
                .condition(VALID_CONDITION)
                .is_none_or(|c| c.status == "True"),
        }
    }

    pub fn state_str(&self) -> &'static str {
        self.state.as_str()
    }

    pub fn state_label(&self) -> &'static str {
        state_label(self.state)
    }

    pub fn matches(&self, q: &str) -> bool {
        let q = q.to_lowercase();
        [&self.name, &self.display_name, &self.owner, &self.provider]
            .iter()
            .any(|f| f.to_lowercase().contains(&q))
    }
}

pub struct TargetRow {
    pub reference: String,
    pub result: &'static str,
    pub last_written: String,
    pub message: String,
}

pub struct HistoryRow {
    pub at: String,
    pub by: String,
    pub kind: &'static str,
    pub expires: String,
}

pub struct ConditionRow {
    pub type_: String,
    pub ok: bool,
    pub reason: String,
    pub message: String,
}

pub struct KeyDetail {
    pub row: KeyRow,
    pub permissions: Vec<String>,
    pub notes: String,
    pub consumers: Vec<String>,
    pub expires_at: String,
    pub expires_source: &'static str,
    pub manual_expires_at: String,
    pub rotate_by: String,
    pub max_age: String,
    pub warn_before: String,
    pub critical_before: String,
    pub rotated_by: String,
    pub last_rotated_date: String,
    pub probe_identity: String,
    pub probe_expiry: String,
    pub probe_at: String,
    pub expiry_mismatch: bool,
    pub targets: Vec<TargetRow>,
    pub history: Vec<HistoryRow>,
    pub conditions: Vec<ConditionRow>,
}

impl KeyDetail {
    pub fn new(key: &ApiKey, thresholds: Thresholds, now: Timestamp) -> KeyDetail {
        let row = KeyRow::new(key, thresholds, now);
        let schedule = Schedule::compute(key, thresholds);
        let status = key.status.clone().unwrap_or_default();
        let probe = status.probe.as_ref();
        let probe_expiry = probe.and_then(|p| p.expires_at.as_ref()).map(|t| t.0);
        let manual = status.manual_expires_at.as_ref().map(|t| t.0);
        let targets = key
            .spec
            .targets
            .iter()
            .map(|t| {
                let reference = t.reference();
                let st = status.targets.iter().find(|s| s.reference == reference);
                TargetRow {
                    reference,
                    result: match st.map(|s| s.result) {
                        Some(TargetResult::Ok) => "ok",
                        Some(TargetResult::Failed) => "failed",
                        None => "never written",
                    },
                    last_written: st
                        .and_then(|s| s.last_written.as_ref())
                        .map(|t| relative(t.0, now))
                        .unwrap_or_default(),
                    message: st.and_then(|s| s.message.clone()).unwrap_or_default(),
                }
            })
            .collect();
        KeyDetail {
            permissions: key.spec.setup.permissions.clone(),
            notes: key.spec.setup.notes.clone().unwrap_or_default(),
            consumers: key.spec.consumers.clone(),
            expires_at: schedule.expires_at.map(fmt_datetime).unwrap_or_default(),
            expires_source: match status.expires_at_source {
                Some(ExpirySource::Probe) => "detected from the provider",
                Some(ExpirySource::Manual) => "entered by hand",
                Some(ExpirySource::None) | None => "",
            },
            manual_expires_at: manual.map(fmt_date).unwrap_or_default(),
            rotate_by: schedule.rotate_by.map(fmt_datetime).unwrap_or_default(),
            max_age: key.spec.rotation.max_age.clone().unwrap_or_default(),
            warn_before: humanize(schedule.thresholds.warn_before),
            critical_before: humanize(schedule.thresholds.critical_before),
            rotated_by: status.rotated_by.clone().unwrap_or_default(),
            last_rotated_date: schedule.last_rotated.map(fmt_datetime).unwrap_or_default(),
            probe_identity: probe.and_then(|p| p.identity.clone()).unwrap_or_default(),
            probe_expiry: probe_expiry.map(fmt_date).unwrap_or_default(),
            probe_at: probe.map(|p| fmt_datetime(p.at.0)).unwrap_or_default(),
            expiry_mismatch: matches!((probe_expiry, manual), (Some(p), Some(m)) if fmt_date(p) != fmt_date(m)),
            targets,
            history: status
                .history
                .iter()
                .map(|h| HistoryRow {
                    at: fmt_datetime(h.at.0),
                    by: h.by.clone(),
                    kind: match h.kind {
                        HistoryKind::Rotated => "Rotated",
                        HistoryKind::Recorded => "Recorded",
                    },
                    expires: h
                        .expires_at
                        .as_ref()
                        .map(|t| fmt_date(t.0))
                        .unwrap_or_else(|| "—".into()),
                })
                .collect(),
            conditions: status
                .conditions
                .iter()
                .map(|c| ConditionRow {
                    type_: c.type_.clone(),
                    ok: c.status == "True",
                    reason: c.reason.clone(),
                    message: c.message.clone(),
                })
                .collect(),
            row,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relative_times() {
        let now: Timestamp = "2026-09-25T00:00:00Z".parse().unwrap();
        let later: Timestamp = "2026-10-07T00:00:00Z".parse().unwrap();
        let earlier: Timestamp = "2026-09-22T00:00:00Z".parse().unwrap();
        assert_eq!(relative(later, now), "in 12d");
        assert_eq!(relative(earlier, now), "3d ago");
        assert_eq!(relative(now, now), "now");
        assert_eq!(fmt_date(later), "2026-10-07");
    }
}

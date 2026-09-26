//! Deadline and alert-state computation for an `ApiKey`.
//!
//! The deadline is the earlier of the provider expiry (`status.expiresAt`)
//! and the rotation policy (`status.lastRotated + spec.rotation.maxAge`).

use jiff::{SignedDuration, Timestamp};

use crate::crd::ApiKey;
use crate::duration;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Thresholds {
    pub warn_before: SignedDuration,
    pub critical_before: SignedDuration,
}

impl Default for Thresholds {
    fn default() -> Self {
        Thresholds {
            warn_before: SignedDuration::from_hours(14 * 24),
            critical_before: SignedDuration::from_hours(5 * 24),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum State {
    Expired,
    Critical,
    Warning,
    Unknown,
    Ok,
    /// On-demand keys: created when needed, no deadline.
    OnDemand,
}

impl State {
    pub fn as_str(self) -> &'static str {
        match self {
            State::Expired => "expired",
            State::Critical => "critical",
            State::Warning => "warning",
            State::Unknown => "unknown",
            State::Ok => "ok",
            State::OnDemand => "on-demand",
        }
    }

    pub fn parse(s: &str) -> Option<State> {
        Some(match s {
            "expired" => State::Expired,
            "critical" => State::Critical,
            "warning" => State::Warning,
            "unknown" => State::Unknown,
            "ok" => State::Ok,
            "on-demand" => State::OnDemand,
            _ => return None,
        })
    }

    pub const ALL: [State; 6] = [
        State::Expired,
        State::Critical,
        State::Warning,
        State::Unknown,
        State::Ok,
        State::OnDemand,
    ];
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeadlineKind {
    /// Set by the provider (or entered by hand).
    Expiry,
    /// Set by `spec.rotation.maxAge`.
    MaxAge,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Schedule {
    pub last_rotated: Option<Timestamp>,
    pub expires_at: Option<Timestamp>,
    pub rotate_by: Option<Timestamp>,
    pub deadline: Option<(Timestamp, DeadlineKind)>,
    pub thresholds: Thresholds,
    /// On-demand keys have no deadline and are never due.
    pub on_demand: bool,
}

impl Schedule {
    pub fn compute(key: &ApiKey, defaults: Thresholds) -> Schedule {
        let status = key.status.as_ref();
        let last_rotated = status.and_then(|s| s.last_rotated.as_ref()).map(|t| t.0);
        let expires_at = status.and_then(|s| s.expires_at.as_ref()).map(|t| t.0);
        let policy = &key.spec.rotation;
        let max_age = policy
            .max_age
            .as_deref()
            .and_then(|d| duration::parse(d).ok());
        let rotate_by = match (last_rotated, max_age) {
            (Some(at), Some(age)) => at.checked_add(age).ok(),
            _ => None,
        };
        let deadline = match (expires_at, rotate_by) {
            (Some(e), Some(r)) if r < e => Some((r, DeadlineKind::MaxAge)),
            (Some(e), _) => Some((e, DeadlineKind::Expiry)),
            (None, Some(r)) => Some((r, DeadlineKind::MaxAge)),
            (None, None) => None,
        };
        let parse_or = |value: &Option<String>, default| {
            value
                .as_deref()
                .and_then(|d| duration::parse(d).ok())
                .unwrap_or(default)
        };
        let thresholds = Thresholds {
            warn_before: parse_or(&policy.warn_before, defaults.warn_before),
            critical_before: parse_or(&policy.critical_before, defaults.critical_before),
        };
        Schedule {
            last_rotated,
            expires_at,
            rotate_by,
            deadline: if key.is_on_demand() { None } else { deadline },
            thresholds,
            on_demand: key.is_on_demand(),
        }
    }

    pub fn remaining(&self, now: Timestamp) -> Option<SignedDuration> {
        self.deadline.map(|(d, _)| d.duration_since(now))
    }

    pub fn state(&self, now: Timestamp) -> State {
        if self.on_demand {
            return State::OnDemand;
        }
        match self.remaining(now) {
            None => State::Unknown,
            Some(r) if r <= SignedDuration::ZERO => State::Expired,
            Some(r) if r < self.thresholds.critical_before => State::Critical,
            Some(r) if r < self.thresholds.warn_before => State::Warning,
            Some(_) => State::Ok,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::{ApiKeySpec, ApiKeyStatus, RotationPolicy};
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;

    fn ts(s: &str) -> Timestamp {
        s.parse().unwrap()
    }

    fn key(expires: Option<&str>, rotated: Option<&str>, max_age: Option<&str>) -> ApiKey {
        let mut k = ApiKey::new(
            "k",
            ApiKeySpec {
                rotation: RotationPolicy {
                    max_age: max_age.map(str::to_string),
                    ..Default::default()
                },
                ..Default::default()
            },
        );
        k.status = Some(ApiKeyStatus {
            expires_at: expires.map(|e| Time(ts(e))),
            last_rotated: rotated.map(|r| Time(ts(r))),
            ..Default::default()
        });
        k
    }

    #[test]
    fn deadline_is_earliest_of_expiry_and_max_age() {
        let k = key(
            Some("2026-12-31T00:00:00Z"),
            Some("2026-09-01T00:00:00Z"),
            Some("30d"),
        );
        let s = Schedule::compute(&k, Thresholds::default());
        assert_eq!(
            s.deadline,
            Some((ts("2026-10-01T00:00:00Z"), DeadlineKind::MaxAge))
        );

        let k = key(
            Some("2026-09-15T00:00:00Z"),
            Some("2026-09-01T00:00:00Z"),
            Some("30d"),
        );
        let s = Schedule::compute(&k, Thresholds::default());
        assert_eq!(
            s.deadline,
            Some((ts("2026-09-15T00:00:00Z"), DeadlineKind::Expiry))
        );
    }

    #[test]
    fn max_age_without_rotation_is_unknown() {
        let k = key(None, None, Some("90d"));
        let s = Schedule::compute(&k, Thresholds::default());
        assert_eq!(s.deadline, None);
        assert_eq!(s.state(ts("2026-09-01T00:00:00Z")), State::Unknown);
    }

    #[test]
    fn states_follow_thresholds() {
        let k = key(Some("2026-10-01T00:00:00Z"), None, None);
        let s = Schedule::compute(&k, Thresholds::default());
        assert_eq!(s.state(ts("2026-09-01T00:00:00Z")), State::Ok);
        assert_eq!(s.state(ts("2026-09-20T00:00:00Z")), State::Warning);
        assert_eq!(s.state(ts("2026-09-27T00:00:00Z")), State::Critical);
        assert_eq!(s.state(ts("2026-10-01T00:00:00Z")), State::Expired);
    }

    #[test]
    fn on_demand_keys_have_no_deadline() {
        let mut k = key(Some("2026-09-02T00:00:00Z"), None, None);
        k.spec.lifecycle = crate::crd::Lifecycle::OnDemand;
        let s = Schedule::compute(&k, Thresholds::default());
        assert_eq!(s.deadline, None);
        assert_eq!(s.state(ts("2026-10-01T00:00:00Z")), State::OnDemand);
    }

    #[test]
    fn per_key_thresholds_override_defaults() {
        let mut k = key(Some("2026-10-01T00:00:00Z"), None, None);
        k.spec.rotation.warn_before = Some("30d".into());
        k.spec.rotation.critical_before = Some("bogus".into());
        let s = Schedule::compute(&k, Thresholds::default());
        assert_eq!(
            s.thresholds.warn_before,
            SignedDuration::from_hours(30 * 24)
        );
        assert_eq!(
            s.thresholds.critical_before,
            Thresholds::default().critical_before
        );
        assert_eq!(s.state(ts("2026-09-05T00:00:00Z")), State::Warning);
    }
}

//! Rotation bookkeeping: recording a rotation by hand, and (with targets)
//! passing a new key through to the secret stores.

use std::sync::Arc;

use jiff::Timestamp;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;
use secrecy::{ExposeSecret, SecretString};
use tracing::{info, warn};

use crate::crd::{
    Actor, ApiKey, ApiKeyStatus, ExpirySource, HISTORY_LIMIT, HistoryEntry, HistoryKind,
    ProbeStatus, Provider, TargetResult, TargetStatus,
};
use crate::metrics::Metrics;
use crate::providers::{ProbeError, ProbeResult, Prober};
use crate::repo::{AuditEvent, RepoError, Repository};
use crate::targets::TargetWriter;
use crate::validation::{PathAllowList, validate};

/// Records that a key was rotated, updating dates and history.
pub fn apply_rotation(
    status: &mut ApiKeyStatus,
    at: Timestamp,
    by: &Actor,
    kind: HistoryKind,
    manual_expires_at: Option<Timestamp>,
    probe: Option<ProbeStatus>,
) {
    let probed = probe.as_ref().and_then(|p| p.expires_at.clone());
    let (expires_at, source) = match (probed, manual_expires_at) {
        (Some(p), _) => (Some(p), ExpirySource::Probe),
        (None, Some(m)) => (Some(Time(m)), ExpirySource::Manual),
        (None, None) => (None, ExpirySource::None),
    };
    status.last_rotated = Some(Time(at));
    status.rotated_by = Some(by.clone());
    status.manual_expires_at = manual_expires_at.map(Time);
    status.expires_at = expires_at.clone();
    status.expires_at_source = Some(source);
    status.probe = probe;
    status.history.insert(
        0,
        HistoryEntry {
            at: Time(at),
            by: by.clone(),
            kind,
            expires_at,
        },
    );
    status.history.truncate(HISTORY_LIMIT);
}

#[derive(Debug, thiserror::Error)]
pub enum RecordError {
    #[error("the rotation date is in the future")]
    FutureDate,
    #[error("the expiry date is before the rotation date")]
    ExpiryBeforeRotation,
    #[error(transparent)]
    Repo(#[from] RepoError),
}

/// Records a rotation done outside the app (no key involved).
pub async fn record(
    repo: &dyn Repository,
    name: &str,
    actor: &Actor,
    rotated_at: Timestamp,
    expires_at: Option<Timestamp>,
    now: Timestamp,
) -> Result<ApiKey, RecordError> {
    if rotated_at > now {
        return Err(RecordError::FutureDate);
    }
    if let Some(e) = expires_at
        && e < rotated_at
    {
        return Err(RecordError::ExpiryBeforeRotation);
    }
    let updated = repo
        .update_status(name, &|status| {
            apply_rotation(
                status,
                rotated_at,
                actor,
                HistoryKind::Recorded,
                expires_at,
                None,
            )
        })
        .await?;
    let expiry = expires_at.map_or_else(|| "no expiry".to_string(), |e| format!("expires {e}"));
    repo.record_event(
        &updated,
        AuditEvent {
            reason: "Recorded",
            note: format!("{actor} recorded a rotation at {rotated_at} ({expiry})"),
            warning: false,
        },
    )
    .await;
    tracing::info!(key = name, actor = %actor.sub, %rotated_at, "rotation recorded");
    Ok(updated)
}

/// A newly submitted key. The value is zeroed when this is dropped.
pub struct RotateRequest {
    pub value: SecretString,
    pub actor: Actor,
    pub manual_expires_at: Option<Timestamp>,
    pub skip_verification: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProbeOutcome {
    /// The provider has no probe.
    NotSupported,
    /// The admin chose to skip verification.
    Skipped,
    Checked(ProbeResult),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TargetOutcome {
    pub reference: String,
    pub error: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RotateOutcome {
    pub probe: ProbeOutcome,
    pub targets: Vec<TargetOutcome>,
    /// Every target was written, and the rotation was recorded.
    pub completed: bool,
    /// Probed and manual expiry disagree (the probed one is used).
    pub expiry_mismatch: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum RotateError {
    #[error("no API key named {0:?}")]
    NotFound(String),
    #[error("the key is empty")]
    Empty,
    #[error("this key has no targets; use Record rotation instead")]
    NoTargets,
    #[error("the ApiKey spec is invalid: {0}")]
    InvalidSpec(String),
    #[error(transparent)]
    Probe(#[from] ProbeError),
    #[error("the key was written, but saving its status failed: {0}")]
    Status(RepoError),
}

/// Passes a new key through to an `ApiKey`'s targets and records the result.
pub struct Rotator {
    repo: Arc<dyn Repository>,
    writer: Arc<dyn TargetWriter>,
    prober: Arc<dyn Prober>,
    metrics: Arc<Metrics>,
    allowed: PathAllowList,
}

impl Rotator {
    pub fn new(
        repo: Arc<dyn Repository>,
        writer: Arc<dyn TargetWriter>,
        prober: Arc<dyn Prober>,
        metrics: Arc<Metrics>,
        allowed: PathAllowList,
    ) -> Self {
        Rotator {
            repo,
            writer,
            prober,
            metrics,
            allowed,
        }
    }

    pub async fn rotate(
        &self,
        name: &str,
        req: RotateRequest,
    ) -> Result<RotateOutcome, RotateError> {
        let result = self.rotate_inner(name, &req).await;
        let label = match &result {
            Ok(o) if o.completed => "ok",
            Ok(o) if o.targets.iter().all(|t| t.error.is_some()) => "failed",
            Ok(_) => "partial",
            Err(_) => "rejected",
        };
        self.metrics.rotation(label);
        result
        // `req` (and the key in it) is dropped and zeroed here.
    }

    async fn rotate_inner(
        &self,
        name: &str,
        req: &RotateRequest,
    ) -> Result<RotateOutcome, RotateError> {
        let key = self
            .repo
            .get(name)
            .ok_or_else(|| RotateError::NotFound(name.to_string()))?;
        if req.value.expose_secret().trim().is_empty() {
            return Err(RotateError::Empty);
        }
        if key.spec.targets.is_empty() {
            return Err(RotateError::NoTargets);
        }
        let problems = validate(&key.spec, &self.allowed);
        if !problems.is_empty() {
            return Err(RotateError::InvalidSpec(problems.join("; ")));
        }

        let provider = key.spec.provider;
        let probe = if req.skip_verification {
            ProbeOutcome::Skipped
        } else if provider == Provider::Generic {
            ProbeOutcome::NotSupported
        } else {
            match self.prober.probe(provider, &req.value).await {
                Ok(Some(result)) => {
                    self.metrics.probe(provider.as_str(), "ok");
                    ProbeOutcome::Checked(result)
                }
                Ok(None) => ProbeOutcome::NotSupported,
                Err(e) => {
                    let label = match e {
                        ProbeError::Rejected(_) => "rejected",
                        ProbeError::Unavailable(_) => "error",
                    };
                    self.metrics.probe(provider.as_str(), label);
                    warn!(key = name, actor = %req.actor.sub, error = %e, "probe failed; nothing written");
                    self.repo
                        .record_event(
                            &key,
                            AuditEvent {
                                reason: "RotationRejected",
                                note: format!("{}: {e}", req.actor),
                                warning: true,
                            },
                        )
                        .await;
                    return Err(e.into());
                }
            }
        };

        let mut targets = Vec::with_capacity(key.spec.targets.len());
        for target in &key.spec.targets {
            let reference = target.reference();
            let error = self
                .writer
                .write(target, &req.value)
                .await
                .err()
                .map(|e| e.to_string());
            targets.push(TargetOutcome { reference, error });
        }
        let completed = targets.iter().all(|t| t.error.is_none());

        let now = Timestamp::now();
        let probe_status = match &probe {
            ProbeOutcome::Checked(r) => Some(ProbeStatus {
                at: Time(now),
                identity: r.identity.clone(),
                expires_at: r.expires_at.map(Time),
            }),
            _ => None,
        };
        let probed_expiry = probe_status
            .as_ref()
            .and_then(|p| p.expires_at.as_ref())
            .map(|t| t.0);
        let expiry_mismatch = matches!(
            (probed_expiry, req.manual_expires_at),
            (Some(p), Some(m)) if p.as_second() / 86_400 != m.as_second() / 86_400
        );

        let spec_refs: Vec<String> = key.spec.targets.iter().map(|t| t.reference()).collect();
        let updated = self
            .repo
            .update_status(name, &|status| {
                // Drop entries for targets no longer in the spec.
                status.targets.retain(|t| spec_refs.contains(&t.reference));
                for outcome in &targets {
                    let entry = TargetStatus {
                        reference: outcome.reference.clone(),
                        last_written: Some(Time(now)),
                        result: if outcome.error.is_none() {
                            TargetResult::Ok
                        } else {
                            TargetResult::Failed
                        },
                        message: outcome.error.clone(),
                    };
                    match status
                        .targets
                        .iter_mut()
                        .find(|t| t.reference == entry.reference)
                    {
                        Some(existing) => *existing = entry,
                        None => status.targets.push(entry),
                    }
                }
                if completed {
                    apply_rotation(
                        status,
                        now,
                        &req.actor,
                        HistoryKind::Rotated,
                        req.manual_expires_at,
                        probe_status.clone(),
                    );
                }
            })
            .await
            .map_err(RotateError::Status)?;

        let failed: Vec<&str> = targets
            .iter()
            .filter(|t| t.error.is_some())
            .map(|t| t.reference.as_str())
            .collect();
        let (reason, warning, note) = if completed {
            (
                "Rotated",
                false,
                format!(
                    "{} rotated the key ({} targets written)",
                    req.actor,
                    targets.len()
                ),
            )
        } else {
            (
                "RotationFailed",
                true,
                format!(
                    "{} submitted a key; failed targets: {}",
                    req.actor,
                    failed.join(", ")
                ),
            )
        };
        self.repo
            .record_event(
                &updated,
                AuditEvent {
                    reason,
                    note,
                    warning,
                },
            )
            .await;
        info!(key = name, actor = %req.actor.sub, completed, failed = ?failed, "key submitted");

        Ok(RotateOutcome {
            probe,
            targets,
            completed,
            expiry_mismatch,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::{ApiKeySpec, OpenBaoTarget, TargetSpec};
    use crate::providers::{NoProbe, StaticProber};
    use crate::repo::MemoryRepository;
    use crate::schedule::Thresholds;
    use crate::targets::MemoryWriter;

    fn target(path: &str) -> TargetSpec {
        TargetSpec {
            openbao: Some(OpenBaoTarget {
                mount: "secret".into(),
                path: path.into(),
                key: "token".into(),
            }),
        }
    }

    struct Fixture {
        repo: Arc<MemoryRepository>,
        writer: Arc<MemoryWriter>,
        rotator: Rotator,
    }

    fn fixture(provider: Provider, prober: Arc<dyn Prober>) -> Fixture {
        let repo = Arc::new(MemoryRepository::new([ApiKey::new(
            "k",
            ApiKeySpec {
                provider,
                targets: vec![target("a"), target("b")],
                ..Default::default()
            },
        )]));
        let writer = Arc::new(MemoryWriter::default());
        let dyn_repo: Arc<dyn Repository> = repo.clone();
        let metrics = Metrics::new(dyn_repo.clone(), Thresholds::default());
        let rotator = Rotator::new(
            dyn_repo,
            writer.clone(),
            prober,
            metrics,
            PathAllowList::allow_all(),
        );
        Fixture {
            repo,
            writer,
            rotator,
        }
    }

    fn request(value: &str) -> RotateRequest {
        RotateRequest {
            value: SecretString::from(value),
            actor: Actor::new("u-alice", "alice"),
            manual_expires_at: None,
            skip_verification: false,
        }
    }

    #[tokio::test]
    async fn rotation_writes_all_targets_and_records() {
        let f = fixture(Provider::Generic, Arc::new(NoProbe));
        let outcome = f.rotator.rotate("k", request("new-key")).await.unwrap();
        assert!(outcome.completed);
        assert_eq!(outcome.probe, ProbeOutcome::NotSupported);
        assert_eq!(
            f.writer.writes(),
            vec![
                ("openbao/secret/a#token".to_string(), 7),
                ("openbao/secret/b#token".to_string(), 7)
            ]
        );
        let status = f.repo.get("k").unwrap().status.clone().unwrap();
        assert_eq!(status.rotated_by, Some(Actor::new("u-alice", "alice")));
        assert!(status.targets.iter().all(|t| t.result == TargetResult::Ok));
        assert_eq!(status.history[0].kind, HistoryKind::Rotated);
        assert_eq!(f.repo.events()[0].1.reason, "Rotated");
    }

    #[tokio::test]
    async fn partial_failure_does_not_mark_rotated() {
        let f = fixture(Provider::Generic, Arc::new(NoProbe));
        f.writer.fail(
            "openbao/secret/b#token",
            "OpenBao write returned 403: permission denied",
        );
        let outcome = f.rotator.rotate("k", request("new-key")).await.unwrap();
        assert!(!outcome.completed);
        assert_eq!(outcome.targets[0].error, None);
        assert!(outcome.targets[1].error.as_deref().unwrap().contains("403"));
        let status = f.repo.get("k").unwrap().status.clone().unwrap();
        assert!(status.last_rotated.is_none());
        assert_eq!(status.targets[1].result, TargetResult::Failed);
        let event = &f.repo.events()[0].1;
        assert_eq!(event.reason, "RotationFailed");
        assert!(event.warning);
    }

    #[tokio::test]
    async fn rejected_probe_writes_nothing() {
        let f = fixture(
            Provider::Github,
            Arc::new(StaticProber(Err(ProbeError::Rejected(
                "401 Bad credentials".into(),
            )))),
        );
        let err = f.rotator.rotate("k", request("bad")).await.unwrap_err();
        assert!(matches!(err, RotateError::Probe(ProbeError::Rejected(_))));
        assert!(f.writer.writes().is_empty());
        assert!(f.repo.get("k").unwrap().status.is_none());
        assert_eq!(f.repo.events()[0].1.reason, "RotationRejected");

        // Skipping verification writes anyway.
        let mut req = request("bad");
        req.skip_verification = true;
        let outcome = f.rotator.rotate("k", req).await.unwrap();
        assert_eq!(outcome.probe, ProbeOutcome::Skipped);
        assert!(outcome.completed);
    }

    #[tokio::test]
    async fn probed_expiry_wins_and_mismatch_is_reported() {
        let probed = ts("2026-12-01T00:00:00Z");
        let f = fixture(
            Provider::Github,
            Arc::new(StaticProber(Ok(Some(ProbeResult {
                expires_at: Some(probed),
                identity: Some("octocat".into()),
            })))),
        );
        let mut req = request("k");
        req.manual_expires_at = Some(ts("2026-11-01T00:00:00Z"));
        let outcome = f.rotator.rotate("k", req).await.unwrap();
        assert!(outcome.expiry_mismatch);
        let status = f.repo.get("k").unwrap().status.clone().unwrap();
        assert_eq!(status.expires_at, Some(Time(probed)));
        assert_eq!(status.expires_at_source, Some(ExpirySource::Probe));
        assert_eq!(status.probe.unwrap().identity.as_deref(), Some("octocat"));
    }

    #[tokio::test]
    async fn rejects_bad_requests() {
        let f = fixture(Provider::Generic, Arc::new(NoProbe));
        assert!(matches!(
            f.rotator.rotate("k", request("  ")).await,
            Err(RotateError::Empty)
        ));
        assert!(matches!(
            f.rotator.rotate("missing", request("x")).await,
            Err(RotateError::NotFound(_))
        ));
        f.repo.insert(ApiKey::new("manual", ApiKeySpec::default()));
        assert!(matches!(
            f.rotator.rotate("manual", request("x")).await,
            Err(RotateError::NoTargets)
        ));
        let mut bad = ApiKey::new("bad", ApiKeySpec::default());
        bad.spec.targets = vec![TargetSpec::default()];
        f.repo.insert(bad);
        assert!(matches!(
            f.rotator.rotate("bad", request("x")).await,
            Err(RotateError::InvalidSpec(_))
        ));
        assert!(f.writer.writes().is_empty());
    }

    fn ts(s: &str) -> Timestamp {
        s.parse().unwrap()
    }

    fn actor(sub: &str) -> Actor {
        Actor::new(sub, format!("{sub} (display)"))
    }

    #[tokio::test]
    async fn record_updates_status_and_history() {
        let repo = MemoryRepository::new([ApiKey::new("k", ApiKeySpec::default())]);
        let now = ts("2026-09-25T12:00:00Z");
        for day in 1..=12 {
            let at = ts(&format!("2026-09-{day:02}T00:00:00Z"));
            record(&repo, "k", &actor("alice"), at, None, now)
                .await
                .unwrap();
        }
        let key = record(
            &repo,
            "k",
            &actor("bob"),
            ts("2026-09-20T00:00:00Z"),
            Some(ts("2026-12-01T00:00:00Z")),
            now,
        )
        .await
        .unwrap();
        let status = key.status.unwrap();
        assert_eq!(status.rotated_by, Some(actor("bob")));
        assert_eq!(status.expires_at_source, Some(ExpirySource::Manual));
        assert_eq!(status.expires_at, Some(Time(ts("2026-12-01T00:00:00Z"))));
        assert_eq!(status.history.len(), HISTORY_LIMIT);
        assert_eq!(status.history[0].by.sub, "bob");
        assert_eq!(repo.events().len(), 13);
        assert_eq!(repo.events()[12].1.reason, "Recorded");
    }

    #[tokio::test]
    async fn record_rejects_bad_dates() {
        let repo = MemoryRepository::new([ApiKey::new("k", ApiKeySpec::default())]);
        let now = ts("2026-09-25T12:00:00Z");
        let err = record(
            &repo,
            "k",
            &actor("a"),
            ts("2026-10-01T00:00:00Z"),
            None,
            now,
        )
        .await;
        assert!(matches!(err, Err(RecordError::FutureDate)));
        let err = record(
            &repo,
            "k",
            &actor("a"),
            ts("2026-09-01T00:00:00Z"),
            Some(ts("2026-08-01T00:00:00Z")),
            now,
        )
        .await;
        assert!(matches!(err, Err(RecordError::ExpiryBeforeRotation)));
        let err = record(&repo, "missing", &actor("a"), now, None, now).await;
        assert!(matches!(
            err,
            Err(RecordError::Repo(RepoError::NotFound(_)))
        ));
    }

    #[test]
    fn probe_expiry_wins_over_manual() {
        let mut status = ApiKeyStatus::default();
        let probe = ProbeStatus {
            at: Time(ts("2026-09-01T00:00:00Z")),
            identity: Some("me".into()),
            expires_at: Some(Time(ts("2026-11-01T00:00:00Z"))),
        };
        apply_rotation(
            &mut status,
            ts("2026-09-01T00:00:00Z"),
            &actor("a"),
            HistoryKind::Rotated,
            Some(ts("2026-12-01T00:00:00Z")),
            Some(probe),
        );
        assert_eq!(status.expires_at_source, Some(ExpirySource::Probe));
        assert_eq!(status.expires_at, Some(Time(ts("2026-11-01T00:00:00Z"))));
        assert_eq!(
            status.manual_expires_at,
            Some(Time(ts("2026-12-01T00:00:00Z")))
        );
    }
}

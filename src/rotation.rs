//! Rotation bookkeeping: recording a rotation by hand, and (with targets)
//! passing a new key through to the secret stores.

use jiff::Timestamp;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;

use crate::crd::{
    Actor, ApiKey, ApiKeyStatus, ExpirySource, HISTORY_LIMIT, HistoryEntry, HistoryKind,
    ProbeStatus,
};
use crate::repo::{AuditEvent, RepoError, Repository};

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::ApiKeySpec;
    use crate::repo::MemoryRepository;

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

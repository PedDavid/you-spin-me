//! Kubernetes-backed [`Repository`] and the controller that maintains the
//! `Valid` condition.
//!
//! The controller's reflector store doubles as the read cache for the UI
//! and metrics, so there is a single watch on `apikeys`.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use futures::StreamExt;
use jiff::Timestamp;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{Condition, Time};
use kube::api::{Patch, PatchParams, PostParams};
use kube::runtime::controller::{Action, Controller};
use kube::runtime::events::{Event, EventType, Recorder, Reporter};
use kube::runtime::reflector::{ObjectRef, Store};
use kube::runtime::watcher;
use kube::{Api, Client, Resource};
use serde_json::json;
use tracing::{debug, info, warn};

use crate::crd::ApiKey;
use crate::repo::{AuditEvent, RepoError, Repository, StatusMutation};
use crate::validation::{PathAllowList, validate};

pub const VALID_CONDITION: &str = "Valid";
const MAX_STATUS_ATTEMPTS: usize = 3;

pub struct KubeRepository {
    api: Api<ApiKey>,
    namespace: String,
    store: Store<ApiKey>,
    recorder: Recorder,
    ready: Arc<AtomicBool>,
}

struct Ctx {
    api: Api<ApiKey>,
    allowed: PathAllowList,
}

impl KubeRepository {
    /// Starts the controller in the background and returns the repository
    /// backed by its cache.
    pub fn start(client: Client, namespace: &str, allowed: PathAllowList) -> Arc<Self> {
        let api: Api<ApiKey> = Api::namespaced(client.clone(), namespace);
        let controller = Controller::new(api.clone(), watcher::Config::default());
        let store = controller.store();
        let ready = Arc::new(AtomicBool::new(false));

        let ctx = Arc::new(Ctx {
            api: api.clone(),
            allowed,
        });
        tokio::spawn(
            controller
                .run(reconcile, error_policy, ctx)
                .for_each(|result| async move {
                    match result {
                        Ok((obj, _)) => debug!(name = %obj.name, "reconciled"),
                        Err(e) => warn!(error = %e, "reconcile failed"),
                    }
                }),
        );
        {
            let store = store.clone();
            let ready = ready.clone();
            tokio::spawn(async move {
                // Re-poll with a timeout: the store's readiness signal only
                // wakes the most recent waiter, and the controller waits too.
                loop {
                    let wait = store.wait_until_ready();
                    match tokio::time::timeout(Duration::from_secs(1), wait).await {
                        Ok(Ok(())) => {
                            info!("ApiKey cache synced");
                            ready.store(true, Ordering::Relaxed);
                            return;
                        }
                        Ok(Err(_)) => return,
                        Err(_) => continue,
                    }
                }
            });
        }

        let reporter = Reporter {
            controller: "you-spin-me".into(),
            instance: std::env::var("POD_NAME").ok(),
        };
        Arc::new(KubeRepository {
            api,
            namespace: namespace.to_string(),
            store,
            recorder: Recorder::new(client, reporter),
            ready,
        })
    }
}

#[async_trait]
impl Repository for KubeRepository {
    fn list(&self) -> Vec<Arc<ApiKey>> {
        self.store.state()
    }

    fn get(&self, name: &str) -> Option<Arc<ApiKey>> {
        self.store
            .get(&ObjectRef::new(name).within(&self.namespace))
    }

    async fn update_status(
        &self,
        name: &str,
        mutate: StatusMutation<'_>,
    ) -> Result<ApiKey, RepoError> {
        for _ in 0..MAX_STATUS_ATTEMPTS {
            // A fresh read carries the resourceVersion, so a concurrent
            // write makes the replace fail with 409 instead of being lost.
            let mut obj = match self.api.get_status(name).await {
                Ok(obj) => obj,
                Err(kube::Error::Api(s)) if s.is_not_found() => {
                    return Err(RepoError::NotFound(name.to_string()));
                }
                Err(e) => return Err(e.into()),
            };
            let mut status = obj.status.take().unwrap_or_default();
            mutate(&mut status);
            obj.status = Some(status);
            match self
                .api
                .replace_status(name, &PostParams::default(), &obj)
                .await
            {
                Ok(updated) => return Ok(updated),
                Err(kube::Error::Api(s)) if s.is_conflict() => continue,
                Err(e) => return Err(e.into()),
            }
        }
        Err(RepoError::Conflict)
    }

    async fn record_event(&self, key: &ApiKey, event: AuditEvent) {
        let ev = Event {
            type_: if event.warning {
                EventType::Warning
            } else {
                EventType::Normal
            },
            reason: event.reason.to_string(),
            note: Some(event.note),
            action: event.reason.to_string(),
            secondary: None,
        };
        if let Err(e) = self.recorder.publish(&ev, &key.object_ref(&())).await {
            warn!(error = %e, key = key.name(), "failed to publish event");
        }
    }

    fn ready(&self) -> bool {
        self.ready.load(Ordering::Relaxed)
    }
}

/// Desired `Valid` condition for `key`, or `None` if the current one is up to date.
pub fn desired_valid_condition(
    key: &ApiKey,
    allowed: &PathAllowList,
    now: Timestamp,
) -> Option<Condition> {
    let problems = validate(&key.spec, allowed);
    let (status, reason, message) = if problems.is_empty() {
        ("True", "Valid", "Spec is valid".to_string())
    } else {
        ("False", "InvalidSpec", problems.join("; "))
    };
    let generation = key.metadata.generation;
    let existing = key.condition(VALID_CONDITION);
    if let Some(c) = existing
        && c.status == status
        && c.message == message
        && c.observed_generation == generation
    {
        return None;
    }
    let last_transition_time = match existing {
        Some(c) if c.status == status => c.last_transition_time.clone(),
        _ => Time(now),
    };
    Some(Condition {
        type_: VALID_CONDITION.into(),
        status: status.into(),
        reason: reason.into(),
        message,
        observed_generation: generation,
        last_transition_time,
    })
}

async fn reconcile(key: Arc<ApiKey>, ctx: Arc<Ctx>) -> Result<Action, kube::Error> {
    let Some(condition) = desired_valid_condition(&key, &ctx.allowed, Timestamp::now()) else {
        return Ok(Action::await_change());
    };
    let mut conditions: Vec<Condition> = key
        .status
        .as_ref()
        .map(|s| {
            s.conditions
                .iter()
                .filter(|c| c.type_ != VALID_CONDITION)
                .cloned()
                .collect()
        })
        .unwrap_or_default();
    conditions.push(condition);
    let patch = json!({
        "status": {
            "conditions": conditions,
            "observedGeneration": key.metadata.generation,
        }
    });
    ctx.api
        .patch_status(key.name(), &PatchParams::default(), &Patch::Merge(&patch))
        .await?;
    Ok(Action::await_change())
}

fn error_policy(_key: Arc<ApiKey>, _error: &kube::Error, _ctx: Arc<Ctx>) -> Action {
    Action::requeue(Duration::from_secs(30))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::{ApiKeySpec, ApiKeyStatus};

    #[test]
    fn valid_condition_is_only_rewritten_on_change() {
        let now: Timestamp = "2026-09-01T00:00:00Z".parse().unwrap();
        let allowed = PathAllowList::allow_all();
        let mut key = ApiKey::new("k", ApiKeySpec::default());
        key.metadata.generation = Some(1);

        let first = desired_valid_condition(&key, &allowed, now).unwrap();
        assert_eq!(first.status, "True");

        key.status = Some(ApiKeyStatus {
            conditions: vec![first.clone()],
            ..Default::default()
        });
        assert!(desired_valid_condition(&key, &allowed, now).is_none());

        key.spec.rotation.max_age = Some("nope".into());
        key.metadata.generation = Some(2);
        let later: Timestamp = "2026-09-02T00:00:00Z".parse().unwrap();
        let second = desired_valid_condition(&key, &allowed, later).unwrap();
        assert_eq!(second.status, "False");
        assert_eq!(second.reason, "InvalidSpec");
        assert_eq!(second.last_transition_time, Time(later));
    }
}

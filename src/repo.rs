//! Access to `ApiKey` resources: a cached read side and status writes.
//!
//! [`crate::k8s::KubeRepository`] is the real implementation;
//! [`MemoryRepository`] backs tests and `--demo` mode.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use async_trait::async_trait;

use crate::crd::{ApiKey, ApiKeyStatus};

#[derive(Debug, thiserror::Error)]
pub enum RepoError {
    #[error("ApiKey {0:?} not found")]
    NotFound(String),
    #[error("conflicting concurrent update, try again")]
    Conflict,
    #[error("kubernetes API error: {0}")]
    Kube(#[from] kube::Error),
}

/// An audit record, published as a Kubernetes Event on the `ApiKey`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditEvent {
    /// PascalCase reason, e.g. `Rotated`.
    pub reason: &'static str,
    pub note: String,
    pub warning: bool,
}

pub type StatusMutation<'a> = &'a (dyn Fn(&mut ApiKeyStatus) + Send + Sync);

#[async_trait]
pub trait Repository: Send + Sync + 'static {
    /// All `ApiKey`s from the local cache.
    fn list(&self) -> Vec<Arc<ApiKey>>;

    fn get(&self, name: &str) -> Option<Arc<ApiKey>>;

    /// Applies `mutate` to the current status of `name` and writes it back,
    /// retrying on conflicts. Returns the updated object.
    async fn update_status(
        &self,
        name: &str,
        mutate: StatusMutation<'_>,
    ) -> Result<ApiKey, RepoError>;

    /// Best effort: failures are logged, not returned.
    async fn record_event(&self, key: &ApiKey, event: AuditEvent);

    /// True once the cache has synced.
    fn ready(&self) -> bool;
}

/// In-memory repository for tests and demo mode.
#[derive(Default)]
pub struct MemoryRepository {
    keys: RwLock<BTreeMap<String, Arc<ApiKey>>>,
    events: RwLock<Vec<(String, AuditEvent)>>,
}

impl MemoryRepository {
    pub fn new(keys: impl IntoIterator<Item = ApiKey>) -> Self {
        let repo = MemoryRepository::default();
        for key in keys {
            repo.insert(key);
        }
        repo
    }

    pub fn insert(&self, key: ApiKey) {
        let name = key.name().to_string();
        self.keys.write().unwrap().insert(name, Arc::new(key));
    }

    pub fn events(&self) -> Vec<(String, AuditEvent)> {
        self.events.read().unwrap().clone()
    }
}

#[async_trait]
impl Repository for MemoryRepository {
    fn list(&self) -> Vec<Arc<ApiKey>> {
        self.keys.read().unwrap().values().cloned().collect()
    }

    fn get(&self, name: &str) -> Option<Arc<ApiKey>> {
        self.keys.read().unwrap().get(name).cloned()
    }

    async fn update_status(
        &self,
        name: &str,
        mutate: StatusMutation<'_>,
    ) -> Result<ApiKey, RepoError> {
        let mut keys = self.keys.write().unwrap();
        let current = keys
            .get(name)
            .ok_or_else(|| RepoError::NotFound(name.to_string()))?;
        let mut updated = ApiKey::clone(current);
        let mut status = updated.status.take().unwrap_or_default();
        mutate(&mut status);
        updated.status = Some(status);
        keys.insert(name.to_string(), Arc::new(updated.clone()));
        Ok(updated)
    }

    async fn record_event(&self, key: &ApiKey, event: AuditEvent) {
        self.events
            .write()
            .unwrap()
            .push((key.name().to_string(), event));
    }

    fn ready(&self) -> bool {
        true
    }
}

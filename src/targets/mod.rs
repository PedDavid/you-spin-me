//! Write-only secret stores that a rotated key is passed through to.

pub mod openbao;

use std::sync::Mutex;

use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretString};

use crate::crd::TargetSpec;

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum TargetError {
    #[error("target has no store configured")]
    Unconfigured,
    #[error("{0}")]
    Store(String),
}

#[async_trait]
pub trait TargetWriter: Send + Sync + 'static {
    /// Writes `value` to `target`. Must never read the stored value back
    /// or include it in errors or logs.
    async fn write(&self, target: &TargetSpec, value: &SecretString) -> Result<(), TargetError>;
}

/// Records writes in memory, for tests and demo mode. Stores only the
/// length of each value.
#[derive(Default)]
pub struct MemoryWriter {
    writes: Mutex<Vec<(String, usize)>>,
    /// References that fail with the given message.
    failing: Mutex<Vec<(String, String)>>,
}

impl MemoryWriter {
    pub fn fail(&self, reference: &str, message: &str) {
        self.failing
            .lock()
            .unwrap()
            .push((reference.to_string(), message.to_string()));
    }

    pub fn writes(&self) -> Vec<(String, usize)> {
        self.writes.lock().unwrap().clone()
    }
}

#[async_trait]
impl TargetWriter for MemoryWriter {
    async fn write(&self, target: &TargetSpec, value: &SecretString) -> Result<(), TargetError> {
        let reference = target.reference();
        if let Some((_, msg)) = self
            .failing
            .lock()
            .unwrap()
            .iter()
            .find(|(r, _)| *r == reference)
        {
            return Err(TargetError::Store(msg.clone()));
        }
        self.writes
            .lock()
            .unwrap()
            .push((reference, value.expose_secret().len()));
        Ok(())
    }
}

/// Used when no OpenBao address is configured: every write fails.
pub struct NoStore;

#[async_trait]
impl TargetWriter for NoStore {
    async fn write(&self, _: &TargetSpec, _: &SecretString) -> Result<(), TargetError> {
        Err(TargetError::Store(
            "no OpenBao address configured (--openbao-addr)".into(),
        ))
    }
}

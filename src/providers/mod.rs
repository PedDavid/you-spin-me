//! Expiry probes: one call to the provider's API with a newly submitted key,
//! to validate it and learn when it expires.

use async_trait::async_trait;
use jiff::Timestamp;
use secrecy::SecretString;

use crate::crd::Provider;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProbeResult {
    pub expires_at: Option<Timestamp>,
    /// Who the key belongs to (login, token id…). Never the key itself.
    pub identity: Option<String>,
}

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum ProbeError {
    #[error("the provider rejected the key: {0}")]
    Rejected(String),
    #[error("could not check the key with the provider: {0}")]
    Unavailable(String),
}

#[async_trait]
pub trait Prober: Send + Sync + 'static {
    /// `Ok(None)` means the provider has no probe.
    async fn probe(
        &self,
        provider: Provider,
        key: &SecretString,
    ) -> Result<Option<ProbeResult>, ProbeError>;
}

/// No probes at all: every provider is treated as `generic`.
pub struct NoProbe;

#[async_trait]
impl Prober for NoProbe {
    async fn probe(
        &self,
        _: Provider,
        _: &SecretString,
    ) -> Result<Option<ProbeResult>, ProbeError> {
        Ok(None)
    }
}

/// Canned answers, for tests and demo mode.
pub struct StaticProber(pub Result<Option<ProbeResult>, ProbeError>);

#[async_trait]
impl Prober for StaticProber {
    async fn probe(
        &self,
        _: Provider,
        _: &SecretString,
    ) -> Result<Option<ProbeResult>, ProbeError> {
        self.0.clone()
    }
}

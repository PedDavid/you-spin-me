//! Prometheus metrics. Per-key gauges are computed from the repository
//! cache on every scrape; counters track rotations and probes.

use std::sync::Arc;

use jiff::Timestamp;
use prometheus_client::encoding::{DescriptorEncoder, EncodeLabelSet, EncodeMetric};
use prometheus_client::metrics::MetricType;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::ConstGauge;
use prometheus_client::registry::Registry;

use crate::crd::{ApiKey, TargetResult};
use crate::repo::Repository;
use crate::schedule::{Schedule, Thresholds};

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct ResultLabels {
    pub result: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct ProbeLabels {
    pub provider: String,
    pub result: String,
}

pub struct Metrics {
    registry: Registry,
    pub rotations: Family<ResultLabels, Counter>,
    pub probes: Family<ProbeLabels, Counter>,
}

impl Metrics {
    pub fn new(repo: Arc<dyn Repository>, thresholds: Thresholds) -> Arc<Self> {
        let mut registry = Registry::default();
        let rotations = Family::<ResultLabels, Counter>::default();
        let probes = Family::<ProbeLabels, Counter>::default();
        registry.register(
            "youspinme_rotations",
            "Key submissions by result (ok, partial, failed, rejected)",
            rotations.clone(),
        );
        registry.register(
            "youspinme_probe_requests",
            "Provider probe requests by provider and result",
            probes.clone(),
        );
        registry.register_collector(Box::new(KeyCollector { repo, thresholds }));
        Arc::new(Metrics {
            registry,
            rotations,
            probes,
        })
    }

    pub fn rotation(&self, result: &str) {
        self.rotations
            .get_or_create(&ResultLabels {
                result: result.into(),
            })
            .inc();
    }

    pub fn probe(&self, provider: &str, result: &str) {
        self.probes
            .get_or_create(&ProbeLabels {
                provider: provider.into(),
                result: result.into(),
            })
            .inc();
    }

    pub fn encode(&self) -> String {
        let mut out = String::new();
        prometheus_client::encoding::text::encode(&mut out, &self.registry)
            .expect("writing to a String cannot fail");
        out
    }
}

struct KeyCollector {
    repo: Arc<dyn Repository>,
    thresholds: Thresholds,
}

impl std::fmt::Debug for KeyCollector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyCollector").finish_non_exhaustive()
    }
}

type Labels = Vec<(&'static str, String)>;

fn key_labels(key: &ApiKey) -> Labels {
    vec![
        ("namespace", key.namespace().to_string()),
        ("name", key.name().to_string()),
        ("provider", key.spec.provider.as_str().to_string()),
        ("owner", key.spec.owner.clone().unwrap_or_default()),
    ]
}

fn seconds(t: Timestamp) -> f64 {
    t.as_millisecond() as f64 / 1000.0
}

struct Row {
    key: Arc<ApiKey>,
    labels: Labels,
    schedule: Schedule,
}

fn gauge(
    encoder: &mut DescriptorEncoder,
    rows: &[Row],
    name: &str,
    help: &str,
    value: impl Fn(&Row) -> Option<f64>,
) -> Result<(), std::fmt::Error> {
    let mut metric = encoder.encode_descriptor(name, help, None, MetricType::Gauge)?;
    for row in rows {
        if let Some(v) = value(row) {
            ConstGauge::new(v).encode(metric.encode_family(&row.labels)?)?;
        }
    }
    Ok(())
}

impl prometheus_client::collector::Collector for KeyCollector {
    fn encode(&self, mut encoder: DescriptorEncoder) -> Result<(), std::fmt::Error> {
        let all: Vec<Row> = self
            .repo
            .list()
            .into_iter()
            .map(|key| Row {
                labels: key_labels(&key),
                schedule: Schedule::compute(&key, self.thresholds),
                key,
            })
            .collect();
        // On-demand keys have no deadline: they get the info and last-used
        // metrics only, so they never trigger deadline or unknown-state alerts.
        let (on_demand, rows): (Vec<Row>, Vec<Row>) =
            all.into_iter().partition(|r| r.key.is_on_demand());

        {
            let mut info = encoder.encode_descriptor(
                "youspinme_apikey",
                "ApiKey metadata, for joins in alert annotations",
                None,
                MetricType::Info,
            )?;
            for row in rows.iter().chain(&on_demand) {
                let mut labels = row.labels.clone();
                labels.push(("lifecycle", row.key.spec.lifecycle.as_str().to_string()));
                labels.push(("display_name", row.key.display_name().to_string()));
                labels.push((
                    "renew_url",
                    row.key.spec.renew_url.clone().unwrap_or_default(),
                ));
                info.encode_info(&labels)?;
            }
        }

        gauge(
            &mut encoder,
            &on_demand,
            "youspinme_apikey_last_used_timestamp_seconds",
            "On-demand keys: when the create page was last opened",
            |r| {
                r.key
                    .status
                    .as_ref()
                    .and_then(|s| s.last_used.as_ref())
                    .map(|t| seconds(t.0))
            },
        )?;
        gauge(
            &mut encoder,
            &rows,
            "youspinme_apikey_expiry_timestamp_seconds",
            "Effective expiry of the key (probed or entered by hand)",
            |r| r.schedule.expires_at.map(seconds),
        )?;
        gauge(
            &mut encoder,
            &rows,
            "youspinme_apikey_rotate_by_timestamp_seconds",
            "lastRotated + maxAge",
            |r| r.schedule.rotate_by.map(seconds),
        )?;
        gauge(
            &mut encoder,
            &rows,
            "youspinme_apikey_deadline_timestamp_seconds",
            "Earlier of expiry and rotate-by; the one to alert on",
            |r| r.schedule.deadline.map(|(d, _)| seconds(d)),
        )?;
        gauge(
            &mut encoder,
            &rows,
            "youspinme_apikey_last_rotated_timestamp_seconds",
            "When the key was last rotated or recorded",
            |r| r.schedule.last_rotated.map(seconds),
        )?;
        gauge(
            &mut encoder,
            &rows,
            "youspinme_apikey_warn_before_seconds",
            "Warning threshold before the deadline",
            |r| Some(r.schedule.thresholds.warn_before.as_secs_f64()),
        )?;
        gauge(
            &mut encoder,
            &rows,
            "youspinme_apikey_critical_before_seconds",
            "Critical threshold before the deadline",
            |r| Some(r.schedule.thresholds.critical_before.as_secs_f64()),
        )?;
        gauge(
            &mut encoder,
            &rows,
            "youspinme_apikey_state_known",
            "1 if the key has a deadline, 0 if its state is unknown",
            |r| {
                Some(if r.schedule.deadline.is_some() {
                    1.0
                } else {
                    0.0
                })
            },
        )?;

        let mut healthy = encoder.encode_descriptor(
            "youspinme_apikey_target_healthy",
            "1 if the last write to the target succeeded",
            None,
            MetricType::Gauge,
        )?;
        for row in &rows {
            let Some(status) = &row.key.status else {
                continue;
            };
            for target in &status.targets {
                let mut labels = row.labels.clone();
                labels.push(("target", target.reference.clone()));
                let value = if target.result == TargetResult::Ok {
                    1.0
                } else {
                    0.0
                };
                ConstGauge::new(value).encode(healthy.encode_family(&labels)?)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::{ApiKeySpec, ApiKeyStatus, TargetStatus};
    use crate::repo::MemoryRepository;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;

    #[test]
    fn exports_key_gauges() {
        let mut key = ApiKey::new(
            "renovate",
            ApiKeySpec {
                owner: Some("david".into()),
                renew_url: Some("https://example.com".into()),
                ..Default::default()
            },
        );
        key.metadata.namespace = Some("ysm".into());
        key.status = Some(ApiKeyStatus {
            expires_at: Some(Time("2026-10-01T00:00:00Z".parse().unwrap())),
            targets: vec![TargetStatus {
                reference: "openbao/secret/ci#token".into(),
                last_written: None,
                result: TargetResult::Failed,
                message: None,
            }],
            ..Default::default()
        });
        let unknown = ApiKey::new("unknown", ApiKeySpec::default());
        let mut adhoc = ApiKey::new(
            "adhoc",
            ApiKeySpec {
                lifecycle: crate::crd::Lifecycle::OnDemand,
                ..Default::default()
            },
        );
        adhoc.status = Some(ApiKeyStatus {
            last_used: Some(Time("2026-09-01T00:00:00Z".parse().unwrap())),
            ..Default::default()
        });
        let repo: Arc<dyn Repository> = Arc::new(MemoryRepository::new([key, unknown, adhoc]));
        let metrics = Metrics::new(repo, Thresholds::default());
        metrics.rotation("ok");
        metrics.probe("github", "ok");
        let text = metrics.encode();

        assert!(text.contains(
            r#"youspinme_apikey_deadline_timestamp_seconds{namespace="ysm",name="renovate",provider="generic",owner="david"} 1790812800"#
        ), "{text}");
        assert!(
            text.contains(r#"youspinme_apikey_info{namespace="ysm",name="renovate""#),
            "{text}"
        );
        assert!(
            text.contains(r#"renew_url="https://example.com"} 1"#),
            "{text}"
        );
        assert!(text.contains(r#"youspinme_apikey_state_known{namespace="",name="unknown",provider="generic",owner=""} 0"#), "{text}");
        assert!(text.contains(r#"youspinme_apikey_warn_before_seconds{namespace="ysm",name="renovate",provider="generic",owner="david"} 1209600"#), "{text}");
        assert!(
            text.contains(r#"target="openbao/secret/ci#token"} 0"#),
            "{text}"
        );
        assert!(
            text.contains(r#"youspinme_rotations_total{result="ok"} 1"#),
            "{text}"
        );
        // On-demand keys: info and last-used only, never state_known = 0.
        assert!(text.contains(r#"youspinme_apikey_last_used_timestamp_seconds{namespace="",name="adhoc",provider="generic",owner=""} 1788220800"#), "{text}");
        assert!(text.contains(r#"lifecycle="onDemand""#), "{text}");
        assert!(
            !text.contains(r#"youspinme_apikey_state_known{namespace="",name="adhoc""#),
            "{text}"
        );
        assert!(
            text.contains(r#"youspinme_probe_requests_total{provider="github",result="ok"} 1"#),
            "{text}"
        );
    }
}

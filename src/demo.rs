//! Sample `ApiKey`s for `--demo` mode.

use jiff::{SignedDuration, Timestamp};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;

use crate::crd::{
    ApiKey, ApiKeySpec, ApiKeyStatus, ExpirySource, HistoryEntry, HistoryKind, OpenBaoTarget,
    Provider, RotationPolicy, Setup, TargetResult, TargetSpec, TargetStatus,
};

fn days(n: i64) -> SignedDuration {
    SignedDuration::from_hours(24 * n)
}

fn target(path: &str, key: &str) -> TargetSpec {
    TargetSpec {
        openbao: Some(OpenBaoTarget {
            mount: "secret".into(),
            path: path.into(),
            key: key.into(),
        }),
    }
}

struct Sample {
    name: &'static str,
    display: &'static str,
    provider: Provider,
    renew: &'static str,
    permissions: &'static [&'static str],
    max_age: Option<&'static str>,
    targets: Vec<TargetSpec>,
    consumers: &'static [&'static str],
    rotated_days_ago: Option<i64>,
    expires_in_days: Option<i64>,
    target_failed: bool,
}

pub fn sample_keys(now: Timestamp) -> Vec<ApiKey> {
    let samples = vec![
        Sample {
            name: "renovate-github",
            display: "Renovate – GitHub token",
            provider: Provider::Github,
            renew: "https://github.com/settings/personal-access-tokens",
            permissions: &["contents: read", "pull_requests: write", "workflows: write"],
            max_age: Some("90d"),
            targets: vec![target("ci/renovate", "token")],
            consumers: &["GitHub Actions secret RENOVATE_TOKEN in infra repo"],
            rotated_days_ago: Some(80),
            expires_in_days: Some(10),
            target_failed: false,
        },
        Sample {
            name: "cloudflare-ddns",
            display: "Cloudflare – DDNS",
            provider: Provider::Cloudflare,
            renew: "https://dash.cloudflare.com/profile/api-tokens",
            permissions: &["Zone.DNS: edit"],
            max_age: None,
            targets: vec![],
            consumers: &["Router web UI → Dynamic DNS"],
            rotated_days_ago: Some(360),
            expires_in_days: Some(3),
            target_failed: false,
        },
        Sample {
            name: "openai-homeassistant",
            display: "OpenAI – Home Assistant",
            provider: Provider::Generic,
            renew: "https://platform.openai.com/api-keys",
            permissions: &["project: home-assistant", "models: read"],
            max_age: Some("180d"),
            targets: vec![target("home/home-assistant", "openai_api_key")],
            consumers: &[],
            rotated_days_ago: Some(20),
            expires_in_days: None,
            target_failed: false,
        },
        Sample {
            name: "hetzner-backups",
            display: "Hetzner – backup box",
            provider: Provider::Generic,
            renew: "https://console.hetzner.cloud/",
            permissions: &["read & write"],
            max_age: Some("365d"),
            targets: vec![target("backups/restic", "hcloud_token")],
            consumers: &[],
            rotated_days_ago: Some(370),
            expires_in_days: None,
            target_failed: true,
        },
        Sample {
            name: "tailscale-authkey",
            display: "Tailscale – auth key",
            provider: Provider::Generic,
            renew: "https://login.tailscale.com/admin/settings/keys",
            permissions: &["reusable", "tag:k8s"],
            max_age: Some("90d"),
            targets: vec![target("net/tailscale", "authkey")],
            consumers: &[],
            rotated_days_ago: None,
            expires_in_days: None,
            target_failed: false,
        },
    ];

    samples
        .into_iter()
        .map(|s| {
            let mut key = ApiKey::new(
                s.name,
                ApiKeySpec {
                    display_name: Some(s.display.into()),
                    provider: s.provider,
                    owner: Some("david".into()),
                    renew_url: Some(s.renew.into()),
                    setup: Setup {
                        permissions: s.permissions.iter().map(|p| p.to_string()).collect(),
                        notes: None,
                    },
                    rotation: RotationPolicy {
                        max_age: s.max_age.map(str::to_string),
                        ..Default::default()
                    },
                    targets: s.targets.clone(),
                    consumers: s.consumers.iter().map(|c| c.to_string()).collect(),
                },
            );
            key.metadata.namespace = Some("demo".into());
            if let Some(ago) = s.rotated_days_ago {
                let rotated = now - days(ago);
                let expires = s.expires_in_days.map(|d| Time(now + days(d)));
                key.status = Some(ApiKeyStatus {
                    last_rotated: Some(Time(rotated)),
                    rotated_by: Some("david".into()),
                    expires_at_source: Some(if expires.is_some() {
                        ExpirySource::Manual
                    } else {
                        ExpirySource::None
                    }),
                    manual_expires_at: expires.clone(),
                    expires_at: expires.clone(),
                    targets: s
                        .targets
                        .iter()
                        .map(|t| TargetStatus {
                            reference: t.reference(),
                            last_written: Some(Time(rotated)),
                            result: if s.target_failed {
                                TargetResult::Failed
                            } else {
                                TargetResult::Ok
                            },
                            message: s
                                .target_failed
                                .then(|| "OpenBao returned 403: permission denied".into()),
                        })
                        .collect(),
                    history: vec![HistoryEntry {
                        at: Time(rotated),
                        by: "david".into(),
                        kind: if s.targets.is_empty() {
                            HistoryKind::Recorded
                        } else {
                            HistoryKind::Rotated
                        },
                        expires_at: expires,
                    }],
                    ..Default::default()
                });
            }
            key
        })
        .collect()
}

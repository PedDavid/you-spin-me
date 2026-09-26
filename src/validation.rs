//! Checks for an `ApiKey` spec, reported through the `Valid` condition.

use crate::crd::{ApiKeySpec, Lifecycle};
use crate::duration;

/// Globs for OpenBao target paths, matched against `<mount>/data/<path>` with
/// OpenBao policy semantics: `+` matches one path segment, a trailing `*`
/// matches any suffix.
#[derive(Clone, Debug)]
pub struct PathAllowList {
    patterns: Vec<String>,
}

impl PathAllowList {
    pub fn new<I, S>(patterns: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        PathAllowList {
            patterns: patterns
                .into_iter()
                .map(Into::into)
                .map(|p: String| p.trim().to_string())
                .filter(|p| !p.is_empty())
                .collect(),
        }
    }

    pub fn allow_all() -> Self {
        PathAllowList::new(["*"])
    }

    pub fn allows(&self, path: &str) -> bool {
        self.patterns.iter().any(|p| glob_match(p, path))
    }

    pub fn patterns(&self) -> &[String] {
        &self.patterns
    }
}

fn glob_match(pattern: &str, path: &str) -> bool {
    let (pattern, prefix) = match pattern.strip_suffix('*') {
        Some(p) => (p, true),
        None => (pattern, false),
    };
    let mut rest = path;
    let mut pat_segments = pattern.split('/').peekable();
    while let Some(seg) = pat_segments.next() {
        let is_last = pat_segments.peek().is_none();
        if is_last && prefix {
            // Final (possibly partial) segment before `*`: plain prefix match,
            // unless it is `+`, which must match one segment first.
            if seg == "+" {
                return match rest.find('/') {
                    Some(i) => i > 0,
                    None => !rest.is_empty(),
                };
            }
            return rest.starts_with(seg);
        }
        let (current, remaining) = match rest.find('/') {
            Some(i) => (&rest[..i], Some(&rest[i + 1..])),
            None => (rest, None),
        };
        let matched = if seg == "+" {
            !current.is_empty()
        } else {
            current == seg
        };
        if !matched {
            return false;
        }
        match remaining {
            Some(r) => rest = r,
            None => return pat_segments.peek().is_none() && !prefix,
        }
    }
    false
}

/// Returns the problems found in `spec`; empty means valid.
pub fn validate(spec: &ApiKeySpec, allowed: &PathAllowList) -> Vec<String> {
    let mut problems = Vec::new();
    if spec.lifecycle == Lifecycle::OnDemand {
        if !spec.targets.is_empty() {
            problems
                .push("lifecycle onDemand: keys are never stored, so targets must be empty".into());
        }
        if spec.rotation.max_age.is_some() {
            problems.push(
                "lifecycle onDemand: keys have no rotation policy, remove rotation.maxAge".into(),
            );
        }
    }
    let rotation = &spec.rotation;
    for (field, value) in [
        ("rotation.maxAge", &rotation.max_age),
        ("rotation.warnBefore", &rotation.warn_before),
        ("rotation.criticalBefore", &rotation.critical_before),
    ] {
        if let Some(v) = value
            && let Err(e) = duration::parse(v)
        {
            problems.push(format!("{field}: {e}"));
        }
    }
    if let (Some(w), Some(c)) = (
        rotation
            .warn_before
            .as_deref()
            .and_then(|d| duration::parse(d).ok()),
        rotation
            .critical_before
            .as_deref()
            .and_then(|d| duration::parse(d).ok()),
    ) && c > w
    {
        problems.push("rotation.criticalBefore is longer than rotation.warnBefore".into());
    }
    if let Some(url) = &spec.renew_url {
        match url::Url::parse(url) {
            Ok(u) if u.scheme() == "https" || u.scheme() == "http" => {}
            _ => problems.push(format!("renewUrl: {url:?} is not an http(s) URL")),
        }
    }
    let mut seen = std::collections::HashSet::new();
    for (i, target) in spec.targets.iter().enumerate() {
        match &target.openbao {
            None => problems.push(format!(
                "targets[{i}]: no target type set (expected openbao)"
            )),
            Some(t) => {
                for (field, value) in [("mount", &t.mount), ("path", &t.path), ("key", &t.key)] {
                    if value.trim().is_empty() {
                        problems.push(format!("targets[{i}].openbao.{field} is empty"));
                    }
                }
                if t.path.split('/').any(|s| s == "..") || t.mount.contains('/') {
                    problems.push(format!("targets[{i}].openbao: invalid mount or path"));
                }
                let policy_path = t.policy_path();
                if !allowed.allows(&policy_path) {
                    problems.push(format!(
                        "targets[{i}]: {policy_path} is not in allowedPaths ({})",
                        allowed.patterns().join(", ")
                    ));
                }
                if !seen.insert(t.reference()) {
                    problems.push(format!("targets[{i}]: duplicate target {}", t.reference()));
                }
            }
        }
    }
    problems
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::{OpenBaoTarget, TargetSpec};

    #[test]
    fn globs_follow_openbao_semantics() {
        let cases = [
            ("*", "secret/data/anything", true),
            ("secret/data/ci/*", "secret/data/ci/renovate", true),
            ("secret/data/ci/*", "secret/data/cid", false),
            ("secret/data/ci*", "secret/data/cid", true),
            ("secret/data/ci/renovate", "secret/data/ci/renovate", true),
            (
                "secret/data/ci/renovate",
                "secret/data/ci/renovate/x",
                false,
            ),
            (
                "secret/data/+/api-keys/*",
                "secret/data/home/api-keys/openai",
                true,
            ),
            (
                "secret/data/+/api-keys/*",
                "secret/data/home/other/openai",
                false,
            ),
            ("secret/data/+", "secret/data/home", true),
            ("secret/data/+", "secret/data/home/x", false),
            ("kv/*", "secret/data/x", false),
        ];
        for (pattern, path, expected) in cases {
            assert_eq!(glob_match(pattern, path), expected, "{pattern} vs {path}");
        }
    }

    fn target(mount: &str, path: &str, key: &str) -> TargetSpec {
        TargetSpec {
            openbao: Some(OpenBaoTarget {
                mount: mount.into(),
                path: path.into(),
                key: key.into(),
            }),
        }
    }

    #[test]
    fn valid_spec_has_no_problems() {
        let spec = ApiKeySpec {
            renew_url: Some("https://example.com/keys".into()),
            targets: vec![target("secret", "ci/renovate", "token")],
            ..Default::default()
        };
        assert!(validate(&spec, &PathAllowList::allow_all()).is_empty());
    }

    #[test]
    fn on_demand_keys_cannot_be_stored_or_rotated() {
        let mut spec = ApiKeySpec {
            lifecycle: Lifecycle::OnDemand,
            renew_url: Some("https://example.com/new".into()),
            ..Default::default()
        };
        assert!(validate(&spec, &PathAllowList::allow_all()).is_empty());
        spec.targets = vec![target("secret", "x", "token")];
        spec.rotation.max_age = Some("30d".into());
        let text = validate(&spec, &PathAllowList::allow_all()).join("\n");
        assert!(text.contains("targets must be empty"), "{text}");
        assert!(text.contains("remove rotation.maxAge"), "{text}");
    }

    #[test]
    fn reports_problems() {
        let mut spec = ApiKeySpec {
            renew_url: Some("javascript:alert(1)".into()),
            targets: vec![
                target("secret", "ci/renovate", "token"),
                target("secret", "ci/renovate", "token"),
                target("secret", "home/x", "token"),
                TargetSpec::default(),
            ],
            ..Default::default()
        };
        spec.rotation.max_age = Some("forever".into());
        spec.rotation.warn_before = Some("1d".into());
        spec.rotation.critical_before = Some("2d".into());
        let problems = validate(&spec, &PathAllowList::new(["secret/data/ci/*"]));
        let text = problems.join("\n");
        assert!(text.contains("rotation.maxAge"), "{text}");
        assert!(text.contains("criticalBefore is longer"), "{text}");
        assert!(text.contains("renewUrl"), "{text}");
        assert!(text.contains("duplicate target"), "{text}");
        assert!(
            text.contains("secret/data/home/x is not in allowedPaths"),
            "{text}"
        );
        assert!(text.contains("no target type set"), "{text}");
    }
}

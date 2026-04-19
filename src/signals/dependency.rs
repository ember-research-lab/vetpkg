use crate::signals::Check;
use crate::types::{PackageIntel, PolicyConfig, Signal};
use std::collections::HashSet;

pub struct NewDependencyCheck;

/// Cap on how many new-dep signals can be emitted per package. Having many
/// new deps is one signal of change, not N signals — emitting every one
/// overwhelms the scorer for packages that legitimately add a handful of
/// siblings in a release.
pub const MAX_NEW_DEP_SIGNALS: usize = 3;

impl Check for NewDependencyCheck {
    fn name(&self) -> &'static str {
        "new_dependency"
    }

    fn evaluate(&self, intel: &PackageIntel, _config: &PolicyConfig) -> Vec<Signal> {
        // Skip silently when we have no prior baseline to compare against —
        // otherwise every package on first scan looks like it has "all new"
        // deps, which is indistinguishable from a real attacker adding them.
        if intel.prior_dependencies.is_empty() {
            return Vec::new();
        }
        let prior: HashSet<_> = intel.prior_dependencies.iter().cloned().collect();
        intel
            .dependencies
            .iter()
            .filter(|d| !prior.contains(*d))
            .take(MAX_NEW_DEP_SIGNALS)
            .map(|d| Signal::NewDependency { name: d.clone() })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_new_deps_no_signal() {
        let intel = PackageIntel {
            prior_dependencies: vec!["a".into()],
            dependencies: vec!["a".into()],
            ..Default::default()
        };
        assert!(NewDependencyCheck
            .evaluate(&intel, &PolicyConfig::default())
            .is_empty());
    }

    #[test]
    fn one_new_dep_fires() {
        let intel = PackageIntel {
            prior_dependencies: vec!["a".into()],
            dependencies: vec!["a".into(), "b".into()],
            ..Default::default()
        };
        let out = NewDependencyCheck.evaluate(&intel, &PolicyConfig::default());
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn empty_prior_skips_check() {
        // Without a baseline, every dep would look "new" — we can't
        // meaningfully compare, so stay quiet.
        let intel = PackageIntel {
            prior_dependencies: vec![],
            dependencies: vec!["a".into(), "b".into(), "c".into()],
            ..Default::default()
        };
        assert!(NewDependencyCheck
            .evaluate(&intel, &PolicyConfig::default())
            .is_empty());
    }

    #[test]
    fn cap_prevents_score_runaway() {
        let intel = PackageIntel {
            prior_dependencies: vec!["a".into()],
            dependencies: (0..20).map(|i| format!("d{i}")).collect(),
            ..Default::default()
        };
        let out = NewDependencyCheck.evaluate(&intel, &PolicyConfig::default());
        assert_eq!(out.len(), MAX_NEW_DEP_SIGNALS);
    }
}

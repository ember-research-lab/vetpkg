use crate::signals::Check;
use crate::types::{PackageIntel, PolicyConfig, Signal};
use std::collections::HashSet;

pub struct NewDependencyCheck;

impl Check for NewDependencyCheck {
    fn name(&self) -> &'static str {
        "new_dependency"
    }

    fn evaluate(&self, intel: &PackageIntel, _config: &PolicyConfig) -> Vec<Signal> {
        let prior: HashSet<_> = intel.prior_dependencies.iter().cloned().collect();
        intel
            .dependencies
            .iter()
            .filter(|d| !prior.contains(*d))
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
}

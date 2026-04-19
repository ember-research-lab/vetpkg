use crate::signals::Check;
use crate::types::{PackageIntel, PolicyConfig, Signal};
use std::collections::HashSet;

pub struct MaintainerChangeCheck;

impl Check for MaintainerChangeCheck {
    fn name(&self) -> &'static str {
        "maintainer"
    }

    fn evaluate(&self, intel: &PackageIntel, _config: &PolicyConfig) -> Vec<Signal> {
        if intel.prior_maintainers.is_empty() {
            return Vec::new();
        }
        let prior: HashSet<_> = intel.prior_maintainers.iter().cloned().collect();
        let curr: HashSet<_> = intel.maintainers.iter().cloned().collect();
        let added: Vec<String> = curr.difference(&prior).cloned().collect();
        let removed: Vec<String> = prior.difference(&curr).cloned().collect();
        if added.is_empty() && removed.is_empty() {
            return Vec::new();
        }
        vec![Signal::MaintainerChange { added, removed }]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_change_no_signal() {
        let intel = PackageIntel {
            prior_maintainers: vec!["a".into()],
            maintainers: vec!["a".into()],
            ..Default::default()
        };
        assert!(MaintainerChangeCheck
            .evaluate(&intel, &PolicyConfig::default())
            .is_empty());
    }

    #[test]
    fn swap_fires() {
        let intel = PackageIntel {
            prior_maintainers: vec!["a".into()],
            maintainers: vec!["b".into()],
            ..Default::default()
        };
        let out = MaintainerChangeCheck.evaluate(&intel, &PolicyConfig::default());
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn first_publish_no_signal() {
        let intel = PackageIntel {
            prior_maintainers: vec![],
            maintainers: vec!["a".into()],
            ..Default::default()
        };
        assert!(MaintainerChangeCheck
            .evaluate(&intel, &PolicyConfig::default())
            .is_empty());
    }
}

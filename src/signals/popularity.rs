use crate::signals::Check;
use crate::types::{PackageIntel, PolicyConfig, Signal};

pub struct PopularityAnomalyCheck;

impl Check for PopularityAnomalyCheck {
    fn name(&self) -> &'static str {
        "popularity"
    }

    fn evaluate(&self, intel: &PackageIntel, _config: &PolicyConfig) -> Vec<Signal> {
        if let Some(rank) = intel.popularity_rank {
            if rank > 100_000 && !intel.install_hooks.is_empty() {
                return vec![Signal::PopularityAnomaly {
                    reason: format!("low-popularity (rank {rank}) with install hooks"),
                }];
            }
        }
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::InstallHook;

    #[test]
    fn popular_no_signal() {
        let intel = PackageIntel {
            popularity_rank: Some(500),
            install_hooks: vec![InstallHook {
                stage: "postinstall".into(),
                command: "node setup.js".into(),
            }],
            ..Default::default()
        };
        assert!(PopularityAnomalyCheck
            .evaluate(&intel, &PolicyConfig::default())
            .is_empty());
    }

    #[test]
    fn unknown_with_hooks_fires() {
        let intel = PackageIntel {
            popularity_rank: Some(500_000),
            install_hooks: vec![InstallHook {
                stage: "postinstall".into(),
                command: "node setup.js".into(),
            }],
            ..Default::default()
        };
        let out = PopularityAnomalyCheck.evaluate(&intel, &PolicyConfig::default());
        assert_eq!(out.len(), 1);
    }
}

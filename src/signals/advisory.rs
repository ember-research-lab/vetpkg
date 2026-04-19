use crate::signals::Check;
use crate::types::{PackageIntel, PolicyConfig, Signal};

pub struct AdvisoryCheck;

impl Check for AdvisoryCheck {
    fn name(&self) -> &'static str {
        "advisory"
    }

    fn evaluate(&self, intel: &PackageIntel, _config: &PolicyConfig) -> Vec<Signal> {
        intel
            .advisories
            .iter()
            .map(|a| Signal::AdvisoryCheck {
                id: a.id.clone(),
                severity: a.severity,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Advisory, Severity};

    #[test]
    fn no_advisories_no_signal() {
        let intel = PackageIntel {
            name: "express".into(),
            ..Default::default()
        };
        assert!(AdvisoryCheck
            .evaluate(&intel, &PolicyConfig::default())
            .is_empty());
    }

    #[test]
    fn advisory_produces_signal() {
        let intel = PackageIntel {
            name: "lodash".into(),
            advisories: vec![Advisory {
                id: "GHSA-x1x1".into(),
                severity: Severity::High,
                summary: "test".into(),
            }],
            ..Default::default()
        };
        let out = AdvisoryCheck.evaluate(&intel, &PolicyConfig::default());
        assert_eq!(out.len(), 1);
        assert!(matches!(
            out[0],
            Signal::AdvisoryCheck {
                severity: Severity::High,
                ..
            }
        ));
    }
}

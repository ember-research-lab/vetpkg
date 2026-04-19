use crate::signals::Check;
use crate::types::{PackageIntel, PolicyConfig, Signal};

pub struct FreshPackageCheck;

impl Check for FreshPackageCheck {
    fn name(&self) -> &'static str {
        "fresh_package"
    }

    fn evaluate(&self, intel: &PackageIntel, config: &PolicyConfig) -> Vec<Signal> {
        let mut out = Vec::new();
        if let Some(age) = intel.age_hours {
            if age < config.fresh_package_hours {
                out.push(Signal::FreshPackage { age_hours: age });
            }
        }
        for (dep, age) in &intel.dep_ages {
            if *age < config.fresh_package_hours {
                out.push(Signal::FreshPackage { age_hours: *age });
                let _ = dep;
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mature_package_no_signal() {
        let intel = PackageIntel {
            age_hours: Some(24.0 * 365.0),
            ..Default::default()
        };
        assert!(FreshPackageCheck
            .evaluate(&intel, &PolicyConfig::default())
            .is_empty());
    }

    #[test]
    fn young_package_fires() {
        let intel = PackageIntel {
            age_hours: Some(2.0),
            ..Default::default()
        };
        let out = FreshPackageCheck.evaluate(&intel, &PolicyConfig::default());
        assert_eq!(out.len(), 1);
    }
}

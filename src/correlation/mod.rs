//! Cross-ecosystem correlation engine.
//!
//! Three correlation kinds feed multiplicative multipliers, stacked and
//! capped at 3.0 per the plan resolutions:
//!   - Maintainer (Task 20): shared email address flagging anomalous
//!     activity across ≥2 ecosystems within 24h → 1.5× (3+ eco → 2.0×)
//!   - Package name (Task 21): same name anomalous in another ecosystem
//!     within 48h → 2.0×
//!   - URL (Task 21): URLs extracted from sink-matched lines reused
//!     across 2+ packages within 7d → 2.5×
//!
//! `final_score = min(base * maintainer * name * url, 1.0)` where each
//! multiplier defaults to 1.0 when no correlation found, with the stack
//! itself clamped to a 3.0 ceiling to prevent runaway combinations.

pub mod indexes;
pub mod url_extract;

use indexes::{MaintainerIndex, NameIndex, UrlIndex};
use std::time::Duration;

pub const MAINTAINER_WINDOW: Duration = Duration::from_secs(24 * 3600);
pub const NAME_WINDOW: Duration = Duration::from_secs(48 * 3600);
pub const URL_WINDOW: Duration = Duration::from_secs(7 * 24 * 3600);

pub const MAINTAINER_MULT_2: f64 = 1.5;
pub const MAINTAINER_MULT_3: f64 = 2.0;
pub const NAME_MULT: f64 = 2.0;
pub const URL_MULT: f64 = 2.5;
pub const STACK_CAP: f64 = 3.0;

pub const ANOMALY_THRESHOLD: f64 = 0.15;

#[derive(Debug, Clone, Default)]
pub struct CorrelationReport {
    pub maintainer_multiplier: f64,
    pub maintainer_reason: Option<String>,
    pub name_multiplier: f64,
    pub name_reason: Option<String>,
    pub url_multiplier: f64,
    pub url_reasons: Vec<String>,
}

impl CorrelationReport {
    pub fn stacked(&self) -> f64 {
        self.maintainer_multiplier
            .max(1.0)
            .mul(self.name_multiplier.max(1.0))
            .mul(self.url_multiplier.max(1.0))
            .min(STACK_CAP)
    }

    pub fn any_fired(&self) -> bool {
        self.maintainer_multiplier > 1.0 || self.name_multiplier > 1.0 || self.url_multiplier > 1.0
    }
}

trait FloatMul {
    fn mul(self, rhs: f64) -> f64;
}
impl FloatMul for f64 {
    fn mul(self, rhs: f64) -> f64 {
        self * rhs
    }
}

pub fn apply_correlation(base: f64, report: &CorrelationReport) -> f64 {
    let multiplier = report.stacked();
    (base * multiplier).min(1.0)
}

pub struct EvaluateInput<'a> {
    pub package: &'a str,
    pub ecosystem: &'a str,
    pub base_score: f64,
    pub maintainers: &'a [String],
    pub extracted_urls: &'a [String],
}

pub struct Indexes<'a> {
    pub maintainer: &'a MaintainerIndex,
    pub name: &'a NameIndex,
    pub url: &'a UrlIndex,
}

#[allow(clippy::too_many_arguments)]
pub fn evaluate(
    package: &str,
    ecosystem: &str,
    base_score: f64,
    maintainers: &[String],
    extracted_urls: &[String],
    maintainer_idx: &MaintainerIndex,
    name_idx: &NameIndex,
    url_idx: &UrlIndex,
) -> CorrelationReport {
    evaluate_with(
        &EvaluateInput {
            package,
            ecosystem,
            base_score,
            maintainers,
            extracted_urls,
        },
        &Indexes {
            maintainer: maintainer_idx,
            name: name_idx,
            url: url_idx,
        },
    )
}

pub fn evaluate_with(input: &EvaluateInput<'_>, idx: &Indexes<'_>) -> CorrelationReport {
    let package = input.package;
    let ecosystem = input.ecosystem;
    let base_score = input.base_score;
    let maintainers = input.maintainers;
    let extracted_urls = input.extracted_urls;
    let maintainer_idx = idx.maintainer;
    let name_idx = idx.name;
    let url_idx = idx.url;
    let now = indexes::now_unix();
    let mut report = CorrelationReport {
        maintainer_multiplier: 1.0,
        name_multiplier: 1.0,
        url_multiplier: 1.0,
        ..Default::default()
    };

    if base_score > ANOMALY_THRESHOLD {
        for email in maintainers {
            let anomalous: Vec<_> = maintainer_idx
                .packages_for(email)
                .filter(|entry| {
                    entry.ecosystem != ecosystem
                        && entry.last_score > ANOMALY_THRESHOLD
                        && now.saturating_sub(entry.last_seen) <= MAINTAINER_WINDOW.as_secs()
                })
                .collect();
            let ecos: std::collections::BTreeSet<&str> =
                anomalous.iter().map(|e| e.ecosystem.as_str()).collect();
            let count = ecos.len() + 1;
            if count >= 3 {
                report.maintainer_multiplier = MAINTAINER_MULT_3;
                report.maintainer_reason = Some(format!(
                    "email {email} anomalous across {count} ecosystems within 24h"
                ));
                break;
            } else if count == 2 {
                report.maintainer_multiplier = MAINTAINER_MULT_2;
                report.maintainer_reason = Some(format!(
                    "email {email} anomalous across 2 ecosystems within 24h"
                ));
            }
        }

        let name_hits: Vec<_> = name_idx
            .entries_for(package)
            .filter(|entry| {
                entry.ecosystem != ecosystem
                    && entry.last_score > ANOMALY_THRESHOLD
                    && now.saturating_sub(entry.last_seen) <= NAME_WINDOW.as_secs()
            })
            .collect();
        if !name_hits.is_empty() {
            report.name_multiplier = NAME_MULT;
            report.name_reason = Some(format!(
                "same name {package} anomalous in {} other ecosystem(s) within 48h",
                name_hits.len()
            ));
        }
    }

    for url in extracted_urls {
        let others: Vec<_> = url_idx
            .seen_elsewhere(url, ecosystem, package)
            .filter(|entry| now.saturating_sub(entry.last_seen) <= URL_WINDOW.as_secs())
            .collect();
        if !others.is_empty() {
            report.url_multiplier = URL_MULT;
            for entry in others {
                let msg = format!(
                    "URL {url} reused by {}:{} within 7d",
                    entry.ecosystem, entry.package
                );
                if !report.url_reasons.contains(&msg) {
                    report.url_reasons.push(msg);
                }
            }
        }
    }

    report
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stacking_caps_at_three() {
        let r = CorrelationReport {
            maintainer_multiplier: MAINTAINER_MULT_3,
            name_multiplier: NAME_MULT,
            url_multiplier: URL_MULT,
            ..Default::default()
        };
        assert!((r.stacked() - 3.0).abs() < 1e-9);
    }

    #[test]
    fn no_correlation_leaves_score_unchanged() {
        let r = CorrelationReport::default();
        let r = CorrelationReport {
            maintainer_multiplier: 1.0,
            name_multiplier: 1.0,
            url_multiplier: 1.0,
            ..r
        };
        assert_eq!(apply_correlation(0.4, &r), 0.4);
        assert!(!r.any_fired());
    }

    #[test]
    fn block_ceiling_at_one() {
        let r = CorrelationReport {
            maintainer_multiplier: MAINTAINER_MULT_2,
            name_multiplier: NAME_MULT,
            url_multiplier: 1.0,
            ..Default::default()
        };
        assert!(apply_correlation(0.5, &r) <= 1.0);
    }

    #[test]
    fn teampcp_scenario_blocks_via_multiplier() {
        let r = CorrelationReport {
            maintainer_multiplier: MAINTAINER_MULT_2,
            name_multiplier: NAME_MULT,
            url_multiplier: 1.0,
            ..Default::default()
        };
        let final_score = apply_correlation(0.35, &r);
        assert!(
            final_score >= 0.6,
            "TeamPCP should block; got {final_score}"
        );
    }
}

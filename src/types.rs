use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Ecosystem {
    Npm,
    PyPI,
    Cargo,
}

impl Ecosystem {
    pub fn as_str(self) -> &'static str {
        match self {
            Ecosystem::Npm => "npm",
            Ecosystem::PyPI => "pypi",
            Ecosystem::Cargo => "cargo",
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct PackageIntel {
    pub ecosystem: Option<Ecosystem>,
    pub name: String,
    pub version: String,
    pub maintainers: Vec<String>,
    pub prior_maintainers: Vec<String>,
    pub publish_time: Option<u64>,
    pub publish_history: Vec<(String, u64)>,
    pub dependencies: Vec<String>,
    pub prior_dependencies: Vec<String>,
    pub install_hooks: Vec<InstallHook>,
    pub advisories: Vec<Advisory>,
    pub typosquat_matches: Vec<String>,
    pub age_hours: Option<f64>,
    pub dep_ages: HashMap<String, f64>,
    pub popularity_rank: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct InstallHook {
    pub stage: String,
    pub command: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Advisory {
    pub id: String,
    pub severity: Severity,
    pub summary: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Unknown,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Signal {
    AdvisoryCheck {
        id: String,
        severity: Severity,
    },
    MaintainerChange {
        added: Vec<String>,
        removed: Vec<String>,
    },
    HookCheck {
        stage: String,
        reason: String,
    },
    NewDependency {
        name: String,
    },
    PopularityAnomaly {
        reason: String,
    },
    FreshPackage {
        age_hours: f64,
    },
    Typosquat {
        matched: String,
        distance: f32,
    },
    PublishAnomaly {
        kind: PublishAnomalyKind,
        detail: String,
    },
    BinaryBlobDetection {
        kind: BlobKind,
        path: String,
        detail: String,
    },
    BuildScriptDiff {
        kind: BuildScriptKind,
        file: String,
        detail: String,
    },
    TaintDetection {
        kind: TaintKind,
        file: String,
        detail: String,
    },
    InfiniteLoop {
        file: String,
        pattern: String,
    },
    BinShadow {
        bin_name: String,
        target: String,
    },
    ResolvedUrlMismatch {
        name: String,
        expected_registry: String,
        actual_url: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaintKind {
    SameScopePath,
    VariableFlow,
    FileCoOccurrence,
    LoneSourceOrSink,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublishAnomalyKind {
    Cadence,
    HourOfDay,
    VersionSequence,
    /// Maintainer set unchanged + previous publish was > 12 months
    /// ago. Catches the canonical hijack-of-popular-package shape:
    /// same account, long-dormant, then suddenly active. Distinct
    /// from MaintainerChange (which catches *new* maintainers).
    /// Source: is_package_jul2025 incident; tracked since corpus
    /// extension §2.1.
    DormantMaintainer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlobKind {
    NewHighEntropyInTestDir,
    NewHighEntropyElsewhere,
    CompressedInsideTarball,
    ChangedExistingBlob,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildScriptKind {
    NewShellExec,
    ReadFromTestOrData,
    DecompressTestFixture,
    EnvManipulation,
    SecurityRemoval,
    PatchVersionChange,
}

impl Signal {
    pub fn weight(&self) -> f64 {
        match self {
            Signal::AdvisoryCheck { severity, .. } => match severity {
                Severity::Critical => 0.5,
                Severity::High => 0.4,
                Severity::Medium => 0.2,
                Severity::Low => 0.1,
                Severity::Unknown => 0.3,
            },
            Signal::MaintainerChange { .. } => 0.25,
            Signal::HookCheck { .. } => 0.2,
            Signal::NewDependency { .. } => 0.1,
            Signal::PopularityAnomaly { .. } => 0.15,
            Signal::FreshPackage { .. } => 0.2,
            Signal::Typosquat { .. } => 0.35,
            Signal::PublishAnomaly { kind, .. } => match kind {
                PublishAnomalyKind::Cadence => 0.15,
                PublishAnomalyKind::HourOfDay => 0.10,
                PublishAnomalyKind::VersionSequence => 0.10,
                // Higher weight than other publish anomalies because
                // dormant-account compromise with new behaviour is a
                // strong-signal hijack pattern, not a calibration blip.
                PublishAnomalyKind::DormantMaintainer => 0.30,
            },
            Signal::BinaryBlobDetection { kind, .. } => match kind {
                BlobKind::NewHighEntropyInTestDir => 0.25,
                BlobKind::NewHighEntropyElsewhere => 0.15,
                BlobKind::CompressedInsideTarball => 0.20,
                BlobKind::ChangedExistingBlob => 0.10,
            },
            Signal::BuildScriptDiff { kind, .. } => match kind {
                BuildScriptKind::NewShellExec => 0.20,
                BuildScriptKind::ReadFromTestOrData => 0.25,
                BuildScriptKind::DecompressTestFixture => 0.25,
                BuildScriptKind::EnvManipulation => 0.15,
                BuildScriptKind::SecurityRemoval => 0.20,
                BuildScriptKind::PatchVersionChange => 0.10,
            },
            Signal::TaintDetection { kind, .. } => match kind {
                TaintKind::SameScopePath => 0.35,
                TaintKind::VariableFlow => 0.30,
                TaintKind::FileCoOccurrence => 0.15,
                TaintKind::LoneSourceOrSink => 0.05,
            },
            Signal::InfiniteLoop { .. } => 0.30,
            Signal::BinShadow { .. } => 0.35,
            Signal::ResolvedUrlMismatch { .. } => 0.40,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RiskScore {
    pub score: f64,
    pub signals: Vec<Signal>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    Warn,
    Block,
}

#[derive(Debug, Clone)]
pub struct PolicyConfig {
    pub port: u16,
    pub allow_threshold: f64,
    pub block_threshold: f64,
    pub typosquat_distance_threshold: f32,
    pub fresh_package_hours: f64,
    pub npm_upstream: String,
    pub pypi_upstream: String,
    pub cargo_index_upstream: String,
    pub cargo_dl_upstream: String,
    pub timeout_secs: u32,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            port: 9451,
            allow_threshold: 0.3,
            block_threshold: 0.6,
            typosquat_distance_threshold: 0.15,
            fresh_package_hours: 72.0,
            npm_upstream: "https://registry.npmjs.org".to_string(),
            pypi_upstream: "https://pypi.org".to_string(),
            cargo_index_upstream: "https://index.crates.io".to_string(),
            cargo_dl_upstream: "https://static.crates.io".to_string(),
            timeout_secs: 30,
        }
    }
}

impl PolicyConfig {
    pub fn verdict(&self, score: f64) -> Verdict {
        if score >= self.block_threshold {
            Verdict::Block
        } else if score >= self.allow_threshold {
            Verdict::Warn
        } else {
            Verdict::Allow
        }
    }
}

pub trait RegistryAdapter {
    fn ecosystem(&self) -> Ecosystem;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdict_thresholds() {
        let cfg = PolicyConfig::default();
        assert_eq!(cfg.verdict(0.0), Verdict::Allow);
        assert_eq!(cfg.verdict(0.25), Verdict::Allow);
        assert_eq!(cfg.verdict(0.3), Verdict::Warn);
        assert_eq!(cfg.verdict(0.59), Verdict::Warn);
        assert_eq!(cfg.verdict(0.6), Verdict::Block);
        assert_eq!(cfg.verdict(1.0), Verdict::Block);
    }

    #[test]
    fn ecosystem_str() {
        assert_eq!(Ecosystem::Npm.as_str(), "npm");
        assert_eq!(Ecosystem::PyPI.as_str(), "pypi");
        assert_eq!(Ecosystem::Cargo.as_str(), "cargo");
    }

    #[test]
    fn signal_weights() {
        let s = Signal::Typosquat {
            matched: "react".into(),
            distance: 0.1,
        };
        assert!((s.weight() - 0.35).abs() < 1e-9);
    }
}

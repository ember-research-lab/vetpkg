use std::path::PathBuf;
use std::time::Duration;

use vetpkg::cli::audit::{audit, report_as_json, AuditOptions};
use vetpkg::types::Verdict;

fn fixture_path() -> PathBuf {
    PathBuf::from("tests/fixtures/package-lock-v3.json")
}

#[test]
fn audit_parses_v3_lockfile_and_finds_typosquats() {
    let opts = AuditOptions {
        path: fixture_path(),
        full: false,
        as_json: false,
        fail_on_warn: false,
    };
    let report = audit(&opts).expect("audit ran");
    assert_eq!(report.lockfile_version, 3);
    assert!(
        report.package_count >= 10,
        "expected >=10 packages, got {}",
        report.package_count
    );

    let block_or_warn: Vec<_> = report
        .findings
        .iter()
        .filter(|f| matches!(f.verdict, Verdict::Block | Verdict::Warn))
        .collect();

    assert!(
        block_or_warn.iter().any(|f| f.name == "requets"),
        "'requets' should be flagged as a typosquat of 'requests'"
    );
    assert!(
        block_or_warn.iter().any(|f| f.name == "expreess"),
        "'expreess' should be flagged as a typosquat of 'express'"
    );

    for f in &report.findings {
        if [
            "express",
            "lodash",
            "react",
            "debug",
            "left-pad",
            "axios",
            "follow-redirects",
            "@vercel/next",
        ]
        .contains(&f.name.as_str())
        {
            assert_eq!(
                f.verdict,
                Verdict::Allow,
                "{} should Allow, got {:?} score {:.3} signals {:?}",
                f.name,
                f.verdict,
                f.score,
                f.signals
            );
        }
    }
}

#[test]
fn audit_sorts_by_score_desc() {
    let opts = AuditOptions {
        path: fixture_path(),
        full: false,
        as_json: false,
        fail_on_warn: false,
    };
    let report = audit(&opts).unwrap();
    for window in report.findings.windows(2) {
        assert!(
            window[0].score >= window[1].score,
            "findings not sorted: {} ({:.3}) before {} ({:.3})",
            window[0].name,
            window[0].score,
            window[1].name,
            window[1].score,
        );
    }
}

#[test]
fn audit_json_parses_and_includes_summary() {
    let opts = AuditOptions {
        path: fixture_path(),
        full: false,
        as_json: true,
        fail_on_warn: false,
    };
    let report = audit(&opts).unwrap();
    let json = report_as_json(&report);
    let parsed = vetpkg::json::parse(&json).expect("emitted JSON must reparse");
    assert!(parsed.get("lockfile").is_some());
    assert!(parsed.get("summary").is_some());
    assert!(parsed.get("findings").is_some());
    let summary = parsed.get("summary").unwrap();
    assert!(summary.get("block").is_some());
    assert!(summary.get("warn").is_some());
    assert!(summary.get("allow").is_some());
}

#[test]
fn audit_rejects_v1_lockfile() {
    let td = vetpkg::platform::TempDir::new("vetpkg-v1").unwrap();
    let lock = td.path().join("package-lock.json");
    std::fs::write(
        &lock,
        r#"{"name":"x","version":"1.0.0","lockfileVersion":1}"#,
    )
    .unwrap();
    let opts = AuditOptions {
        path: lock,
        full: false,
        as_json: false,
        fail_on_warn: false,
    };
    let err = audit(&opts).unwrap_err();
    assert!(err.contains("v1"));
}

#[test]
fn audit_missing_lockfile_clear_error() {
    let opts = AuditOptions {
        path: PathBuf::from("/no-such-path-for-vetpkg-audit-test"),
        full: false,
        as_json: false,
        fail_on_warn: false,
    };
    let err = audit(&opts).unwrap_err();
    assert!(err.to_lowercase().contains("no package-lock.json"));
}

#[test]
fn audit_meets_30s_sla_on_1000_pkgs() {
    let mut entries = String::new();
    entries.push_str("{\n  \"name\":\"big\",\n  \"version\":\"1.0.0\",\n  \"lockfileVersion\":3,\n  \"packages\":{\n");
    entries.push_str("    \"\":{\"name\":\"big\",\"version\":\"1.0.0\"}");
    for i in 0..1000 {
        entries.push_str(&format!(
            ",\n    \"node_modules/pkg-{i}\":{{\"version\":\"1.0.0\",\"resolved\":\"https://x/y.tgz\"}}"
        ));
    }
    entries.push_str("\n  }\n}\n");

    let td = vetpkg::platform::TempDir::new("vetpkg-big-lock").unwrap();
    let lock = td.path().join("package-lock.json");
    std::fs::write(&lock, &entries).unwrap();

    let opts = AuditOptions {
        path: lock,
        full: false,
        as_json: false,
        fail_on_warn: false,
    };
    let start = std::time::Instant::now();
    let report = audit(&opts).unwrap();
    let elapsed = start.elapsed();
    assert_eq!(report.package_count, 1000);
    let budget = if cfg!(debug_assertions) {
        Duration::from_secs(60)
    } else {
        Duration::from_secs(30)
    };
    assert!(
        elapsed < budget,
        "audit took {:?}, budget {:?}",
        elapsed,
        budget
    );
}

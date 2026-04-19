//! Phase 5 audit-ci end-to-end — builds a synthetic .github/workflows/
//! directory, runs the CLI-layer audit, and asserts the expected findings.

use std::fs;
use std::path::PathBuf;

use vetpkg::ci::Severity;
use vetpkg::cli::audit_ci::{audit, report_as_json, AuditOptions};
use vetpkg::platform::TempDir;

fn write(root: &std::path::Path, rel: &str, content: &str) {
    let p = root.join(rel);
    if let Some(parent) = p.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(&p, content).unwrap();
}

#[test]
fn audit_ci_flags_unpinned_branch_and_secret_in_run() {
    let td = TempDir::new("audit-ci-flag").unwrap();
    write(
        td.path(),
        ".github/workflows/ci.yml",
        r#"name: CI
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: some/thirdparty@main
      - name: deploy
        run: |
          curl -sSL https://deploy.example.com/${{ secrets.API_KEY }}
"#,
    );
    let opts = AuditOptions {
        path: PathBuf::from(td.path()),
        ..Default::default()
    };
    let report = audit(&opts).unwrap();
    let severities: Vec<Severity> = report.findings.iter().map(|f| f.severity).collect();
    assert!(
        severities.contains(&Severity::High),
        "{:#?}",
        report.findings
    );
    assert!(
        severities.contains(&Severity::Medium),
        "{:#?}",
        report.findings
    );
}

#[test]
fn audit_ci_clean_sha_pinned_workflow() {
    let td = TempDir::new("audit-ci-clean").unwrap();
    write(
        td.path(),
        ".github/workflows/ci.yml",
        r#"name: CI
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
      - name: test
        run: echo hi
"#,
    );
    let opts = AuditOptions {
        path: PathBuf::from(td.path()),
        ..Default::default()
    };
    let report = audit(&opts).unwrap();
    let bad: Vec<_> = report
        .findings
        .iter()
        .filter(|f| {
            matches!(
                f.severity,
                Severity::Medium | Severity::High | Severity::Critical
            )
        })
        .collect();
    assert!(bad.is_empty(), "unexpected findings: {:#?}", bad);
}

#[test]
fn audit_ci_json_emits_parseable_shape() {
    let td = TempDir::new("audit-ci-json").unwrap();
    write(
        td.path(),
        ".github/workflows/ci.yml",
        "jobs:\n  b:\n    runs-on: x\n    steps:\n      - uses: some/action@v1\n",
    );
    let opts = AuditOptions {
        path: PathBuf::from(td.path()),
        as_json: true,
        ..Default::default()
    };
    let report = audit(&opts).unwrap();
    let json = report_as_json(&report);
    let parsed = vetpkg::json::parse(&json).unwrap();
    assert!(parsed.get("findings").is_some());
    let summary = parsed.get("summary").unwrap();
    assert!(summary.get("high").is_some());
}

#[test]
fn audit_ci_missing_workflows_dir_errors_clearly() {
    let td = TempDir::new("audit-ci-missing").unwrap();
    let opts = AuditOptions {
        path: PathBuf::from(td.path()),
        ..Default::default()
    };
    let r = audit(&opts);
    assert!(r.is_err(), "expected error for missing workflows dir");
}

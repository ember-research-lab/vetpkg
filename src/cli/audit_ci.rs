//! `vetpkg audit-ci` — audit GitHub Actions workflows for supply-chain
//! defensibility. No `--online` fetching in this pass (the network
//! integration is a follow-up); the offline checks already cover
//! unpinned actions, permission scoping, and secret exposure.

use crate::ci::actions::scan_workflow;
use crate::ci::{Finding, Severity};
use crate::json::{to_json_string, JsonValue};
use crate::yaml::parse_yaml;
use std::fs;
use std::path::{Path, PathBuf};

pub struct AuditOptions {
    pub path: PathBuf,
    pub online: bool,
    pub strict: bool,
    pub as_json: bool,
}

pub struct AuditReport {
    pub workflows: Vec<PathBuf>,
    pub findings: Vec<Finding>,
}

pub fn run(args: Vec<String>) -> Result<u8, String> {
    let opts = parse_args(&args)?;
    let report = audit(&opts)?;
    if opts.as_json {
        println!("{}", report_as_json(&report));
    } else {
        print_human(&report);
    }
    let has_findings = report.findings.iter().any(|f| {
        matches!(
            f.severity,
            Severity::Medium | Severity::High | Severity::Critical
        )
    });
    if has_findings && opts.strict {
        Ok(1)
    } else {
        Ok(0)
    }
}

fn parse_args(args: &[String]) -> Result<AuditOptions, String> {
    let mut path = PathBuf::from(".");
    let mut online = false;
    let mut strict = false;
    let mut as_json = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--path" => {
                i += 1;
                path = PathBuf::from(args.get(i).ok_or("--path requires a value")?);
            }
            "--online" => online = true,
            "--strict" => strict = true,
            "--json" => as_json = true,
            other => return Err(format!("unknown audit-ci flag: {other}")),
        }
        i += 1;
    }
    Ok(AuditOptions {
        path,
        online,
        strict,
        as_json,
    })
}

pub fn audit(opts: &AuditOptions) -> Result<AuditReport, String> {
    if opts.online {
        eprintln!("note: --online network checks not yet wired; offline checks still run.");
    }
    let workflows = find_workflows(&opts.path)?;
    let mut findings: Vec<Finding> = Vec::new();
    for wf in &workflows {
        let text = fs::read_to_string(wf).map_err(|e| format!("read {:?}: {e}", wf))?;
        let parsed = match parse_yaml(&text) {
            Ok(v) => v,
            Err(e) => {
                findings.push(Finding {
                    severity: Severity::Medium,
                    file: wf.to_string_lossy().into_owned(),
                    line: 0,
                    check: crate::ci::Check::PermissionScope,
                    message: format!("YAML parse error: {e}"),
                    subject: None,
                });
                continue;
            }
        };
        let wf_label = wf.to_string_lossy().into_owned();
        findings.extend(scan_workflow(&wf_label, &parsed));
    }
    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.file.cmp(&b.file))
    });
    Ok(AuditReport {
        workflows,
        findings,
    })
}

fn find_workflows(root: &Path) -> Result<Vec<PathBuf>, String> {
    let workflows_dir = if root.ends_with("workflows") {
        root.to_path_buf()
    } else if root.is_file() {
        return Ok(vec![root.to_path_buf()]);
    } else {
        root.join(".github").join("workflows")
    };
    if !workflows_dir.is_dir() {
        return Err(format!("no .github/workflows at {:?}", root));
    }
    let mut files = Vec::new();
    for entry in
        fs::read_dir(&workflows_dir).map_err(|e| format!("read_dir {:?}: {e}", workflows_dir))?
    {
        let entry = entry.map_err(|e| format!("entry error: {e}"))?;
        let p = entry.path();
        if p.is_file() {
            if let Some(ext) = p.extension().and_then(|e| e.to_str()) {
                if ext == "yml" || ext == "yaml" {
                    files.push(p);
                }
            }
        }
    }
    files.sort();
    Ok(files)
}

pub fn report_as_json(r: &AuditReport) -> String {
    let (c, h, m, l, i) = counts(&r.findings);
    let findings_json: Vec<JsonValue> = r
        .findings
        .iter()
        .map(|f| {
            JsonValue::Object(vec![
                (
                    "severity".into(),
                    JsonValue::Str(f.severity.label().to_ascii_lowercase()),
                ),
                ("file".into(), JsonValue::Str(f.file.clone())),
                ("line".into(), JsonValue::Number(f.line as f64)),
                ("check".into(), JsonValue::Str(f.check.label().into())),
                ("message".into(), JsonValue::Str(f.message.clone())),
                (
                    "subject".into(),
                    match &f.subject {
                        Some(s) => JsonValue::Str(s.clone()),
                        None => JsonValue::Null,
                    },
                ),
            ])
        })
        .collect();
    let summary = JsonValue::Object(vec![
        ("critical".into(), JsonValue::Number(c as f64)),
        ("high".into(), JsonValue::Number(h as f64)),
        ("medium".into(), JsonValue::Number(m as f64)),
        ("low".into(), JsonValue::Number(l as f64)),
        ("info".into(), JsonValue::Number(i as f64)),
    ]);
    to_json_string(&JsonValue::Object(vec![
        ("findings".into(), JsonValue::Array(findings_json)),
        ("summary".into(), summary),
    ]))
}

fn print_human(r: &AuditReport) {
    println!("vetpkg CI Audit Report");
    println!("══════════════════════");
    println!();
    if r.workflows.is_empty() {
        println!("no workflow files found");
        return;
    }
    for f in &r.findings {
        println!(
            "{:<8}  {}:{}",
            f.severity.label(),
            f.file,
            if f.line == 0 {
                "?".into()
            } else {
                f.line.to_string()
            }
        );
        println!("  {}", f.message);
        if let Some(s) = &f.subject {
            println!("  → {s}");
        }
        println!();
    }
    let (c, h, m, l, i) = counts(&r.findings);
    println!("Summary: {c} critical, {h} high, {m} medium, {l} low, {i} info");
}

fn counts(findings: &[Finding]) -> (usize, usize, usize, usize, usize) {
    let mut c = 0;
    let mut h = 0;
    let mut m = 0;
    let mut l = 0;
    let mut i = 0;
    for f in findings {
        match f.severity {
            Severity::Critical => c += 1,
            Severity::High => h += 1,
            Severity::Medium => m += 1,
            Severity::Low => l += 1,
            Severity::Info => i += 1,
        }
    }
    (c, h, m, l, i)
}

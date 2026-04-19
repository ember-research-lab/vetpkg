//! `vetpkg audit-ci` — audit GitHub Actions workflows for supply-chain
//! defensibility. Offline checks (unpinned actions, permission scoping,
//! secret exposure) always run. `--online` additionally fetches each
//! tag-pinned action's current commit SHA from the GitHub REST API and
//! compares against a local cache in `{config_dir}/cache/ci_cache.json`;
//! a mismatch emits a Critical finding.

use crate::ci::actions::{classify_ref, scan_workflow, RefType};
use crate::ci::pin_check::{self, PinCheckEntry, GITHUB_API_DEFAULT};
use crate::ci::{Check, Finding, Severity};
use crate::json::{parse, to_json_string, JsonValue};
use crate::platform;
use crate::yaml::{parse_yaml, YamlValue};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub struct AuditOptions {
    pub path: PathBuf,
    pub online: bool,
    pub strict: bool,
    pub as_json: bool,
    pub github_api_base: Option<String>,
    pub cache_path: Option<PathBuf>,
}

impl Default for AuditOptions {
    fn default() -> Self {
        Self {
            path: PathBuf::from("."),
            online: false,
            strict: false,
            as_json: false,
            github_api_base: None,
            cache_path: None,
        }
    }
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
        github_api_base: None,
        cache_path: None,
    })
}

pub fn audit(opts: &AuditOptions) -> Result<AuditReport, String> {
    let workflows = find_workflows(&opts.path)?;
    let mut findings: Vec<Finding> = Vec::new();
    let mut parsed_workflows: Vec<(String, YamlValue)> = Vec::new();
    for wf in &workflows {
        let text = fs::read_to_string(wf).map_err(|e| format!("read {:?}: {e}", wf))?;
        let parsed = match parse_yaml(&text) {
            Ok(v) => v,
            Err(e) => {
                findings.push(Finding {
                    severity: Severity::Medium,
                    file: wf.to_string_lossy().into_owned(),
                    line: 0,
                    check: Check::PermissionScope,
                    message: format!("YAML parse error: {e}"),
                    subject: None,
                });
                continue;
            }
        };
        let wf_label = wf.to_string_lossy().into_owned();
        findings.extend(scan_workflow(&wf_label, &parsed));
        parsed_workflows.push((wf_label, parsed));
    }

    if opts.online {
        findings.extend(run_online_tag_checks(opts, &parsed_workflows));
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

fn run_online_tag_checks(opts: &AuditOptions, parsed: &[(String, YamlValue)]) -> Vec<Finding> {
    let api_base = opts
        .github_api_base
        .clone()
        .unwrap_or_else(|| GITHUB_API_DEFAULT.to_string());
    let cache_path = opts
        .cache_path
        .clone()
        .unwrap_or_else(|| platform::cache_dir().join("ci_cache.json"));
    let mut cache = load_pin_cache(&cache_path);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let mut findings: Vec<Finding> = Vec::new();
    for (file, root) in parsed {
        for (job_uses, _job) in iter_job_action_refs(root) {
            let (rt, target, reference) = classify_ref(&job_uses);
            if !matches!(rt, RefType::Tag) {
                continue;
            }
            let Some((owner, repo)) = pin_check::split_owner_repo(target) else {
                continue;
            };
            let cache_key = format!("{owner}/{repo}@{reference}");

            let current_sha = match pin_check::resolve_tag_sha(&api_base, &owner, &repo, reference)
            {
                Ok(sha) => sha,
                Err(e) => {
                    findings.push(Finding {
                        severity: Severity::Low,
                        file: file.clone(),
                        line: 0,
                        check: Check::TagMutation,
                        message: format!("online check failed for {cache_key}: {e}"),
                        subject: Some(job_uses.clone()),
                    });
                    continue;
                }
            };

            match cache.get(&cache_key) {
                None => {
                    findings.push(Finding {
                        severity: Severity::Info,
                        file: file.clone(),
                        line: 0,
                        check: Check::TagMutation,
                        message: format!(
                            "{cache_key}: baseline established (first scan — no prior reference)"
                        ),
                        subject: Some(job_uses.clone()),
                    });
                    cache.insert(
                        cache_key.clone(),
                        PinCheckEntry {
                            action: format!("{owner}/{repo}"),
                            tag: reference.to_string(),
                            sha: current_sha.clone(),
                            checked_at: now,
                        },
                    );
                }
                Some(prev) => {
                    if prev.sha != current_sha {
                        findings.push(Finding {
                            severity: Severity::Critical,
                            file: file.clone(),
                            line: 0,
                            check: Check::TagMutation,
                            message: format!(
                                "{cache_key}: upstream SHA {} differs from cached {}; tag may have been hijacked",
                                &current_sha[..8.min(current_sha.len())],
                                &prev.sha[..8.min(prev.sha.len())]
                            ),
                            subject: Some(job_uses.clone()),
                        });
                    } else {
                        let days = now.saturating_sub(prev.checked_at) / 86400;
                        findings.push(Finding {
                            severity: Severity::Info,
                            file: file.clone(),
                            line: 0,
                            check: Check::TagMutation,
                            message: format!(
                                "{cache_key}: baseline verified against scan from {days}d ago"
                            ),
                            subject: Some(job_uses.clone()),
                        });
                    }
                    cache.insert(
                        cache_key.clone(),
                        PinCheckEntry {
                            action: prev.action.clone(),
                            tag: prev.tag.clone(),
                            sha: current_sha,
                            checked_at: now,
                        },
                    );
                }
            }
        }
    }
    let _ = save_pin_cache(&cache_path, &cache);
    findings
}

fn iter_job_action_refs(root: &YamlValue) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    let Some(jobs) = root.get("jobs").and_then(|v| v.as_map()) else {
        return out;
    };
    for (job_name, job) in jobs {
        if let Some(steps) = job.get("steps").and_then(|v| v.as_list()) {
            for step in steps {
                if let Some(uses) = step.get("uses").and_then(|v| v.as_str()) {
                    out.push((uses.to_string(), job_name.clone()));
                }
            }
        }
        if let Some(uses) = job.get("uses").and_then(|v| v.as_str()) {
            out.push((uses.to_string(), job_name.clone()));
        }
    }
    out
}

fn load_pin_cache(path: &Path) -> HashMap<String, PinCheckEntry> {
    let Ok(text) = fs::read_to_string(path) else {
        return HashMap::new();
    };
    let Ok(v) = parse(&text) else {
        return HashMap::new();
    };
    let Some(obj) = v.as_object() else {
        return HashMap::new();
    };
    let mut out = HashMap::new();
    for (k, entry) in obj {
        let action = entry
            .get("action")
            .and_then(|s| s.as_str())
            .unwrap_or("")
            .to_string();
        let tag = entry
            .get("tag")
            .and_then(|s| s.as_str())
            .unwrap_or("")
            .to_string();
        let sha = entry
            .get("sha")
            .and_then(|s| s.as_str())
            .unwrap_or("")
            .to_string();
        let checked_at = entry
            .get("checked_at")
            .and_then(|n| n.as_f64())
            .unwrap_or(0.0) as u64;
        if sha.is_empty() {
            continue;
        }
        out.insert(
            k.clone(),
            PinCheckEntry {
                action,
                tag,
                sha,
                checked_at,
            },
        );
    }
    out
}

fn save_pin_cache(path: &Path, cache: &HashMap<String, PinCheckEntry>) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|e| format!("mkdir {:?}: {e}", parent))?;
        }
    }
    let mut pairs: Vec<(String, JsonValue)> = Vec::with_capacity(cache.len());
    for (k, entry) in cache {
        pairs.push((
            k.clone(),
            JsonValue::Object(vec![
                ("action".into(), JsonValue::Str(entry.action.clone())),
                ("tag".into(), JsonValue::Str(entry.tag.clone())),
                ("sha".into(), JsonValue::Str(entry.sha.clone())),
                (
                    "checked_at".into(),
                    JsonValue::Number(entry.checked_at as f64),
                ),
            ]),
        ));
    }
    pairs.sort_by(|a, b| a.0.cmp(&b.0));
    let json = to_json_string(&JsonValue::Object(pairs));
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, json).map_err(|e| format!("write {:?}: {e}", tmp))?;
    fs::rename(&tmp, path).map_err(|e| format!("rename {:?}: {e}", tmp))?;
    Ok(())
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

//! `vetpkg audit` — lockfile audit subcommand.
//!
//! Scope without `--full`: score each resolved (name, version) from
//! `package-lock.json` using signals that work from lockfile data alone
//! (primarily Typosquat; advisory and fresh-package if metadata is provided).
//! This intentionally does no network I/O so it runs safely in CI and on air-
//! gapped hosts.
//!
//! Scope with `--full`: parallel upstream metadata fetch (10-thread pool)
//! and full signal battery. That code path arrives with the upstream-fetch
//! layer and is stubbed with a clear error today.

use crate::engine::SecurityEngine;
use crate::json::{parse, JsonValue};
use crate::types::{Ecosystem, PackageIntel, PolicyConfig, Signal, Verdict};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

pub struct AuditOptions {
    pub path: PathBuf,
    pub full: bool,
    pub as_json: bool,
    pub fail_on_warn: bool,
}

#[derive(Debug, Clone)]
pub struct AuditFinding {
    pub name: String,
    pub version: String,
    pub score: f64,
    pub verdict: Verdict,
    pub signals: Vec<Signal>,
}

#[derive(Debug, Clone)]
pub struct AuditReport {
    pub lockfile_path: PathBuf,
    pub lockfile_version: u64,
    pub package_count: usize,
    pub findings: Vec<AuditFinding>,
    pub elapsed_ms: u128,
}

impl AuditReport {
    pub fn counts(&self) -> (usize, usize, usize) {
        let mut b = 0;
        let mut w = 0;
        let mut a = 0;
        for f in &self.findings {
            match f.verdict {
                Verdict::Block => b += 1,
                Verdict::Warn => w += 1,
                Verdict::Allow => a += 1,
            }
        }
        (b, w, a)
    }
}

pub fn run(args: Vec<String>) -> Result<u8, String> {
    let opts = parse_args(&args)?;
    let report = audit(&opts)?;
    if opts.as_json {
        println!("{}", report_as_json(&report));
    } else {
        print_human(&report);
    }
    let (blocks, warns, _) = report.counts();
    if blocks > 0 {
        return Ok(1);
    }
    if warns > 0 && opts.fail_on_warn {
        return Ok(1);
    }
    Ok(0)
}

fn parse_args(args: &[String]) -> Result<AuditOptions, String> {
    let mut path = PathBuf::from(".");
    let mut full = false;
    let mut as_json = false;
    let mut fail_on_warn = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--path" => {
                i += 1;
                path = PathBuf::from(args.get(i).ok_or("--path requires a value")?);
            }
            "--full" => full = true,
            "--json" => as_json = true,
            "--fail-on-warn" => fail_on_warn = true,
            other => return Err(format!("unknown audit flag: {other}")),
        }
        i += 1;
    }
    Ok(AuditOptions {
        path,
        full,
        as_json,
        fail_on_warn,
    })
}

pub fn audit(opts: &AuditOptions) -> Result<AuditReport, String> {
    if opts.full {
        return Err("audit --full requires upstream fetching (not yet wired; coming in Phase 1 integration)".into());
    }
    let lockfile_path = resolve_lockfile(&opts.path)?;
    let text =
        fs::read_to_string(&lockfile_path).map_err(|e| format!("read {:?}: {e}", lockfile_path))?;
    let root = parse(&text).map_err(|e| format!("parse {:?}: {e}", lockfile_path))?;
    let lockfile_version = detect_lockfile_version(&root)?;

    let entries = extract_entries(&root, lockfile_version)?;

    let engine = SecurityEngine::new(PolicyConfig::default());
    let start = Instant::now();
    let mut findings: Vec<AuditFinding> = Vec::with_capacity(entries.len());

    // Lockfile-tampering sweep: collate resolved-URL mismatches by package
    // name so we can merge them into the per-package scoring below.
    let npm_upstream = PolicyConfig::default().npm_upstream;
    let expected_host = npm_upstream
        .strip_prefix("https://")
        .or_else(|| npm_upstream.strip_prefix("http://"))
        .map(|s| s.trim_end_matches('/').to_string())
        .unwrap_or_else(|| "registry.npmjs.org".to_string());
    let resolved_signals = check_resolved_urls(&root, &expected_host);
    let mut resolved_by_name: std::collections::HashMap<String, Vec<Signal>> =
        std::collections::HashMap::new();
    for s in resolved_signals {
        if let Signal::ResolvedUrlMismatch { name, .. } = &s {
            resolved_by_name.entry(name.clone()).or_default().push(s);
        }
    }

    for (name, version) in &entries {
        let intel = intel_from_lockfile(name, version);
        let mut score = engine.score(&intel);
        if let Some(extra) = resolved_by_name.remove(name) {
            let extra_weight: f64 = extra.iter().map(|s| s.weight()).sum();
            score.score = (score.score + extra_weight).min(1.0);
            score.signals.extend(extra);
        }
        let verdict = engine.verdict(score.score);
        findings.push(AuditFinding {
            name: name.clone(),
            version: version.clone(),
            score: score.score,
            verdict,
            signals: score.signals,
        });
    }
    findings.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.name.cmp(&b.name))
    });
    let elapsed_ms = start.elapsed().as_millis();

    Ok(AuditReport {
        lockfile_path,
        lockfile_version,
        package_count: entries.len(),
        findings,
        elapsed_ms,
    })
}

fn resolve_lockfile(path: &Path) -> Result<PathBuf, String> {
    if path.is_file() {
        return Ok(path.to_path_buf());
    }
    let direct = path.join("package-lock.json");
    if direct.is_file() {
        return Ok(direct);
    }
    Err(format!(
        "no package-lock.json at {:?} (pass --path pointing to a project root or the lockfile itself)",
        path
    ))
}

fn detect_lockfile_version(root: &JsonValue) -> Result<u64, String> {
    let v = root
        .get("lockfileVersion")
        .and_then(|n| n.as_f64())
        .ok_or_else(|| "package-lock.json missing lockfileVersion".to_string())?;
    let v = v as u64;
    match v {
        1 => Err(
            "package-lock.json v1 is not supported (upgrade project with `npm install` on npm 7+)"
                .to_string(),
        ),
        2 | 3 => Ok(v),
        other => Err(format!("unsupported lockfileVersion {other}")),
    }
}

fn extract_entries(
    root: &JsonValue,
    _lockfile_version: u64,
) -> Result<Vec<(String, String)>, String> {
    let packages = root
        .get("packages")
        .and_then(|p| p.as_object())
        .ok_or_else(|| "lockfile missing 'packages' map".to_string())?;

    let mut seen: BTreeMap<(String, String), ()> = BTreeMap::new();
    for (path, entry) in packages {
        if path.is_empty() {
            continue;
        }
        let name = match entry.get("name").and_then(|n| n.as_str()) {
            Some(s) => s.to_string(),
            None => match extract_name_from_path(path) {
                Some(s) => s,
                None => continue,
            },
        };
        let Some(version) = entry.get("version").and_then(|v| v.as_str()) else {
            continue;
        };
        seen.insert((name, version.to_string()), ());
    }
    Ok(seen.into_keys().collect())
}

/// Scan every lockfile entry's `resolved` URL against the expected
/// registry host. Any entry whose URL points outside that host is a
/// possible lockfile-tampering attempt (attacker replaces the resolved
/// URL to point at a malicious mirror while keeping the name+version).
pub fn check_resolved_urls(root: &JsonValue, expected_host: &str) -> Vec<Signal> {
    let mut out = Vec::new();
    let Some(packages) = root.get("packages").and_then(|p| p.as_object()) else {
        return out;
    };
    for (path, entry) in packages {
        if path.is_empty() {
            continue;
        }
        let Some(resolved) = entry.get("resolved").and_then(|v| v.as_str()) else {
            continue;
        };
        if !resolved_url_matches_host(resolved, expected_host) {
            let name = entry
                .get("name")
                .and_then(|n| n.as_str())
                .map(|s| s.to_string())
                .or_else(|| extract_name_from_path(path))
                .unwrap_or_default();
            out.push(Signal::ResolvedUrlMismatch {
                name,
                expected_registry: expected_host.to_string(),
                actual_url: resolved.to_string(),
            });
        }
    }
    out
}

fn resolved_url_matches_host(url: &str, expected_host: &str) -> bool {
    let rest = match url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
    {
        Some(r) => r,
        None => return false,
    };
    let host = rest.split('/').next().unwrap_or("");
    // npm's registry serves tarballs from registry.npmjs.org; accept the
    // configured host exactly, plus the conventional ecosystem mirrors.
    host == expected_host || host == format!("registry.{expected_host}")
}

pub fn extract_name_from_path(path: &str) -> Option<String> {
    let idx = path.rfind("node_modules/")?;
    let suffix = &path[idx + "node_modules/".len()..];
    if suffix.is_empty() {
        return None;
    }
    if let Some(rest) = suffix.strip_prefix('@') {
        let slash = rest.find('/')?;
        let end = rest[slash + 1..]
            .find('/')
            .map(|x| slash + 1 + x)
            .unwrap_or(rest.len());
        Some(format!("@{}", &rest[..end]))
    } else {
        let end = suffix.find('/').unwrap_or(suffix.len());
        Some(suffix[..end].to_string())
    }
}

fn intel_from_lockfile(name: &str, version: &str) -> PackageIntel {
    PackageIntel {
        ecosystem: Some(Ecosystem::Npm),
        name: name.to_string(),
        version: version.to_string(),
        ..Default::default()
    }
}

pub fn report_as_json(r: &AuditReport) -> String {
    let mut findings = Vec::with_capacity(r.findings.len());
    for f in &r.findings {
        // Field name: `package` matches the agent-monitor integration
        // contract (`ember-agent-monitor/src/integrate.rs`); `name` would
        // silently mismatch. Signal serialization uses the structured
        // `signal_short_label` rather than `{:?}` Debug, which is unstable
        // across releases and not valid JSON-friendly output.
        findings.push(JsonValue::Object(vec![
            ("package".into(), JsonValue::Str(f.name.clone())),
            ("version".into(), JsonValue::Str(f.version.clone())),
            ("score".into(), JsonValue::Number(f.score)),
            (
                "verdict".into(),
                JsonValue::Str(verdict_str(f.verdict).into()),
            ),
            (
                "signals".into(),
                JsonValue::Array(
                    f.signals
                        .iter()
                        .map(|s| JsonValue::Str(crate::engine::orchestrator::signal_short_label(s)))
                        .collect(),
                ),
            ),
        ]));
    }
    let (b, w, a) = r.counts();
    let root = JsonValue::Object(vec![
        (
            "lockfile".into(),
            JsonValue::Str(r.lockfile_path.to_string_lossy().into_owned()),
        ),
        (
            "lockfile_version".into(),
            JsonValue::Number(r.lockfile_version as f64),
        ),
        (
            "package_count".into(),
            JsonValue::Number(r.package_count as f64),
        ),
        ("elapsed_ms".into(), JsonValue::Number(r.elapsed_ms as f64)),
        (
            "summary".into(),
            JsonValue::Object(vec![
                ("block".into(), JsonValue::Number(b as f64)),
                ("warn".into(), JsonValue::Number(w as f64)),
                ("allow".into(), JsonValue::Number(a as f64)),
            ]),
        ),
        ("findings".into(), JsonValue::Array(findings)),
    ]);
    crate::json::to_json_string(&root)
}

fn print_human(r: &AuditReport) {
    println!("vetpkg Lockfile Audit");
    println!("═════════════════════");
    println!();
    println!(
        "lockfile  : {} (v{})",
        r.lockfile_path.display(),
        r.lockfile_version
    );
    println!("packages  : {}", r.package_count);
    println!("elapsed   : {} ms", r.elapsed_ms);
    println!();
    let (b, w, _a) = r.counts();
    let mut shown = 0;
    for f in &r.findings {
        if !matches!(f.verdict, Verdict::Block | Verdict::Warn) {
            continue;
        }
        let tag = match f.verdict {
            Verdict::Block => "BLOCK",
            Verdict::Warn => "WARN ",
            Verdict::Allow => "OK   ",
        };
        println!("{}  {}@{}  score={:.2}", tag, f.name, f.version, f.score);
        for s in &f.signals {
            println!("        {:?}", s);
        }
        shown += 1;
    }
    if shown == 0 {
        println!("no warnings or blocks");
    }
    println!();
    println!(
        "Summary: {} blocked, {} warnings, {} clean",
        b,
        w,
        r.package_count.saturating_sub(b + w)
    );
}

fn verdict_str(v: Verdict) -> &'static str {
    match v {
        Verdict::Block => "block",
        Verdict::Warn => "warn",
        Verdict::Allow => "allow",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_names_from_nm_paths() {
        assert_eq!(
            extract_name_from_path("node_modules/express"),
            Some("express".into())
        );
        assert_eq!(
            extract_name_from_path("node_modules/@vercel/next"),
            Some("@vercel/next".into())
        );
        assert_eq!(
            extract_name_from_path("node_modules/a/node_modules/b"),
            Some("b".into())
        );
        assert_eq!(
            extract_name_from_path("node_modules/a/node_modules/@scope/c"),
            Some("@scope/c".into())
        );
    }

    #[test]
    fn rejects_v1_lockfile() {
        let txt = r#"{"name":"x","version":"1.0.0","lockfileVersion":1}"#;
        let root = parse(txt).unwrap();
        let err = detect_lockfile_version(&root).unwrap_err();
        assert!(err.contains("v1"));
    }

    #[test]
    fn accepts_v2_and_v3() {
        for v in [2u64, 3u64] {
            let txt = format!(r#"{{"lockfileVersion":{}}}"#, v);
            let root = parse(&txt).unwrap();
            assert_eq!(detect_lockfile_version(&root).unwrap(), v);
        }
    }

    #[test]
    fn full_returns_clear_error_until_implemented() {
        let opts = AuditOptions {
            path: PathBuf::from("."),
            full: true,
            as_json: false,
            fail_on_warn: false,
        };
        let err = audit(&opts).unwrap_err();
        assert!(err.contains("--full"));
    }

    #[test]
    fn resolved_url_mismatch_flags_tampering() {
        let lock = parse(
            r#"{
            "packages": {
                "node_modules/express": {
                    "version": "4.18.2",
                    "resolved": "https://evil.mirror.example/express/-/express-4.18.2.tgz"
                },
                "node_modules/lodash": {
                    "version": "4.17.21",
                    "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"
                }
            }
        }"#,
        )
        .unwrap();
        let signals = check_resolved_urls(&lock, "registry.npmjs.org");
        assert_eq!(signals.len(), 1);
        assert!(matches!(
            &signals[0],
            Signal::ResolvedUrlMismatch { name, .. } if name == "express"
        ));
    }

    #[test]
    fn clean_lockfile_urls_no_signal() {
        let lock = parse(
            r#"{"packages":{"node_modules/x":{"version":"1.0.0","resolved":"https://registry.npmjs.org/x/-/x-1.0.0.tgz"}}}"#,
        )
        .unwrap();
        assert!(check_resolved_urls(&lock, "registry.npmjs.org").is_empty());
    }
}

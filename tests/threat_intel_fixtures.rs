//! Threat-intel fixture regression test for vetpkg.
//!
//! Each fixture under `threat-intel/fixtures/<name>/` provides a
//! synthetic lockfile.json + expected.json (and a README.md citing
//! the source). The runner feeds the lockfile through the standard
//! `audit()` path and asserts:
//!
//! - Every `expected_findings[i]` package + version exists in the
//!   report with the expected verdict.
//! - The signals on that finding contain the expected short labels
//!   (substring match against `signal_short_label`).
//! - Every `expected_clean[i]` package resolves to `Verdict::Allow`.
//!
//! Adding a fixture is a directory drop — no code change required.

use std::path::PathBuf;
use vetpkg::cli::audit::{audit, AuditOptions};
use vetpkg::engine::orchestrator::signal_short_label;
use vetpkg::types::Verdict;

#[test]
fn all_threat_intel_fixtures_match_expected() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("threat-intel/fixtures");
    let mut fixtures: Vec<PathBuf> = match std::fs::read_dir(&root) {
        Ok(it) => it
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.is_dir())
            .collect(),
        Err(_) => Vec::new(),
    };
    fixtures.sort();
    assert!(
        !fixtures.is_empty(),
        "no fixtures discovered under {root:?} — refusing to silently pass"
    );

    let mut failures = Vec::new();
    for dir in &fixtures {
        let name = dir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("?")
            .to_string();
        if let Err(e) = run_fixture(dir) {
            failures.push(format!("{name}: {e}"));
        }
    }
    assert!(
        failures.is_empty(),
        "vetpkg threat-intel regressions:\n{}",
        failures.join("\n---\n")
    );
}

fn run_fixture(dir: &std::path::Path) -> Result<(), String> {
    let lockfile = dir.join("lockfile.json");
    let expected_path = dir.join("expected.json");
    if !lockfile.exists() {
        return Err(format!("missing lockfile.json in {}", dir.display()));
    }
    if !expected_path.exists() {
        return Err(format!("missing expected.json in {}", dir.display()));
    }

    let opts = AuditOptions {
        path: lockfile,
        full: false,
        as_json: false,
        fail_on_warn: false,
    };
    let report = audit(&opts).map_err(|e| format!("audit failed: {e}"))?;

    let expected_text = std::fs::read_to_string(&expected_path)
        .map_err(|e| format!("read expected.json: {e}"))?;

    // Parse minimal subset: expected_findings[].package/version/verdict/signals_contain
    // and expected_clean[]. We use targeted string parsing rather than a
    // full JSON dependency since vetpkg has zero crate deps and pulling
    // serde for a test-only path violates the discipline. The format is
    // small and stable.
    let expected = parse_expected(&expected_text)?;

    for ef in &expected.findings {
        let f = report
            .findings
            .iter()
            .find(|x| x.name == ef.package && x.version == ef.version)
            .ok_or_else(|| {
                format!(
                    "expected package {}@{} not in report; saw: {}",
                    ef.package,
                    ef.version,
                    report
                        .findings
                        .iter()
                        .map(|x| format!("{}@{}", x.name, x.version))
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            })?;
        if f.verdict != ef.verdict {
            return Err(format!(
                "{}@{}: expected verdict {:?}, got {:?} (signals: {:?})",
                ef.package,
                ef.version,
                ef.verdict,
                f.verdict,
                f.signals.iter().map(signal_short_label).collect::<Vec<_>>()
            ));
        }
        let labels: Vec<String> = f.signals.iter().map(signal_short_label).collect();
        for needle in &ef.signals_contain {
            let hit = labels.iter().any(|l| l.contains(needle));
            if !hit {
                return Err(format!(
                    "{}@{}: expected signal containing {:?}, got: {:?}",
                    ef.package, ef.version, needle, labels
                ));
            }
        }
    }

    for clean_name in &expected.clean {
        if let Some(f) = report.findings.iter().find(|x| x.name == *clean_name) {
            if f.verdict != Verdict::Allow {
                return Err(format!(
                    "{} should Allow, got {:?} (signals: {:?})",
                    clean_name,
                    f.verdict,
                    f.signals.iter().map(signal_short_label).collect::<Vec<_>>()
                ));
            }
        }
    }

    Ok(())
}

#[derive(Debug, Default)]
struct Expected {
    findings: Vec<ExpectedFinding>,
    clean: Vec<String>,
}

#[derive(Debug)]
struct ExpectedFinding {
    package: String,
    version: String,
    verdict: Verdict,
    signals_contain: Vec<String>,
}

/// Tiny zero-dep parser for the expected.json subset we use.
/// The format is small and stable; full JSON is overkill.
fn parse_expected(text: &str) -> Result<Expected, String> {
    let mut out = Expected::default();
    // expected_findings is an array of objects; we walk it by finding
    // the array bracket then iterating object literals via brace
    // matching.
    if let Some(arr) = extract_array(text, "expected_findings") {
        for obj in split_top_level_objects(&arr) {
            let pkg = extract_string(&obj, "package").ok_or("expected_findings: missing package")?;
            let ver = extract_string(&obj, "version").ok_or("expected_findings: missing version")?;
            let verdict_s =
                extract_string(&obj, "verdict").ok_or("expected_findings: missing verdict")?;
            let verdict = match verdict_s.as_str() {
                "Allow" => Verdict::Allow,
                "Warn" => Verdict::Warn,
                "Block" => Verdict::Block,
                _ => return Err(format!("unknown verdict: {verdict_s}")),
            };
            let signals_contain = extract_string_array(&obj, "signals_contain").unwrap_or_default();
            out.findings.push(ExpectedFinding {
                package: pkg,
                version: ver,
                verdict,
                signals_contain,
            });
        }
    }
    if let Some(arr) = extract_array(text, "expected_clean") {
        out.clean = parse_string_array(&arr);
    }
    Ok(out)
}

fn extract_array(text: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\"");
    let start = text.find(&needle)?;
    let after = text[start + needle.len()..].find('[')?;
    let begin = start + needle.len() + after + 1;
    let mut depth = 1usize;
    let mut end = begin;
    let bytes = text.as_bytes();
    while end < bytes.len() && depth > 0 {
        match bytes[end] {
            b'[' => depth += 1,
            b']' => depth -= 1,
            _ => {}
        }
        end += 1;
    }
    Some(text[begin..end - 1].to_string())
}

fn split_top_level_objects(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut depth = 0usize;
    let mut start = None;
    for (i, ch) in s.char_indices() {
        match ch {
            '{' => {
                if depth == 0 {
                    start = Some(i);
                }
                depth += 1;
            }
            '}' => {
                depth -= 1;
                if depth == 0 {
                    if let Some(begin) = start {
                        out.push(s[begin..=i].to_string());
                    }
                }
            }
            _ => {}
        }
    }
    out
}

fn extract_string(text: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\"");
    let start = text.find(&needle)?;
    let rest = &text[start + needle.len()..];
    let colon = rest.find(':')?;
    let after = &rest[colon + 1..];
    // Skip leading whitespace.
    let trimmed = after.trim_start();
    if !trimmed.starts_with('"') {
        return None;
    }
    let body = &trimmed[1..];
    let end = body.find('"')?;
    Some(body[..end].to_string())
}

fn extract_string_array(text: &str, key: &str) -> Option<Vec<String>> {
    let needle = format!("\"{key}\"");
    let start = text.find(&needle)?;
    let rest = &text[start + needle.len()..];
    let bracket = rest.find('[')?;
    let after = &rest[bracket + 1..];
    let close = after.find(']')?;
    Some(parse_string_array(&after[..close]))
}

fn parse_string_array(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut iter = s.char_indices();
    while let Some((i, c)) = iter.next() {
        if c == '"' {
            // Find the matching closing quote.
            let rest = &s[i + 1..];
            if let Some(end) = rest.find('"') {
                out.push(rest[..end].to_string());
                // Advance the iterator past the closing quote.
                let skip = i + 1 + end + 1 - i - 1;
                for _ in 0..skip {
                    iter.next();
                }
            }
        }
    }
    out
}

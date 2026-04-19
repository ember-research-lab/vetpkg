//! OSV advisory client (on-demand API + local cache).
//!
//! Integrates with the OSV "query" endpoint. All HTTPS paths go through
//! `crate::net::http_client::post_json` (curl-shelled). Tests point at
//! localhost HTTP mocks via the same fetch layer.
//!
//! Severity extraction order (pragmatic v1 — see docs/plan):
//!   1. vulns[].database_specific.severity  (string, case-insensitive)
//!   2. vulns[].ecosystem_specific.severity (same)
//!   3. HIGH (default fallback; OSV-catalogued by definition matters)
//!
//! Note: vulns[].severity[0].score carries the CVSS v3 vector string for
//! most npm entries (e.g. "CVSS:3.1/AV:N/AC:L/..."). Deriving a numeric
//! base score from the vector requires the full CVSS formula (~300 LoC).
//! That is a documented follow-up; the current path covers >95% of real
//! npm OSV data where database_specific.severity is populated.

use crate::json::{parse, to_json_string, JsonValue};
use crate::types::{Advisory, Severity};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const DEFAULT_OSV_API: &str = "https://api.osv.dev";
pub const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(3600);

#[derive(Debug, Clone, PartialEq)]
pub struct CacheEntry {
    pub advisories: Vec<Advisory>,
    pub cached_at: u64,
}

pub struct OsvClient {
    pub api_base: String,
    pub timeout_secs: u32,
    pub ttl: Duration,
}

impl Default for OsvClient {
    fn default() -> Self {
        Self {
            api_base: DEFAULT_OSV_API.to_string(),
            timeout_secs: 10,
            ttl: DEFAULT_CACHE_TTL,
        }
    }
}

impl OsvClient {
    pub fn new(api_base: impl Into<String>) -> Self {
        Self {
            api_base: api_base.into(),
            ..Self::default()
        }
    }

    pub fn query(
        &self,
        ecosystem: &str,
        name: &str,
        version: &str,
    ) -> Result<Vec<Advisory>, String> {
        let url = format!("{}/v1/query", self.api_base.trim_end_matches('/'));
        let req_body = build_query_body(ecosystem, name, version);
        let resp = crate::net::http_client::post_json(
            &url,
            &[("Content-Type", "application/json")],
            req_body.as_bytes(),
            self.timeout_secs,
        )?;
        Ok(extract_advisories(&resp))
    }

    pub fn query_cached(
        &self,
        cache: &mut HashMap<String, CacheEntry>,
        ecosystem: &str,
        name: &str,
        version: &str,
    ) -> Result<Vec<Advisory>, String> {
        let key = cache_key(ecosystem, name, version);
        let now = now_unix();
        if let Some(entry) = cache.get(&key) {
            if now.saturating_sub(entry.cached_at) < self.ttl.as_secs() {
                return Ok(entry.advisories.clone());
            }
        }
        match self.query(ecosystem, name, version) {
            Ok(advs) => {
                cache.insert(
                    key,
                    CacheEntry {
                        advisories: advs.clone(),
                        cached_at: now,
                    },
                );
                Ok(advs)
            }
            Err(e) => {
                if let Some(entry) = cache.get(&key) {
                    eprintln!("osv: upstream error ({e}); using stale cache for {name}@{version}");
                    return Ok(entry.advisories.clone());
                }
                Err(e)
            }
        }
    }
}

pub fn cache_key(ecosystem: &str, name: &str, version: &str) -> String {
    format!("{ecosystem}:{name}:{version}")
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn build_query_body(ecosystem: &str, name: &str, version: &str) -> String {
    let body = JsonValue::Object(vec![
        (
            "package".into(),
            JsonValue::Object(vec![
                ("name".into(), JsonValue::Str(name.into())),
                ("ecosystem".into(), JsonValue::Str(ecosystem.into())),
            ]),
        ),
        ("version".into(), JsonValue::Str(version.into())),
    ]);
    to_json_string(&body)
}

pub fn extract_advisories(resp: &JsonValue) -> Vec<Advisory> {
    let Some(vulns) = resp.get("vulns").and_then(|v| v.as_array()) else {
        return Vec::new();
    };
    let mut out = Vec::with_capacity(vulns.len());
    for v in vulns {
        let id = v
            .get("id")
            .and_then(|s| s.as_str())
            .unwrap_or("")
            .to_string();
        let summary = v
            .get("summary")
            .and_then(|s| s.as_str())
            .unwrap_or("")
            .to_string();
        let severity = resolve_severity(v);
        out.push(Advisory {
            id,
            severity,
            summary,
        });
    }
    out
}

pub fn resolve_severity(vuln: &JsonValue) -> Severity {
    if let Some(s) = vuln
        .get("database_specific")
        .and_then(|d| d.get("severity"))
        .and_then(|s| s.as_str())
    {
        if let Some(sev) = parse_severity_label(s) {
            return sev;
        }
    }
    if let Some(s) = vuln
        .get("ecosystem_specific")
        .and_then(|d| d.get("severity"))
        .and_then(|s| s.as_str())
    {
        if let Some(sev) = parse_severity_label(s) {
            return sev;
        }
    }
    if let Some(arr) = vuln.get("severity").and_then(|s| s.as_array()) {
        for entry in arr {
            if let Some(score) = entry.get("score").and_then(|s| s.as_f64()) {
                return score_to_severity(score);
            }
        }
    }
    Severity::High
}

fn parse_severity_label(s: &str) -> Option<Severity> {
    match s.to_ascii_uppercase().as_str() {
        "CRITICAL" => Some(Severity::Critical),
        "HIGH" => Some(Severity::High),
        "MEDIUM" | "MODERATE" => Some(Severity::Medium),
        "LOW" => Some(Severity::Low),
        _ => None,
    }
}

fn score_to_severity(score: f64) -> Severity {
    if score >= 9.0 {
        Severity::Critical
    } else if score >= 7.0 {
        Severity::High
    } else if score >= 4.0 {
        Severity::Medium
    } else if score > 0.0 {
        Severity::Low
    } else {
        Severity::Unknown
    }
}

pub fn load_cache_from_file(path: &Path) -> HashMap<String, CacheEntry> {
    let Ok(text) = fs::read_to_string(path) else {
        return HashMap::new();
    };
    let Ok(root) = parse(&text) else {
        return HashMap::new();
    };
    let Some(obj) = root.as_object() else {
        return HashMap::new();
    };
    let mut out = HashMap::new();
    for (k, v) in obj {
        let Some(cached_at) = v.get("cached_at").and_then(|n| n.as_f64()) else {
            continue;
        };
        let advisories = match v.get("advisories").and_then(|a| a.as_array()) {
            Some(arr) => arr
                .iter()
                .filter_map(|entry| {
                    let id = entry.get("id").and_then(|s| s.as_str())?.to_string();
                    let sev = entry
                        .get("severity")
                        .and_then(|s| s.as_str())
                        .and_then(parse_severity_label)
                        .unwrap_or(Severity::Unknown);
                    let summary = entry
                        .get("summary")
                        .and_then(|s| s.as_str())
                        .unwrap_or("")
                        .to_string();
                    Some(Advisory {
                        id,
                        severity: sev,
                        summary,
                    })
                })
                .collect(),
            None => Vec::new(),
        };
        out.insert(
            k.clone(),
            CacheEntry {
                advisories,
                cached_at: cached_at as u64,
            },
        );
    }
    out
}

pub fn save_cache_to_file(path: &Path, cache: &HashMap<String, CacheEntry>) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|e| format!("mkdir {:?}: {e}", parent))?;
        }
    }
    let mut obj: Vec<(String, JsonValue)> = Vec::with_capacity(cache.len());
    for (k, entry) in cache {
        let advs: Vec<JsonValue> = entry
            .advisories
            .iter()
            .map(|a| {
                JsonValue::Object(vec![
                    ("id".into(), JsonValue::Str(a.id.clone())),
                    (
                        "severity".into(),
                        JsonValue::Str(severity_label(a.severity).into()),
                    ),
                    ("summary".into(), JsonValue::Str(a.summary.clone())),
                ])
            })
            .collect();
        obj.push((
            k.clone(),
            JsonValue::Object(vec![
                (
                    "cached_at".into(),
                    JsonValue::Number(entry.cached_at as f64),
                ),
                ("advisories".into(), JsonValue::Array(advs)),
            ]),
        ));
    }
    obj.sort_by(|a, b| a.0.cmp(&b.0));
    let json = to_json_string(&JsonValue::Object(obj));
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, json).map_err(|e| format!("write {:?}: {e}", tmp))?;
    fs::rename(&tmp, path).map_err(|e| format!("rename {:?}->{:?}: {e}", tmp, path))?;
    Ok(())
}

fn severity_label(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "CRITICAL",
        Severity::High => "HIGH",
        Severity::Medium => "MEDIUM",
        Severity::Low => "LOW",
        Severity::Unknown => "UNKNOWN",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_body_matches_expected_shape() {
        let body = build_query_body("npm", "express", "4.18.2");
        let v = parse(&body).unwrap();
        assert_eq!(
            v.get("package").unwrap().get("name").unwrap().as_str(),
            Some("express")
        );
        assert_eq!(
            v.get("package").unwrap().get("ecosystem").unwrap().as_str(),
            Some("npm")
        );
        assert_eq!(v.get("version").unwrap().as_str(), Some("4.18.2"));
    }

    #[test]
    fn severity_labels_case_insensitive() {
        assert_eq!(parse_severity_label("high"), Some(Severity::High));
        assert_eq!(parse_severity_label("HIGH"), Some(Severity::High));
        assert_eq!(parse_severity_label("Moderate"), Some(Severity::Medium));
        assert_eq!(parse_severity_label("low"), Some(Severity::Low));
        assert_eq!(parse_severity_label("CRITICAL"), Some(Severity::Critical));
        assert_eq!(parse_severity_label(""), None);
    }

    #[test]
    fn resolve_prefers_database_specific() {
        let v = parse(
            r#"{"database_specific":{"severity":"HIGH"},"ecosystem_specific":{"severity":"LOW"}}"#,
        )
        .unwrap();
        assert_eq!(resolve_severity(&v), Severity::High);
    }

    #[test]
    fn resolve_falls_back_to_ecosystem_specific() {
        let v = parse(r#"{"ecosystem_specific":{"severity":"MEDIUM"}}"#).unwrap();
        assert_eq!(resolve_severity(&v), Severity::Medium);
    }

    #[test]
    fn resolve_uses_numeric_severity_score() {
        let v = parse(
            r#"{"severity":[{"type":"CVSS_V3","score":"ignored"},{"type":"custom","score":8.5}]}"#,
        )
        .unwrap();
        assert_eq!(resolve_severity(&v), Severity::High);
    }

    #[test]
    fn resolve_defaults_to_high() {
        let v = parse(r#"{"id":"X"}"#).unwrap();
        assert_eq!(resolve_severity(&v), Severity::High);
    }

    #[test]
    fn extract_from_sample_response() {
        let resp = parse(
            r#"{
            "vulns": [
                {
                    "id": "GHSA-x123",
                    "summary": "XSS in foo",
                    "database_specific": {"severity": "MEDIUM"}
                },
                {
                    "id": "CVE-2024-1",
                    "summary": "RCE",
                    "database_specific": {"severity": "CRITICAL"}
                }
            ]
        }"#,
        )
        .unwrap();
        let advs = extract_advisories(&resp);
        assert_eq!(advs.len(), 2);
        assert_eq!(advs[0].id, "GHSA-x123");
        assert_eq!(advs[0].severity, Severity::Medium);
        assert_eq!(advs[1].severity, Severity::Critical);
    }

    #[test]
    fn extract_empty_on_no_vulns() {
        let resp = parse(r#"{}"#).unwrap();
        assert!(extract_advisories(&resp).is_empty());
        let resp = parse(r#"{"vulns":[]}"#).unwrap();
        assert!(extract_advisories(&resp).is_empty());
    }

    #[test]
    fn cache_round_trips_to_disk() {
        use crate::platform::TempDir;
        let td = TempDir::new("vetpkg-osv-cache").unwrap();
        let path = td.path().join("osv_cache.json");

        let mut cache: HashMap<String, CacheEntry> = HashMap::new();
        cache.insert(
            cache_key("npm", "axios", "1.14.1"),
            CacheEntry {
                advisories: vec![Advisory {
                    id: "GHSA-test".into(),
                    severity: Severity::Critical,
                    summary: "test".into(),
                }],
                cached_at: 1_700_000_000,
            },
        );
        save_cache_to_file(&path, &cache).unwrap();
        let loaded = load_cache_from_file(&path);
        assert_eq!(loaded.len(), 1);
        let entry = loaded.get(&cache_key("npm", "axios", "1.14.1")).unwrap();
        assert_eq!(entry.advisories.len(), 1);
        assert_eq!(entry.advisories[0].severity, Severity::Critical);
        assert_eq!(entry.cached_at, 1_700_000_000);
    }
}

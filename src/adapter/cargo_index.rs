//! Cargo sparse-index adapter (docs/plan resolution: proxy the sparse
//! index, NOT the api/v1 website endpoints). Modern cargo resolves via
//! sparse HTTP and downloads .crate tarballs from a CDN URL; api/v1 is
//! used only by the crates.io website and does not run during installs.
//!
//! Index URL shape: {index_base}/{ch1}{ch2}/{ch3}{ch4}/{crate}
//!   where ch1..ch4 come from the crate name:
//!     len 1:  "1/{name}"
//!     len 2:  "2/{name}"
//!     len 3:  "3/{first_char}/{name}"
//!     len ≥4: "{first_two}/{next_two}/{name}"
//!
//! Response format is JSON-lines: one version per line, not a JSON array.
//! Each line is {"name":"...","vers":"...","deps":[...],"features":{...},
//!   "cksum":"...","yanked":false,"links":null}.
//!
//! Users wire the proxy into cargo via `.cargo/config.toml`:
//!   [source.crates-io] replace-with="vetpkg"
//!   [source.vetpkg]    registry="sparse+http://127.0.0.1:9451/cargo/index/"

use crate::json::{parse, to_json_string, JsonValue};

pub const DEFAULT_INDEX_BASE: &str = "https://index.crates.io";
pub const DEFAULT_DOWNLOAD_BASE: &str = "https://static.crates.io";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SparseIndexEntry {
    pub name: String,
    pub version: String,
    pub yanked: bool,
    pub cksum: Option<String>,
    pub raw: String,
}

pub fn sparse_index_path(crate_name: &str) -> String {
    let lower = crate_name.to_ascii_lowercase();
    let bytes = lower.as_bytes();
    match bytes.len() {
        0 => lower,
        1 => format!("1/{lower}"),
        2 => format!("2/{lower}"),
        3 => format!("3/{}/{lower}", char::from(bytes[0])),
        _ => {
            let first = std::str::from_utf8(&bytes[..2]).unwrap_or("");
            let next = std::str::from_utf8(&bytes[2..4]).unwrap_or("");
            format!("{first}/{next}/{lower}")
        }
    }
}

pub fn parse_sparse_lines(text: &str) -> Vec<SparseIndexEntry> {
    let mut out: Vec<SparseIndexEntry> = Vec::new();
    for raw in text.lines() {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Ok(v) = parse(trimmed) else { continue };
        let name = v
            .get("name")
            .and_then(|s| s.as_str())
            .unwrap_or("")
            .to_string();
        let version = v
            .get("vers")
            .and_then(|s| s.as_str())
            .unwrap_or("")
            .to_string();
        let yanked = v.get("yanked").and_then(|b| b.as_bool()).unwrap_or(false);
        let cksum = v
            .get("cksum")
            .and_then(|s| s.as_str())
            .map(|s| s.to_string());
        out.push(SparseIndexEntry {
            name,
            version,
            yanked,
            cksum,
            raw: trimmed.to_string(),
        });
    }
    out
}

pub fn emit_sparse_lines(entries: &[SparseIndexEntry]) -> String {
    let mut out = String::new();
    for e in entries {
        out.push_str(&e.raw);
        out.push('\n');
    }
    out
}

pub fn filter_blocked(entries: &[SparseIndexEntry], blocked: &[String]) -> Vec<SparseIndexEntry> {
    entries
        .iter()
        .filter(|e| !blocked.iter().any(|b| b == &e.version))
        .cloned()
        .collect()
}

pub fn mark_yanked(entries: &[SparseIndexEntry], to_mark: &[String]) -> Vec<SparseIndexEntry> {
    entries
        .iter()
        .map(|e| {
            if !e.yanked && to_mark.iter().any(|v| v == &e.version) {
                let updated = set_yanked_true(&e.raw).unwrap_or_else(|| e.raw.clone());
                SparseIndexEntry {
                    yanked: true,
                    raw: updated,
                    ..e.clone()
                }
            } else {
                e.clone()
            }
        })
        .collect()
}

fn set_yanked_true(raw: &str) -> Option<String> {
    let v = parse(raw).ok()?;
    let obj = v.as_object()?;
    let mut new_fields: Vec<(String, JsonValue)> = Vec::with_capacity(obj.len());
    let mut replaced = false;
    for (k, val) in obj {
        if k == "yanked" {
            new_fields.push((k.clone(), JsonValue::Bool(true)));
            replaced = true;
        } else {
            new_fields.push((k.clone(), val.clone()));
        }
    }
    if !replaced {
        new_fields.push(("yanked".into(), JsonValue::Bool(true)));
    }
    Some(to_json_string(&JsonValue::Object(new_fields)))
}

pub fn parse_index_route(path: &str) -> Option<String> {
    let rest = path.strip_prefix("/cargo/index/")?;
    if rest.is_empty() {
        return None;
    }
    let lower = rest.to_ascii_lowercase();
    let looks_valid = lower
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '/');
    if !looks_valid {
        return None;
    }
    Some(rest.to_string())
}

pub fn parse_download_route(path: &str) -> Option<(String, String)> {
    let rest = path.strip_prefix("/cargo/download/")?;
    let (name, version) = rest.split_once('/')?;
    if name.is_empty() || version.is_empty() {
        return None;
    }
    let name_ok = name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if !name_ok {
        return None;
    }
    Some((name.to_string(), version.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sparse_index_paths_match_cargo_convention() {
        assert_eq!(sparse_index_path("a"), "1/a");
        assert_eq!(sparse_index_path("ab"), "2/ab");
        assert_eq!(sparse_index_path("abc"), "3/a/abc");
        assert_eq!(sparse_index_path("serde"), "se/rd/serde");
        assert_eq!(sparse_index_path("tokio"), "to/ki/tokio");
    }

    #[test]
    fn parse_and_emit_round_trip() {
        let raw = "{\"name\":\"serde\",\"vers\":\"1.0.0\",\"yanked\":false,\"cksum\":\"abc\"}\n{\"name\":\"serde\",\"vers\":\"1.1.0\",\"yanked\":false,\"cksum\":\"def\"}\n";
        let entries = parse_sparse_lines(raw);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "serde");
        assert_eq!(entries[0].version, "1.0.0");
        assert_eq!(entries[0].cksum.as_deref(), Some("abc"));
        let back = emit_sparse_lines(&entries);
        assert!(back.contains("1.0.0"));
        assert!(back.contains("1.1.0"));
    }

    #[test]
    fn filter_blocked_removes_entry() {
        let entries = parse_sparse_lines(
            "{\"name\":\"x\",\"vers\":\"1.0.0\",\"yanked\":false}\n{\"name\":\"x\",\"vers\":\"1.0.1\",\"yanked\":false}\n",
        );
        let out = filter_blocked(&entries, &["1.0.0".into()]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].version, "1.0.1");
    }

    #[test]
    fn mark_yanked_rewrites_raw() {
        let entries = parse_sparse_lines(
            "{\"name\":\"x\",\"vers\":\"1.0.0\",\"yanked\":false,\"cksum\":\"abc\"}\n",
        );
        let out = mark_yanked(&entries, &["1.0.0".into()]);
        assert_eq!(out.len(), 1);
        assert!(out[0].yanked);
        let reparsed = parse_sparse_lines(&emit_sparse_lines(&out));
        assert!(reparsed[0].yanked);
        assert_eq!(reparsed[0].cksum.as_deref(), Some("abc"));
    }

    #[test]
    fn index_route_accepts_valid_paths() {
        assert_eq!(
            parse_index_route("/cargo/index/se/rd/serde"),
            Some("se/rd/serde".to_string())
        );
        assert_eq!(
            parse_index_route("/cargo/index/1/a"),
            Some("1/a".to_string())
        );
        assert!(parse_index_route("/cargo/index/").is_none());
        assert!(parse_index_route("/cargo/download/serde/1.0.0").is_none());
    }

    #[test]
    fn download_route_extracts_name_and_version() {
        assert_eq!(
            parse_download_route("/cargo/download/serde/1.0.0"),
            Some(("serde".into(), "1.0.0".into()))
        );
        assert!(parse_download_route("/cargo/download/serde").is_none());
        assert!(parse_download_route("/cargo/download//1.0.0").is_none());
    }
}

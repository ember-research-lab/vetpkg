//! PyPI adapter: Simple API (PEP 503) tokenizer + JSON API parser.
//!
//! The Simple API returns HTML with one link per distribution file. PEP 503
//! does NOT mandate one link per line, so we parse across line breaks by
//! scanning for `<a `..`</a>` tag pairs and extracting href attributes.
//!
//! The JSON API returns structured metadata we can map to PackageIntel.

use crate::adapter::npm::iso_to_unix;
use crate::json::JsonValue;
use crate::types::{Ecosystem, PackageIntel};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimpleLink {
    pub href: String,
    pub filename: String,
}

pub fn parse_simple_html(html: &str) -> Vec<SimpleLink> {
    let mut out: Vec<SimpleLink> = Vec::new();
    let bytes = html.as_bytes();
    let mut i = 0usize;
    let lower: Vec<u8> = bytes.iter().map(|b| b.to_ascii_lowercase()).collect();
    while i + 3 <= lower.len() {
        if lower[i] == b'<'
            && matches!(lower.get(i + 1), Some(b'a'))
            && is_tag_boundary(lower.get(i + 2))
        {
            let tag_end = match find_byte(&lower, i, b'>') {
                Some(p) => p,
                None => break,
            };
            let attrs = &bytes[i + 2..tag_end];
            if let Some(href) = extract_attr(attrs, "href") {
                let filename = filename_from_href(&href);
                if !filename.is_empty() {
                    out.push(SimpleLink { href, filename });
                }
            }
            i = tag_end + 1;
            continue;
        }
        i += 1;
    }
    out
}

fn is_tag_boundary(b: Option<&u8>) -> bool {
    matches!(b, Some(c) if c.is_ascii_whitespace() || *c == b'>' || *c == b'/')
}

fn find_byte(bytes: &[u8], start: usize, target: u8) -> Option<usize> {
    bytes[start..]
        .iter()
        .position(|b| *b == target)
        .map(|p| start + p)
}

fn extract_attr(attrs_bytes: &[u8], name: &str) -> Option<String> {
    let lower: Vec<u8> = attrs_bytes.iter().map(|b| b.to_ascii_lowercase()).collect();
    let needle = name.as_bytes();
    let mut i = 0usize;
    while i + needle.len() <= lower.len() {
        if lower[i..i + needle.len()] == *needle {
            let after = i + needle.len();
            let eq_idx = skip_ws_and_find(&lower, after, b'=')?;
            let mut j = eq_idx + 1;
            while j < lower.len() && lower[j].is_ascii_whitespace() {
                j += 1;
            }
            let quote = lower.get(j).copied()?;
            if quote == b'"' || quote == b'\'' {
                let start = j + 1;
                let end = find_byte(&lower, start, quote)?;
                let raw = &attrs_bytes[start..end];
                return std::str::from_utf8(raw).ok().map(|s| s.to_string());
            }
            let start = j;
            let end = lower[start..]
                .iter()
                .position(|b| b.is_ascii_whitespace() || *b == b'>')
                .map(|p| start + p)
                .unwrap_or(lower.len());
            return std::str::from_utf8(&attrs_bytes[start..end])
                .ok()
                .map(|s| s.to_string());
        }
        i += 1;
    }
    None
}

fn skip_ws_and_find(bytes: &[u8], start: usize, target: u8) -> Option<usize> {
    let mut i = start;
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    if bytes.get(i).copied() == Some(target) {
        Some(i)
    } else {
        None
    }
}

fn filename_from_href(href: &str) -> String {
    let no_frag = href.split('#').next().unwrap_or(href);
    let no_query = no_frag.split('?').next().unwrap_or(no_frag);
    no_query.rsplit('/').next().unwrap_or("").to_string()
}

pub fn intel_for_version(name: &str, metadata: &JsonValue, version: &str) -> Option<PackageIntel> {
    let info = metadata.get("info")?;
    let releases = metadata.get("releases")?.as_object()?;

    let file_list = releases
        .iter()
        .find(|(k, _)| k == version)
        .map(|(_, v)| v)?;
    let publish_time = file_list
        .as_array()?
        .iter()
        .find_map(|entry| entry.get("upload_time_iso_8601").and_then(|s| s.as_str()))
        .and_then(iso_to_unix);

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let age_hours = publish_time.map(|p| ((now.saturating_sub(p)) as f64) / 3600.0);

    let mut publish_history: Vec<(String, u64)> = Vec::new();
    for (ver, arr_val) in releases {
        if let Some(arr) = arr_val.as_array() {
            if let Some(entry) = arr.iter().next() {
                if let Some(ts) = entry
                    .get("upload_time_iso_8601")
                    .and_then(|s| s.as_str())
                    .and_then(iso_to_unix)
                {
                    publish_history.push((ver.clone(), ts));
                }
            }
        }
    }

    let maintainers = collect_emails(info);

    let dependencies = info
        .get("requires_dist")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str())
                .filter_map(parse_requires_dist_name)
                .collect()
        })
        .unwrap_or_default();

    Some(PackageIntel {
        ecosystem: Some(Ecosystem::PyPI),
        name: name.to_string(),
        version: version.to_string(),
        maintainers,
        prior_maintainers: Vec::new(),
        publish_time,
        publish_history,
        dependencies,
        prior_dependencies: Vec::new(),
        install_hooks: Vec::new(),
        advisories: Vec::new(),
        typosquat_matches: Vec::new(),
        age_hours,
        dep_ages: std::collections::HashMap::new(),
        popularity_rank: None,
    })
}

fn collect_emails(info: &JsonValue) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for key in ["maintainer_email", "author_email"] {
        if let Some(s) = info.get(key).and_then(|v| v.as_str()) {
            for email in split_emails(s) {
                if !email.is_empty() && !out.contains(&email) {
                    out.push(email);
                }
            }
        }
    }
    out
}

fn split_emails(s: &str) -> Vec<String> {
    s.split(',')
        .filter_map(|chunk| {
            let chunk = chunk.trim();
            if chunk.is_empty() {
                return None;
            }
            if let Some(start) = chunk.find('<') {
                if let Some(end) = chunk.find('>') {
                    if end > start {
                        return Some(chunk[start + 1..end].trim().to_string());
                    }
                }
            }
            if chunk.contains('@') {
                Some(chunk.to_string())
            } else {
                None
            }
        })
        .collect()
}

pub fn parse_requires_dist_name(spec: &str) -> Option<String> {
    let spec = spec.split(';').next().unwrap_or(spec);
    let spec = spec.trim();
    let mut end = spec.len();
    for (i, b) in spec.as_bytes().iter().enumerate() {
        // Direct byte-membership test — the previous `.to_string().as_bytes()`
        // round-trip allocated a fresh String per byte, making this O(n)
        // allocations against an attacker-controlled Requires-Dist string.
        if b" <>=!~()".contains(b) {
            end = i;
            break;
        }
    }
    let name = spec[..end].trim().to_string();
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json::parse;

    #[test]
    fn simple_api_single_line() {
        let html = r#"<!DOCTYPE html><a href="https://files.pythonhosted.org/packages/abc/requests-2.31.0.tar.gz#sha=xx">requests-2.31.0.tar.gz</a>"#;
        let links = parse_simple_html(html);
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].filename, "requests-2.31.0.tar.gz");
    }

    #[test]
    fn simple_api_multiline_links() {
        let html = r#"<html>
<body>
<a href="/packages/a/x-1.0.tar.gz">x-1.0.tar.gz</a>
<a
  href="/packages/a/x-1.1.tar.gz"
  data-requires-python=">=3.8"
>x-1.1.tar.gz</a>
<a class='m' href='/packages/a/x-1.2.tar.gz'>x-1.2.tar.gz</a>
</body>
</html>"#;
        let links = parse_simple_html(html);
        assert_eq!(links.len(), 3);
        assert_eq!(links[0].filename, "x-1.0.tar.gz");
        assert_eq!(links[1].filename, "x-1.1.tar.gz");
        assert_eq!(links[2].filename, "x-1.2.tar.gz");
    }

    #[test]
    fn simple_api_no_links_returns_empty() {
        let links = parse_simple_html("<html><body>no links here</body></html>");
        assert!(links.is_empty());
    }

    #[test]
    fn json_api_maps_metadata() {
        let meta = parse(
            r#"{
            "info": {
                "name": "requests",
                "version": "2.31.0",
                "author_email": "Kenneth Reitz <me@kennethreitz.org>",
                "maintainer_email": "Kenneth Reitz <me@kennethreitz.org>",
                "requires_dist": ["charset-normalizer (>=2)", "idna (>=2.5,<4); python_version>='3'"]
            },
            "releases": {
                "2.31.0": [{"upload_time_iso_8601": "2023-05-22T15:12:00.000000Z"}],
                "2.30.0": [{"upload_time_iso_8601": "2023-05-03T12:00:00.000000Z"}]
            }
        }"#,
        )
        .unwrap();
        let intel = intel_for_version("requests", &meta, "2.31.0").unwrap();
        assert_eq!(intel.ecosystem, Some(Ecosystem::PyPI));
        assert_eq!(intel.name, "requests");
        assert_eq!(intel.maintainers, vec!["me@kennethreitz.org".to_string()]);
        assert_eq!(intel.dependencies.len(), 2);
        assert!(intel
            .dependencies
            .contains(&"charset-normalizer".to_string()));
        assert!(intel.dependencies.contains(&"idna".to_string()));
        assert!(intel.publish_history.len() >= 2);
    }

    #[test]
    fn requires_dist_strips_markers_and_specifiers() {
        assert_eq!(
            parse_requires_dist_name("requests>=2.20,<3.0; python_version>=\"3.6\""),
            Some("requests".into())
        );
        assert_eq!(
            parse_requires_dist_name("charset-normalizer (>=2)"),
            Some("charset-normalizer".into())
        );
        assert_eq!(
            parse_requires_dist_name("  numpy ~=1.24  "),
            Some("numpy".into())
        );
        assert_eq!(parse_requires_dist_name(""), None);
    }
}

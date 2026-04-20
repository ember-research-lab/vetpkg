//! Online tag-mutation detection. Resolves annotated vs lightweight tags
//! through the GitHub REST API, caches the commit SHA for each (owner,
//! action, tag) triple, and flags Critical when a cached SHA differs from
//! the current upstream SHA.
//!
//! Network calls go through `net::http_client::fetch_json`, which will use
//! curl on HTTPS and direct TcpStream on http://127.0.0.1:* for tests.
//! The `VETPKG_NO_EXTERNAL_NETWORK` guard applies — audit-ci --online in CI
//! is a no-op if the env var is set.

use crate::adapter::npm::iso_to_unix;
use crate::net::http_client::fetch_json;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinCheckEntry {
    pub action: String,
    pub tag: String,
    pub sha: String,
    pub checked_at: u64,
}

pub fn parse_tag_ref_response(body: &str) -> Option<(String, String)> {
    let v = crate::json::parse(body).ok()?;
    let obj = v.get("object")?;
    let ty = obj.get("type")?.as_str()?;
    let sha = obj.get("sha")?.as_str()?;
    Some((ty.to_string(), sha.to_string()))
}

pub fn iso_to_unix_opt(s: &str) -> Option<u64> {
    iso_to_unix(s)
}

pub const CACHE_TTL_SECS: u64 = 24 * 3600;
pub const GITHUB_API_DEFAULT: &str = "https://api.github.com";
pub const FETCH_TIMEOUT_SECS: u32 = 10;

pub fn is_stale(entry: &PinCheckEntry, now: u64) -> bool {
    now.saturating_sub(entry.checked_at) >= CACHE_TTL_SECS
}

pub fn resolve_tag_sha(
    api_base: &str,
    owner: &str,
    repo: &str,
    tag: &str,
) -> Result<String, String> {
    // Validate every path component that flows from an attacker-controlled
    // workflow file into the GitHub REST API URL. Without this, a `uses:`
    // value of `evil/repo/../../../admin/settings@v1` produces a URL with
    // literal `..` that curl forwards and GitHub's router walks — potentially
    // reaching endpoints the audit was never meant to probe.
    validate_github_component(owner).map_err(|e| format!("bad owner: {e}"))?;
    validate_github_component(repo).map_err(|e| format!("bad repo: {e}"))?;
    validate_github_ref(tag).map_err(|e| format!("bad tag: {e}"))?;
    let url = format!(
        "{}/repos/{owner}/{repo}/git/ref/tags/{tag}",
        api_base.trim_end_matches('/')
    );
    let ua = format!("vetpkg/{}", env!("CARGO_PKG_VERSION"));
    let headers = &[
        ("User-Agent", ua.as_str()),
        ("Accept", "application/vnd.github+json"),
    ];
    let first =
        fetch_json(&url, headers, FETCH_TIMEOUT_SECS).map_err(|e| format!("tag ref {url}: {e}"))?;
    let (ty, sha) =
        extract_object(&first).ok_or_else(|| format!("tag ref {url}: missing object.type/sha"))?;
    if ty == "commit" {
        return Ok(sha);
    }
    if ty == "tag" {
        validate_sha_like(&sha).map_err(|e| format!("bad annotated-tag sha: {e}"))?;
        let tag_url = format!(
            "{}/repos/{owner}/{repo}/git/tags/{sha}",
            api_base.trim_end_matches('/')
        );
        let second = fetch_json(&tag_url, headers, FETCH_TIMEOUT_SECS)
            .map_err(|e| format!("annotated tag {tag_url}: {e}"))?;
        let (ty2, sha2) = extract_object(&second)
            .ok_or_else(|| format!("annotated tag {tag_url}: missing object.type/sha"))?;
        if ty2 == "commit" {
            return Ok(sha2);
        }
        return Err(format!(
            "annotated tag resolved to unexpected type {ty2:?} at {tag_url}"
        ));
    }
    Err(format!("unexpected ref object type {ty:?} for {url}"))
}

/// GitHub owner/repo names: [a-zA-Z0-9._-]{1,100}. No leading dot or dash.
/// Strictly reject anything else before it reaches a URL path component.
fn validate_github_component(s: &str) -> Result<(), String> {
    if s.is_empty() || s.len() > 100 {
        return Err("length out of range".into());
    }
    if s.starts_with('.') || s.starts_with('-') {
        return Err("must not start with '.' or '-'".into());
    }
    for b in s.bytes() {
        match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'.' | b'-' | b'_' => {}
            _ => return Err(format!("forbidden byte 0x{b:02x}")),
        }
    }
    if s == "." || s == ".." {
        return Err("forbidden component".into());
    }
    Ok(())
}

/// Git ref names as accepted by GitHub (subset of git-check-ref-format).
/// We allow tag-shaped strings plus SHAs (which may appear via `uses:`).
fn validate_github_ref(s: &str) -> Result<(), String> {
    if s.is_empty() || s.len() > 250 {
        return Err("length out of range".into());
    }
    // git forbids these explicitly; we inherit + also block URL-meta chars
    // that would let the ref escape the path segment.
    for b in s.bytes() {
        match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'.' | b'-' | b'_' | b'/' | b'+' => {}
            _ => return Err(format!("forbidden byte 0x{b:02x}")),
        }
    }
    if s.contains("..") || s.starts_with('/') || s.starts_with('.') || s.ends_with('.') {
        return Err("contains invalid sequence".into());
    }
    Ok(())
}

/// Validate a value coming back from the GitHub API before embedding it
/// in a second API URL. Real SHAs are 40-char lowercase hex, but we
/// accept the broader alphanumeric+underscore/hyphen set to remain
/// robust across mock fixtures. What matters for security is that no
/// path-traversal or URL-meta bytes slip through.
fn validate_sha_like(s: &str) -> Result<(), String> {
    if s.is_empty() || s.len() > 64 {
        return Err("length out of range".into());
    }
    for b in s.bytes() {
        match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_' | b'-' => {}
            _ => return Err(format!("forbidden byte 0x{b:02x}")),
        }
    }
    Ok(())
}

fn extract_object(v: &crate::json::JsonValue) -> Option<(String, String)> {
    let obj = v.get("object")?;
    let ty = obj.get("type")?.as_str()?.to_string();
    let sha = obj.get("sha")?.as_str()?.to_string();
    Some((ty, sha))
}

pub fn split_owner_repo(uses_target: &str) -> Option<(String, String)> {
    let (owner, rest) = uses_target.split_once('/')?;
    let repo = rest.split('/').next()?;
    if owner.is_empty() || repo.is_empty() {
        return None;
    }
    Some((owner.to_string(), repo.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_lightweight_tag_ref() {
        let body = r#"{"ref":"refs/tags/v4","object":{"sha":"b4ffde","type":"commit"}}"#;
        let (ty, sha) = parse_tag_ref_response(body).unwrap();
        assert_eq!(ty, "commit");
        assert_eq!(sha, "b4ffde");
    }

    #[test]
    fn parse_annotated_tag_ref() {
        let body = r#"{"ref":"refs/tags/v4","object":{"sha":"abc123","type":"tag"}}"#;
        let (ty, sha) = parse_tag_ref_response(body).unwrap();
        assert_eq!(ty, "tag");
        assert_eq!(sha, "abc123");
    }

    #[test]
    fn split_owner_repo_common_cases() {
        assert_eq!(
            split_owner_repo("actions/checkout"),
            Some(("actions".into(), "checkout".into()))
        );
        assert_eq!(
            split_owner_repo("tj-actions/changed-files"),
            Some(("tj-actions".into(), "changed-files".into()))
        );
        assert_eq!(
            split_owner_repo("owner/repo/path"),
            Some(("owner".into(), "repo".into()))
        );
        assert!(split_owner_repo("just-owner").is_none());
    }

    #[test]
    fn owner_repo_tag_validation_blocks_traversal() {
        assert!(validate_github_component("actions").is_ok());
        assert!(validate_github_component("tj-actions").is_ok());
        assert!(validate_github_component("..").is_err());
        assert!(validate_github_component(".hidden").is_err());
        assert!(validate_github_component("-x").is_err());
        assert!(validate_github_component("a/b").is_err());
        assert!(validate_github_component("a?b").is_err());

        assert!(validate_github_ref("v4").is_ok());
        assert!(validate_github_ref("v1.2.3").is_ok());
        assert!(validate_github_ref("release/v1").is_ok());
        assert!(validate_github_ref("../../admin").is_err());
        assert!(validate_github_ref("v1?query").is_err());
        assert!(validate_github_ref(".hidden").is_err());
    }

    #[test]
    fn resolve_tag_sha_rejects_traversal_input() {
        // owner containing a slash never even reaches fetch_json.
        let err = resolve_tag_sha("https://api.github.com", "evil/a", "repo", "v1").unwrap_err();
        assert!(err.contains("bad owner"));
        let err =
            resolve_tag_sha("https://api.github.com", "owner", "repo", "../evil").unwrap_err();
        assert!(err.contains("bad tag"));
    }

    #[test]
    fn stale_detection_uses_ttl() {
        let now: u64 = 10 * CACHE_TTL_SECS;
        let fresh = PinCheckEntry {
            action: "a/b".into(),
            tag: "v1".into(),
            sha: "x".into(),
            checked_at: now - 3000,
        };
        assert!(!is_stale(&fresh, now));
        let stale = PinCheckEntry {
            action: "a/b".into(),
            tag: "v1".into(),
            sha: "x".into(),
            checked_at: now.saturating_sub(2 * CACHE_TTL_SECS),
        };
        assert!(is_stale(&stale, now));
    }
}

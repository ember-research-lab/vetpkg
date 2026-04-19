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

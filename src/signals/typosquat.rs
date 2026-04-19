use crate::signals::Check;
use crate::types::{PackageIntel, PolicyConfig, Signal};

const TOP_NPM_RAW: &str = include_str!("../../data/top_npm.txt");

pub fn default_corpus() -> Vec<String> {
    TOP_NPM_RAW
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect()
}

pub struct TyposquatCheck {
    pub corpus: Vec<String>,
}

impl TyposquatCheck {
    pub fn new(corpus: Vec<String>) -> Self {
        Self { corpus }
    }
}

impl Check for TyposquatCheck {
    fn name(&self) -> &'static str {
        "typosquat"
    }

    fn evaluate(&self, intel: &PackageIntel, config: &PolicyConfig) -> Vec<Signal> {
        let name = &intel.name;
        let mut out = Vec::new();
        let threshold = config.typosquat_distance_threshold;
        if name.len() < 5 {
            return out;
        }
        for popular in &self.corpus {
            if popular == name {
                return Vec::new();
            }
            if !is_comparable(name, popular) {
                continue;
            }
            let sim = jaro_winkler(name, popular) as f32;
            let dist = 1.0 - sim;
            if dist < threshold && dist > 0.0 {
                out.push(Signal::Typosquat {
                    matched: popular.clone(),
                    distance: dist,
                });
            }
        }
        out
    }
}

fn scope_of(name: &str) -> Option<&str> {
    let rest = name.strip_prefix('@')?;
    let slash = rest.find('/')?;
    Some(&rest[..slash])
}

fn unscoped(name: &str) -> &str {
    match name
        .strip_prefix('@')
        .and_then(|r| r.find('/').map(|s| &r[s + 1..]))
    {
        Some(u) => u,
        None => name,
    }
}

/// Return false when the candidate/corpus pair is structurally incompatible
/// and therefore not a plausible typosquat relationship regardless of
/// surface similarity. Catches the common FP classes observed in real
/// lockfiles (@types/X vs @types/Y, vitest vs vite, source-map-js vs
/// source-map, platform-prebuilt binaries like @rollup/rollup-linux-x64).
pub fn is_comparable(candidate: &str, corpus_entry: &str) -> bool {
    let c_scope = scope_of(candidate);
    let p_scope = scope_of(corpus_entry);
    match (c_scope, p_scope) {
        (Some(cs), Some(ps)) => {
            if cs == ps {
                return false;
            }
            let cu = unscoped(candidate);
            let pu = unscoped(corpus_entry);
            if cu != pu {
                return false;
            }
            return edit_distance(cs, ps) <= 2;
        }
        (Some(_), None) | (None, Some(_)) => return false,
        (None, None) => {}
    }

    let al = candidate.chars().count();
    let bl = corpus_entry.chars().count();
    if al.abs_diff(bl) > 2 {
        return false;
    }
    if family_prefix(candidate, corpus_entry) || family_prefix(corpus_entry, candidate) {
        return false;
    }
    if shared_dash_family(candidate, corpus_entry) {
        return false;
    }
    let min_len = al.min(bl);
    let max_edits = if min_len < 10 { 1 } else { 2 };
    if damerau_levenshtein(candidate, corpus_entry) > max_edits {
        return false;
    }
    true
}

/// If both names share a common prefix ending in `-` and at least 3 chars
/// long before the dash, treat them as a deliberate family even if no
/// other rule matched (catches `strip-indent` vs `strip-ansi`,
/// `babel-preset-solid` vs `babel-preset-jest`, `css-tree` vs `css-what`).
fn shared_dash_family(a: &str, b: &str) -> bool {
    let ab = a.as_bytes();
    let bb = b.as_bytes();
    let max = ab.len().min(bb.len());
    let mut last_dash: Option<usize> = None;
    for i in 0..max {
        if ab[i] != bb[i] {
            break;
        }
        if ab[i] == b'-' {
            last_dash = Some(i);
        }
    }
    match last_dash {
        Some(idx) if idx >= 3 => true,
        _ => false,
    }
}

fn edit_distance(a: &str, b: &str) -> usize {
    damerau_levenshtein(a, b)
}

fn damerau_levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let (m, n) = (a.len(), b.len());
    if m == 0 {
        return n;
    }
    if n == 0 {
        return m;
    }
    let mut d = vec![vec![0usize; n + 1]; m + 1];
    for i in 0..=m {
        d[i][0] = i;
    }
    for j in 0..=n {
        d[0][j] = j;
    }
    for i in 1..=m {
        for j in 1..=n {
            let sub = if a[i - 1] == b[j - 1] { 0 } else { 1 };
            let mut v = (d[i - 1][j] + 1)
                .min(d[i][j - 1] + 1)
                .min(d[i - 1][j - 1] + sub);
            if i >= 2 && j >= 2 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                v = v.min(d[i - 2][j - 2] + 1);
            }
            d[i][j] = v;
        }
    }
    d[m][n]
}

fn family_prefix(longer: &str, shorter: &str) -> bool {
    if longer.len() <= shorter.len() {
        return false;
    }
    let Some(rest) = longer.strip_prefix(shorter) else {
        return false;
    };
    let first = rest.chars().next();
    match first {
        Some('-') | Some('/') | Some('.') | Some('_') => true,
        // Tight-join prefix: `vitest` over `vite`. Require the suffix
        // to be at least 2 chars so short coincidences don't trigger.
        Some(c) if c.is_ascii_alphabetic() => rest.chars().count() >= 2,
        _ => false,
    }
}

pub fn jaro_winkler(a: &str, b: &str) -> f64 {
    let j = jaro(a, b);
    if j < 0.7 {
        return j;
    }
    let ac: Vec<char> = a.chars().collect();
    let bc: Vec<char> = b.chars().collect();
    let l = ac
        .iter()
        .zip(bc.iter())
        .take(4)
        .take_while(|(x, y)| x == y)
        .count();
    j + (l as f64) * 0.1 * (1.0 - j)
}

fn jaro(a: &str, b: &str) -> f64 {
    if a.is_empty() && b.is_empty() {
        return 1.0;
    }
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }
    let ac: Vec<char> = a.chars().collect();
    let bc: Vec<char> = b.chars().collect();
    let alen = ac.len();
    let blen = bc.len();
    let match_distance = (alen.max(blen) / 2).saturating_sub(1);

    let mut a_matches = vec![false; alen];
    let mut b_matches = vec![false; blen];
    let mut matches = 0usize;
    for i in 0..alen {
        let start = i.saturating_sub(match_distance);
        let end = (i + match_distance + 1).min(blen);
        for j in start..end {
            if b_matches[j] {
                continue;
            }
            if ac[i] != bc[j] {
                continue;
            }
            a_matches[i] = true;
            b_matches[j] = true;
            matches += 1;
            break;
        }
    }
    if matches == 0 {
        return 0.0;
    }
    let mut k = 0usize;
    let mut transpositions = 0usize;
    for i in 0..alen {
        if !a_matches[i] {
            continue;
        }
        while !b_matches[k] {
            k += 1;
        }
        if ac[i] != bc[k] {
            transpositions += 1;
        }
        k += 1;
    }
    let m = matches as f64;
    (m / alen as f64 + m / blen as f64 + (m - transpositions as f64 / 2.0) / m) / 3.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn corpus_loads() {
        let c = default_corpus();
        assert!(c.len() > 500, "corpus size {}", c.len());
        assert!(c
            .iter()
            .any(|s| s == "react" || s == "express" || s == "lodash"));
    }

    #[test]
    fn exact_match_no_flag() {
        let chk = TyposquatCheck::new(vec!["express".into(), "react".into()]);
        let intel = PackageIntel {
            name: "express".into(),
            ..Default::default()
        };
        let out = chk.evaluate(&intel, &PolicyConfig::default());
        assert!(out.is_empty());
    }

    #[test]
    fn close_name_flags() {
        let chk = TyposquatCheck::new(vec!["express".into()]);
        let intel = PackageIntel {
            name: "expreess".into(),
            ..Default::default()
        };
        let out = chk.evaluate(&intel, &PolicyConfig::default());
        assert!(!out.is_empty());
    }

    #[test]
    fn far_name_no_flag() {
        let chk = TyposquatCheck::new(vec!["express".into()]);
        let intel = PackageIntel {
            name: "totally-different-package-xyz".into(),
            ..Default::default()
        };
        let out = chk.evaluate(&intel, &PolicyConfig::default());
        assert!(out.is_empty());
    }

    #[test]
    fn jw_known_pairs() {
        let j = jaro_winkler("MARTHA", "MARHTA");
        assert!((j - 0.961).abs() < 0.01, "jw martha = {j}");
    }

    #[test]
    fn same_scope_siblings_not_comparable() {
        assert!(!is_comparable("@babel/compat-data", "@babel/core"));
        assert!(!is_comparable("@types/aria-query", "@types/react"));
        assert!(!is_comparable(
            "@rollup/rollup-android-arm-eabi",
            "@rollup/plugin-babel"
        ));
    }

    #[test]
    fn cross_scope_not_comparable() {
        assert!(!is_comparable("@vitest/utils", "@vue/test-utils"));
        assert!(!is_comparable("@types/react", "@babel/core"));
    }

    #[test]
    fn scoped_vs_unscoped_not_comparable() {
        assert!(!is_comparable("@rollup/rollup-linux-x64-gnu", "rollup"));
        assert!(!is_comparable("react", "@types/react"));
    }

    #[test]
    fn family_delimiter_prefix_not_comparable() {
        assert!(!is_comparable("source-map-js", "source-map"));
        assert!(!is_comparable("has-flag", "has"));
        assert!(!is_comparable("expect-type", "expect"));
    }

    #[test]
    fn tight_join_prefix_not_comparable() {
        assert!(!is_comparable("vitest", "vite"));
        assert!(!is_comparable("vitefu", "vite"));
    }

    #[test]
    fn length_gap_not_comparable() {
        assert!(!is_comparable("require-from-string", "request"));
        assert!(!is_comparable("dequal", "deep-equal"));
        assert!(!is_comparable("pathe", "path-to-regexp"));
    }

    #[test]
    fn plausible_typosquat_still_flagged() {
        assert!(is_comparable("expreess", "express"));
        assert!(is_comparable("reqeust", "request"));
        assert!(is_comparable("lodahs", "lodash"));
    }

    #[test]
    fn shared_dash_families_not_comparable() {
        assert!(!is_comparable("strip-indent", "strip-ansi"));
        assert!(!is_comparable("babel-preset-solid", "babel-preset-jest"));
        assert!(!is_comparable("css-tree", "css-what"));
    }

    #[test]
    fn unrelated_similar_pairs_rejected_by_edit_distance() {
        assert!(!is_comparable("html-escaper", "htmlparser2"));
        assert!(!is_comparable("parse5", "parseurl"));
        assert!(!is_comparable("is-what", "css-what"));
    }

    #[test]
    fn edit_distance_monotonic() {
        assert_eq!(edit_distance("abc", "abc"), 0);
        assert_eq!(edit_distance("abc", "abd"), 1);
        assert_eq!(edit_distance("abc", "axd"), 2);
        assert_eq!(edit_distance("abc", "xyz"), 3);
        assert_eq!(edit_distance("", "abc"), 3);
    }

    #[test]
    fn transposition_is_single_edit() {
        assert_eq!(damerau_levenshtein("reqeust", "request"), 1);
        assert_eq!(damerau_levenshtein("lodahs", "lodash"), 1);
        assert_eq!(damerau_levenshtein("marhta", "martha"), 1);
    }

    #[test]
    fn short_candidate_skipped_entirely() {
        let chk = TyposquatCheck::new(vec!["lodash".into(), "vite".into()]);
        let intel = PackageIntel {
            name: "has".into(),
            ..Default::default()
        };
        assert!(chk.evaluate(&intel, &PolicyConfig::default()).is_empty());
    }

    #[test]
    fn corpus_has_scoped_entries() {
        let c = default_corpus();
        assert!(c.iter().any(|s| s == "@babel/core"));
        assert!(c.iter().any(|s| s == "@vercel/next"));
        assert!(c.iter().any(|s| s == "@types/node"));
        let scoped_count = c.iter().filter(|s| s.starts_with('@')).count();
        assert!(
            scoped_count >= 200,
            "expected 200+ scoped entries, got {}",
            scoped_count
        );
    }

    #[test]
    fn scoped_typo_flags_against_real_corpus() {
        let corpus = default_corpus();
        let chk = TyposquatCheck::new(corpus);
        let intel = PackageIntel {
            name: "@bable/core".into(),
            ..Default::default()
        };
        let out = chk.evaluate(&intel, &PolicyConfig::default());
        assert!(
            out.iter().any(
                |s| matches!(s, Signal::Typosquat { matched, .. } if matched == "@babel/core")
            ),
            "typosquat should flag @bable/core against @babel/core; got {out:?}"
        );
    }

    #[test]
    fn exact_scoped_match_no_flag() {
        let corpus = default_corpus();
        let chk = TyposquatCheck::new(corpus);
        let intel = PackageIntel {
            name: "@babel/core".into(),
            ..Default::default()
        };
        assert!(chk.evaluate(&intel, &PolicyConfig::default()).is_empty());
    }
}

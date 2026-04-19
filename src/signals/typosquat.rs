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
        for popular in &self.corpus {
            if popular == name {
                return Vec::new();
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

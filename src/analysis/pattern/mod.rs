//! Source/sink pattern loader used by TaintDetection (Phase 3).
//!
//! Loading order (union by default, user precedence for disambiguation):
//!   1. Built-in patterns compiled in via include_str!
//!   2. User overrides at `{config_dir}/patterns/{sources,sinks}_{lang}.txt`
//!
//! A user override file may contain a line `# replace` (case-insensitive,
//! after comment stripping) to discard the built-in list entirely for
//! that language — useful when a user wants full control for false-
//! positive triage.
//!
//! All patterns are literal substrings (case-sensitive for JS/TS/Py/Rust
//! identifiers). The matcher is in the sibling matcher module.

use std::path::{Path, PathBuf};

const BUILTIN_SOURCES_JS: &str = include_str!("../../../data/patterns/sources_javascript.txt");
const BUILTIN_SINKS_JS: &str = include_str!("../../../data/patterns/sinks_javascript.txt");
const BUILTIN_SOURCES_PY: &str = include_str!("../../../data/patterns/sources_python.txt");
const BUILTIN_SINKS_PY: &str = include_str!("../../../data/patterns/sinks_python.txt");
const BUILTIN_SOURCES_RS: &str = include_str!("../../../data/patterns/sources_rust.txt");
const BUILTIN_SINKS_RS: &str = include_str!("../../../data/patterns/sinks_rust.txt");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Language {
    JavaScript,
    Python,
    Rust,
}

impl Language {
    pub fn from_extension(ext: &str) -> Option<Language> {
        match ext.to_ascii_lowercase().as_str() {
            "js" | "mjs" | "cjs" | "jsx" | "ts" | "tsx" => Some(Language::JavaScript),
            "py" | "pyi" => Some(Language::Python),
            "rs" => Some(Language::Rust),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Language::JavaScript => "javascript",
            Language::Python => "python",
            Language::Rust => "rust",
        }
    }

    fn builtin_sources(self) -> &'static str {
        match self {
            Language::JavaScript => BUILTIN_SOURCES_JS,
            Language::Python => BUILTIN_SOURCES_PY,
            Language::Rust => BUILTIN_SOURCES_RS,
        }
    }

    fn builtin_sinks(self) -> &'static str {
        match self {
            Language::JavaScript => BUILTIN_SINKS_JS,
            Language::Python => BUILTIN_SINKS_PY,
            Language::Rust => BUILTIN_SINKS_RS,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PatternSet {
    pub sources: Vec<String>,
    pub sinks: Vec<String>,
}

impl PatternSet {
    pub fn builtin(lang: Language) -> Self {
        Self {
            sources: parse_list(lang.builtin_sources(), false).patterns,
            sinks: parse_list(lang.builtin_sinks(), false).patterns,
        }
    }

    pub fn load_for_language(lang: Language, config_dir: Option<&Path>) -> Self {
        let mut set = Self::builtin(lang);
        if let Some(dir) = config_dir {
            if let Some(user_sources) =
                read_user_file(dir, &format!("sources_{}.txt", lang.as_str()))
            {
                let parsed = parse_list(&user_sources, true);
                if parsed.replace {
                    set.sources = parsed.patterns;
                } else {
                    for p in parsed.patterns {
                        if !set.sources.contains(&p) {
                            set.sources.push(p);
                        }
                    }
                }
            }
            if let Some(user_sinks) = read_user_file(dir, &format!("sinks_{}.txt", lang.as_str())) {
                let parsed = parse_list(&user_sinks, true);
                if parsed.replace {
                    set.sinks = parsed.patterns;
                } else {
                    for p in parsed.patterns {
                        if !set.sinks.contains(&p) {
                            set.sinks.push(p);
                        }
                    }
                }
            }
        }
        set
    }
}

fn read_user_file(config_dir: &Path, name: &str) -> Option<String> {
    let path: PathBuf = config_dir.join("patterns").join(name);
    std::fs::read_to_string(path).ok()
}

struct ParsedList {
    patterns: Vec<String>,
    replace: bool,
}

fn parse_list(text: &str, allow_replace: bool) -> ParsedList {
    let mut patterns = Vec::new();
    let mut replace = false;
    for raw in text.lines() {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(stripped) = trimmed.strip_prefix('#') {
            if allow_replace && stripped.trim().eq_ignore_ascii_case("replace") {
                replace = true;
            }
            continue;
        }
        if !patterns.contains(&trimmed.to_string()) {
            patterns.push(trimmed.to_string());
        }
    }
    ParsedList { patterns, replace }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::TempDir;
    use std::fs;

    #[test]
    fn language_from_extension_covers_common_cases() {
        assert_eq!(Language::from_extension("js"), Some(Language::JavaScript));
        assert_eq!(Language::from_extension("TSX"), Some(Language::JavaScript));
        assert_eq!(Language::from_extension("py"), Some(Language::Python));
        assert_eq!(Language::from_extension("rs"), Some(Language::Rust));
        assert!(Language::from_extension("bin").is_none());
    }

    #[test]
    fn builtin_js_sources_loaded() {
        let set = PatternSet::builtin(Language::JavaScript);
        assert!(set.sources.iter().any(|p| p == "process.env"));
        assert!(set.sources.iter().any(|p| p == "fs.readFileSync"));
        assert!(set.sinks.iter().any(|p| p == "fetch("));
        assert!(set.sinks.iter().any(|p| p == "https.request"));
    }

    #[test]
    fn user_file_merged_by_union() {
        let td = TempDir::new("patterns-union").unwrap();
        let patterns_dir = td.path().join("patterns");
        fs::create_dir_all(&patterns_dir).unwrap();
        fs::write(
            patterns_dir.join("sources_javascript.txt"),
            "# user additions\ncustom.leak\nprocess.env\n",
        )
        .unwrap();
        let set = PatternSet::load_for_language(Language::JavaScript, Some(td.path()));
        assert!(set.sources.iter().any(|p| p == "custom.leak"));
        assert!(set.sources.iter().any(|p| p == "process.env"));
        let occurrences = set.sources.iter().filter(|p| p == &"process.env").count();
        assert_eq!(occurrences, 1, "dedup required");
    }

    #[test]
    fn replace_directive_discards_builtins() {
        let td = TempDir::new("patterns-replace").unwrap();
        let patterns_dir = td.path().join("patterns");
        fs::create_dir_all(&patterns_dir).unwrap();
        fs::write(
            patterns_dir.join("sources_python.txt"),
            "# replace\nonly_this\n",
        )
        .unwrap();
        let set = PatternSet::load_for_language(Language::Python, Some(td.path()));
        assert_eq!(set.sources, vec!["only_this".to_string()]);
        assert!(!set.sinks.is_empty(), "sinks should still have defaults");
    }

    #[test]
    fn empty_user_file_keeps_builtins() {
        let td = TempDir::new("patterns-empty").unwrap();
        let patterns_dir = td.path().join("patterns");
        fs::create_dir_all(&patterns_dir).unwrap();
        fs::write(patterns_dir.join("sources_rust.txt"), "").unwrap();
        let set = PatternSet::load_for_language(Language::Rust, Some(td.path()));
        assert!(set.sources.iter().any(|p| p == "std::env::var"));
    }

    #[test]
    fn no_config_dir_falls_back_to_builtin() {
        let set = PatternSet::load_for_language(Language::Rust, None);
        assert!(set.sources.iter().any(|p| p == "std::env::var"));
    }

    #[test]
    fn builtin_sinks_exist_per_language() {
        for lang in [Language::JavaScript, Language::Python, Language::Rust] {
            let set = PatternSet::builtin(lang);
            assert!(
                !set.sinks.is_empty(),
                "{} should have builtin sinks",
                lang.as_str()
            );
            assert!(
                !set.sources.is_empty(),
                "{} should have builtin sources",
                lang.as_str()
            );
        }
    }
}

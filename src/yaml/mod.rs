//! Minimal YAML parser for GitHub Actions workflows.
//!
//! Supported subset (docs/plan resolution #25):
//!   - Block maps: indent-based nesting, `key: value`
//!   - Block lists: `- item` (map or scalar)
//!   - Multiline scalars: `|` (literal) and `>` (folded)
//!   - Comments: `# …` (stripped outside quoted strings)
//!   - Flow maps on a single line: `{k: v, k2: v2}`
//!   - Flow lists on a single line: `[a, b, c]`
//!   - Scalars: quoted/unquoted strings, ints, bools (`true`/`false`),
//!     null (`null`/`~`).
//!
//! NOT supported: anchors (&foo), aliases (*foo), tags (!!str),
//! multi-document (---), complex keys. The parser errors on those
//! rather than silently misinterpreting.

pub mod workflow;

#[derive(Debug, Clone, PartialEq)]
pub enum YamlValue {
    Null,
    Bool(bool),
    Int(i64),
    Str(String),
    List(Vec<YamlValue>),
    Map(Vec<(String, YamlValue)>),
}

impl YamlValue {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            YamlValue::Str(s) => Some(s),
            _ => None,
        }
    }
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            YamlValue::Bool(b) => Some(*b),
            _ => None,
        }
    }
    pub fn as_int(&self) -> Option<i64> {
        match self {
            YamlValue::Int(n) => Some(*n),
            _ => None,
        }
    }
    pub fn as_list(&self) -> Option<&[YamlValue]> {
        match self {
            YamlValue::List(v) => Some(v),
            _ => None,
        }
    }
    pub fn as_map(&self) -> Option<&[(String, YamlValue)]> {
        match self {
            YamlValue::Map(m) => Some(m),
            _ => None,
        }
    }
    pub fn get(&self, key: &str) -> Option<&YamlValue> {
        self.as_map()
            .and_then(|m| m.iter().find(|(k, _)| k == key).map(|(_, v)| v))
    }
    pub fn is_null(&self) -> bool {
        matches!(self, YamlValue::Null)
    }
}

pub fn parse_yaml(input: &str) -> Result<YamlValue, String> {
    let lines = preprocess_lines(input);
    if lines.is_empty() {
        return Ok(YamlValue::Null);
    }
    let mut parser = BlockParser { lines, idx: 0 };
    parser.parse_value(0)
}

#[derive(Debug, Clone)]
struct PhysLine {
    indent: usize,
    text: String,
    lineno: usize,
}

fn preprocess_lines(input: &str) -> Vec<PhysLine> {
    let mut out = Vec::new();
    for (lineno, raw) in input.lines().enumerate() {
        if raw.trim().is_empty() {
            continue;
        }
        let indent = raw.as_bytes().iter().take_while(|b| **b == b' ').count();
        let body = raw[indent..].trim_end();
        let stripped = strip_comment(body);
        if stripped.trim().is_empty() {
            continue;
        }
        out.push(PhysLine {
            indent,
            text: stripped.to_string(),
            lineno,
        });
    }
    out
}

fn strip_comment(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut in_single = false;
    let mut in_double = false;
    let mut prev = ' ';
    for c in line.chars() {
        match c {
            '\'' if !in_double => in_single = !in_single,
            '"' if !in_single => in_double = !in_double,
            '#' if !in_single && !in_double && (prev == ' ' || prev == '\t' || out.is_empty()) => {
                break;
            }
            _ => {}
        }
        out.push(c);
        prev = c;
    }
    out.trim_end().to_string()
}

struct BlockParser {
    lines: Vec<PhysLine>,
    idx: usize,
}

impl BlockParser {
    fn peek(&self) -> Option<&PhysLine> {
        self.lines.get(self.idx)
    }

    fn parse_value(&mut self, base_indent: usize) -> Result<YamlValue, String> {
        let Some(first) = self.peek().cloned() else {
            return Ok(YamlValue::Null);
        };
        if first.text.starts_with("- ") || first.text == "-" {
            return self.parse_list(base_indent);
        }
        if first.text.contains(':') {
            return self.parse_map(base_indent);
        }
        self.idx += 1;
        parse_scalar(&first.text)
    }

    fn parse_list(&mut self, base_indent: usize) -> Result<YamlValue, String> {
        let mut items: Vec<YamlValue> = Vec::new();
        while let Some(line) = self.peek().cloned() {
            if line.indent < base_indent {
                break;
            }
            if line.indent > base_indent {
                break;
            }
            if !(line.text.starts_with("- ") || line.text == "-") {
                break;
            }
            self.idx += 1;
            let after = if line.text == "-" {
                String::new()
            } else {
                line.text[2..].to_string()
            };
            if after.is_empty() {
                let item = self.parse_value(base_indent + 2)?;
                items.push(item);
                continue;
            }
            if let Some((key, rest)) = split_kv(&after) {
                let mut pairs: Vec<(String, YamlValue)> = Vec::new();
                if rest.is_empty() {
                    let nested = self.parse_value(base_indent + 2)?;
                    pairs.push((key.to_string(), nested));
                } else {
                    pairs.push((key.to_string(), parse_inline_value(rest)?));
                }
                while let Some(next) = self.peek().cloned() {
                    if next.indent == base_indent + 2 && next.text.contains(':') {
                        if next.text.starts_with("- ") {
                            break;
                        }
                        self.idx += 1;
                        if let Some((k, r)) = split_kv(&next.text) {
                            if r.is_empty() {
                                let sub = self.parse_value(base_indent + 4)?;
                                pairs.push((k.to_string(), sub));
                            } else if r == "|" || r == ">" {
                                let block = self.collect_block_scalar(base_indent + 2, r == "|");
                                pairs.push((k.to_string(), YamlValue::Str(block)));
                            } else {
                                pairs.push((k.to_string(), parse_inline_value(r)?));
                            }
                            continue;
                        }
                        break;
                    }
                    if next.indent > base_indent + 2 {
                        break;
                    }
                    break;
                }
                items.push(YamlValue::Map(pairs));
                continue;
            }
            items.push(parse_scalar(&after)?);
        }
        Ok(YamlValue::List(items))
    }

    fn parse_map(&mut self, base_indent: usize) -> Result<YamlValue, String> {
        let mut pairs: Vec<(String, YamlValue)> = Vec::new();
        while let Some(line) = self.peek().cloned() {
            if line.indent != base_indent {
                if line.indent < base_indent {
                    break;
                } else {
                    return Err(format!(
                        "line {}: unexpected indent {} in map at base {}",
                        line.lineno + 1,
                        line.indent,
                        base_indent
                    ));
                }
            }
            if line.text.starts_with("- ") || line.text == "-" {
                break;
            }
            let Some((key, rest)) = split_kv(&line.text) else {
                return Err(format!(
                    "line {}: expected 'key: value', got {:?}",
                    line.lineno + 1,
                    line.text
                ));
            };
            self.idx += 1;
            if rest.is_empty() {
                if let Some(next) = self.peek().cloned() {
                    if next.indent > base_indent {
                        let sub = self.parse_value(next.indent)?;
                        pairs.push((key.to_string(), sub));
                        continue;
                    }
                }
                pairs.push((key.to_string(), YamlValue::Null));
                continue;
            }
            if rest == "|" || rest == ">" {
                let block = self.collect_block_scalar(base_indent, rest == "|");
                pairs.push((key.to_string(), YamlValue::Str(block)));
                continue;
            }
            pairs.push((key.to_string(), parse_inline_value(rest)?));
        }
        Ok(YamlValue::Map(pairs))
    }

    fn collect_block_scalar(&mut self, base_indent: usize, literal: bool) -> String {
        let mut sub_indent: Option<usize> = None;
        let mut parts: Vec<String> = Vec::new();
        while let Some(line) = self.peek().cloned() {
            if line.indent <= base_indent {
                break;
            }
            let offset = match sub_indent {
                Some(i) => i,
                None => {
                    sub_indent = Some(line.indent);
                    line.indent
                }
            };
            let effective = if line.indent < offset {
                line.text.clone()
            } else {
                let pad = line.indent - offset;
                format!("{}{}", " ".repeat(pad), line.text)
            };
            parts.push(effective);
            self.idx += 1;
        }
        if literal {
            let mut s = parts.join("\n");
            if !s.is_empty() {
                s.push('\n');
            }
            s
        } else {
            let mut s = parts.join(" ");
            if !s.is_empty() {
                s.push('\n');
            }
            s
        }
    }
}

pub fn split_kv(line: &str) -> Option<(&str, &str)> {
    let mut in_single = false;
    let mut in_double = false;
    let mut brace_depth = 0i32;
    let mut bracket_depth = 0i32;
    let bytes = line.as_bytes();
    for (i, b) in bytes.iter().enumerate() {
        match *b {
            b'\'' if !in_double => in_single = !in_single,
            b'"' if !in_single => in_double = !in_double,
            b'{' if !in_single && !in_double => brace_depth += 1,
            b'}' if !in_single && !in_double => brace_depth -= 1,
            b'[' if !in_single && !in_double => bracket_depth += 1,
            b']' if !in_single && !in_double => bracket_depth -= 1,
            b':' if !in_single && !in_double && brace_depth == 0 && bracket_depth == 0 => {
                let next = bytes.get(i + 1).copied();
                if next.is_none() || next == Some(b' ') {
                    let key_raw = line[..i].trim();
                    let key = unquote(key_raw);
                    let rest = if i + 1 >= line.len() {
                        ""
                    } else {
                        line[i + 1..].trim()
                    };
                    return Some((string_ref(key, key_raw), rest));
                }
            }
            _ => {}
        }
    }
    None
}

fn string_ref<'a>(unq: Option<&'a str>, raw: &'a str) -> &'a str {
    match unq {
        Some(s) => s,
        None => raw,
    }
}

pub fn unquote(s: &str) -> Option<&str> {
    if s.len() >= 2 {
        let bytes = s.as_bytes();
        let first = bytes[0];
        let last = bytes[s.len() - 1];
        if (first == b'"' && last == b'"') || (first == b'\'' && last == b'\'') {
            return Some(&s[1..s.len() - 1]);
        }
    }
    None
}

pub fn parse_scalar(raw: &str) -> Result<YamlValue, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(YamlValue::Null);
    }
    if trimmed == "null" || trimmed == "~" {
        return Ok(YamlValue::Null);
    }
    if trimmed == "true" {
        return Ok(YamlValue::Bool(true));
    }
    if trimmed == "false" {
        return Ok(YamlValue::Bool(false));
    }
    if let Some(inner) = unquote(trimmed) {
        return Ok(YamlValue::Str(inner.to_string()));
    }
    if let Ok(n) = trimmed.parse::<i64>() {
        return Ok(YamlValue::Int(n));
    }
    Ok(YamlValue::Str(trimmed.to_string()))
}

pub fn parse_inline_value(raw: &str) -> Result<YamlValue, String> {
    let trimmed = raw.trim();
    if let Some(inner) = trimmed.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
        return parse_flow_map(inner);
    }
    if let Some(inner) = trimmed.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
        return parse_flow_list(inner);
    }
    parse_scalar(trimmed)
}

fn parse_flow_map(inner: &str) -> Result<YamlValue, String> {
    let items = split_flow_items(inner)?;
    let mut pairs: Vec<(String, YamlValue)> = Vec::new();
    for item in items {
        if item.trim().is_empty() {
            continue;
        }
        let (k, v) =
            split_kv(&item).ok_or_else(|| format!("flow map item missing colon: {item:?}"))?;
        pairs.push((k.to_string(), parse_inline_value(v)?));
    }
    Ok(YamlValue::Map(pairs))
}

fn parse_flow_list(inner: &str) -> Result<YamlValue, String> {
    let items = split_flow_items(inner)?;
    let mut out: Vec<YamlValue> = Vec::new();
    for item in items {
        let t = item.trim();
        if t.is_empty() {
            continue;
        }
        out.push(parse_inline_value(t)?);
    }
    Ok(YamlValue::List(out))
}

fn split_flow_items(inner: &str) -> Result<Vec<String>, String> {
    let mut parts: Vec<String> = Vec::new();
    let mut buf = String::new();
    let mut in_single = false;
    let mut in_double = false;
    let mut brace_depth = 0i32;
    let mut bracket_depth = 0i32;
    for c in inner.chars() {
        match c {
            '\'' if !in_double => {
                in_single = !in_single;
                buf.push(c);
            }
            '"' if !in_single => {
                in_double = !in_double;
                buf.push(c);
            }
            '{' if !in_single && !in_double => {
                brace_depth += 1;
                buf.push(c);
            }
            '}' if !in_single && !in_double => {
                brace_depth -= 1;
                buf.push(c);
            }
            '[' if !in_single && !in_double => {
                bracket_depth += 1;
                buf.push(c);
            }
            ']' if !in_single && !in_double => {
                bracket_depth -= 1;
                buf.push(c);
            }
            ',' if !in_single && !in_double && brace_depth == 0 && bracket_depth == 0 => {
                parts.push(std::mem::take(&mut buf));
            }
            _ => buf.push(c),
        }
    }
    if !buf.is_empty() {
        parts.push(buf);
    }
    Ok(parts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_key_value() {
        let v = parse_yaml("name: CI\n").unwrap();
        assert_eq!(v.get("name").unwrap().as_str(), Some("CI"));
    }

    #[test]
    fn nested_map() {
        let y = parse_yaml("jobs:\n  build:\n    runs-on: ubuntu-latest\n").unwrap();
        let build = y.get("jobs").unwrap().get("build").unwrap();
        assert_eq!(
            build.get("runs-on").unwrap().as_str(),
            Some("ubuntu-latest")
        );
    }

    #[test]
    fn list_of_maps() {
        let y = parse_yaml(
            r#"steps:
  - uses: actions/checkout@v4
  - name: Build
    run: cargo build
"#,
        )
        .unwrap();
        let steps = y.get("steps").unwrap().as_list().unwrap();
        assert_eq!(steps.len(), 2);
        assert_eq!(
            steps[0].get("uses").unwrap().as_str(),
            Some("actions/checkout@v4")
        );
        assert_eq!(steps[1].get("name").unwrap().as_str(), Some("Build"));
    }

    #[test]
    fn multiline_block_literal() {
        let y = parse_yaml(
            r#"run: |
  echo hello
  echo world
"#,
        )
        .unwrap();
        let r = y.get("run").unwrap().as_str().unwrap();
        assert!(r.contains("echo hello\n"));
        assert!(r.contains("echo world\n"));
    }

    #[test]
    fn comment_stripped() {
        let y = parse_yaml("name: CI # comment\n").unwrap();
        assert_eq!(y.get("name").unwrap().as_str(), Some("CI"));
    }

    #[test]
    fn flow_map_single_line() {
        let y = parse_yaml("permissions: {contents: read, pull-requests: write}\n").unwrap();
        let p = y.get("permissions").unwrap();
        assert_eq!(p.get("contents").unwrap().as_str(), Some("read"));
        assert_eq!(p.get("pull-requests").unwrap().as_str(), Some("write"));
    }

    #[test]
    fn flow_list_single_line() {
        let y = parse_yaml("os: [ubuntu-latest, macos-latest, windows-latest]\n").unwrap();
        let l = y.get("os").unwrap().as_list().unwrap();
        assert_eq!(l.len(), 3);
        assert_eq!(l[0].as_str(), Some("ubuntu-latest"));
    }

    #[test]
    fn booleans_and_ints() {
        let y = parse_yaml("continue-on-error: true\nretries: 3\n").unwrap();
        assert_eq!(y.get("continue-on-error").unwrap().as_bool(), Some(true));
        assert_eq!(y.get("retries").unwrap().as_int(), Some(3));
    }

    #[test]
    fn quoted_string_preserves_special_chars() {
        let y = parse_yaml("message: \"hello # world\"\n").unwrap();
        assert_eq!(y.get("message").unwrap().as_str(), Some("hello # world"));
    }

    #[test]
    fn nested_flow_map_in_block() {
        let y = parse_yaml(
            r#"strategy:
  matrix: {os: [ubuntu-latest, macos-latest], toolchain: [stable]}
"#,
        )
        .unwrap();
        let matrix = y.get("strategy").unwrap().get("matrix").unwrap();
        let os = matrix.get("os").unwrap().as_list().unwrap();
        assert_eq!(os.len(), 2);
    }

    #[test]
    fn inconsistent_indent_inside_map_errors() {
        let r = parse_yaml("a: 1\n   b: 2\n");
        assert!(r.is_err(), "expected error, got {:?}", r);
    }
}

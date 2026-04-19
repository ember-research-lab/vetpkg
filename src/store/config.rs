use crate::types::PolicyConfig;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, PartialEq)]
pub enum TomlValue {
    Str(String),
    Int(i64),
    Float(f64),
    Bool(bool),
}

pub fn parse_toml(input: &str) -> Result<HashMap<String, TomlValue>, String> {
    let mut out: HashMap<String, TomlValue> = HashMap::new();
    let mut section = String::new();

    for (lineno, raw) in input.lines().enumerate() {
        let line = strip_comment(raw).trim();
        if line.is_empty() {
            continue;
        }
        if let Some(s) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            section = s.trim().to_string();
            continue;
        }
        let (k, v) = line
            .split_once('=')
            .ok_or_else(|| format!("line {}: expected 'key = value', got {line:?}", lineno + 1))?;
        let key = k.trim().to_string();
        let val =
            parse_value(v.trim()).ok_or_else(|| format!("line {}: bad value {v:?}", lineno + 1))?;
        let full = if section.is_empty() {
            key
        } else {
            format!("{section}.{key}")
        };
        out.insert(full, val);
    }

    Ok(out)
}

fn strip_comment(s: &str) -> &str {
    let mut in_str = false;
    for (i, c) in s.char_indices() {
        match c {
            '"' => in_str = !in_str,
            '#' if !in_str => return &s[..i],
            _ => {}
        }
    }
    s
}

fn parse_value(s: &str) -> Option<TomlValue> {
    if s == "true" {
        return Some(TomlValue::Bool(true));
    }
    if s == "false" {
        return Some(TomlValue::Bool(false));
    }
    if let Some(inner) = s.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
        return Some(TomlValue::Str(unescape(inner)));
    }
    if let Ok(n) = s.parse::<i64>() {
        return Some(TomlValue::Int(n));
    }
    if let Ok(f) = s.parse::<f64>() {
        return Some(TomlValue::Float(f));
    }
    None
}

fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars().peekable();
    while let Some(c) = it.next() {
        if c == '\\' {
            if let Some(&n) = it.peek() {
                it.next();
                match n {
                    'n' => out.push('\n'),
                    't' => out.push('\t'),
                    '"' => out.push('"'),
                    '\\' => out.push('\\'),
                    other => {
                        out.push('\\');
                        out.push(other);
                    }
                }
            } else {
                out.push('\\');
            }
        } else {
            out.push(c);
        }
    }
    out
}

pub fn load_config(path: &Path) -> Result<PolicyConfig, String> {
    let mut cfg = PolicyConfig::default();
    if !path.exists() {
        return Ok(cfg);
    }
    let text = fs::read_to_string(path).map_err(|e| format!("read {:?}: {e}", path))?;
    let map = parse_toml(&text)?;
    if let Some(TomlValue::Int(n)) = map.get("port") {
        cfg.port = *n as u16;
    }
    if let Some(TomlValue::Int(n)) = map.get("timeout_secs") {
        cfg.timeout_secs = *n as u32;
    }
    if let Some(v) = map.get("allow_threshold") {
        cfg.allow_threshold = as_f64(v).unwrap_or(cfg.allow_threshold);
    }
    if let Some(v) = map.get("block_threshold") {
        cfg.block_threshold = as_f64(v).unwrap_or(cfg.block_threshold);
    }
    if let Some(TomlValue::Str(s)) = map.get("upstream.npm") {
        cfg.npm_upstream = s.clone();
    }
    if let Some(TomlValue::Str(s)) = map.get("upstream.pypi") {
        cfg.pypi_upstream = s.clone();
    }
    if let Some(TomlValue::Str(s)) = map.get("upstream.cargo_index") {
        cfg.cargo_index_upstream = s.clone();
    }
    if let Some(TomlValue::Str(s)) = map.get("upstream.cargo_download") {
        cfg.cargo_dl_upstream = s.clone();
    }
    Ok(cfg)
}

fn as_f64(v: &TomlValue) -> Option<f64> {
    match v {
        TomlValue::Float(f) => Some(*f),
        TomlValue::Int(n) => Some(*n as f64),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_basic_types() {
        let t = "a = 1\nb = \"hi\"\nc = true\nd = 2.5\n";
        let m = parse_toml(t).unwrap();
        assert_eq!(m.get("a"), Some(&TomlValue::Int(1)));
        assert_eq!(m.get("b"), Some(&TomlValue::Str("hi".into())));
        assert_eq!(m.get("c"), Some(&TomlValue::Bool(true)));
        assert!(matches!(m.get("d"), Some(TomlValue::Float(f)) if (*f - 2.5).abs() < 1e-9));
    }

    #[test]
    fn sections_qualify_keys() {
        let t = "port = 9451\n[upstream]\nnpm = \"https://x.example\"\n";
        let m = parse_toml(t).unwrap();
        assert_eq!(m.get("port"), Some(&TomlValue::Int(9451)));
        assert_eq!(
            m.get("upstream.npm"),
            Some(&TomlValue::Str("https://x.example".into()))
        );
    }

    #[test]
    fn comments_stripped() {
        let t = "a = 1 # hi\nb = \"a#b\"\n";
        let m = parse_toml(t).unwrap();
        assert_eq!(m.get("a"), Some(&TomlValue::Int(1)));
        assert_eq!(m.get("b"), Some(&TomlValue::Str("a#b".into())));
    }

    #[test]
    fn missing_file_returns_defaults() {
        let cfg = load_config(Path::new("/no/such/file-for-vetpkg-test")).unwrap();
        assert_eq!(cfg.port, PolicyConfig::default().port);
    }
}

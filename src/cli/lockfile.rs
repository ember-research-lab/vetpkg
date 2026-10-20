//! lockfile — hand-written `Cargo.lock` and `uv.lock` front-ends for `vetpkg audit`.
//!
//! Both formats are TOML subsets. This module scans only what the audit needs
//! (the `[[package]]` tables: name, version, source, checksum) with a
//! line-oriented reader and fails loudly on anything it does not understand —
//! an unknown table, an unparseable key line, a missing field, an unsupported
//! lockfile version. It never skips a package silently.

use crate::types::Ecosystem;
use std::collections::BTreeSet;

/// One resolved package from a lockfile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockEntry {
    pub ecosystem: Ecosystem,
    pub name: String,
    pub version: String,
    /// `Some(source)` when the package resolves from somewhere other than the
    /// ecosystem's default public registry (git, alternate registry, URL).
    pub foreign_source: Option<String>,
}

#[derive(Debug, Default)]
struct RawPackage {
    line: usize,
    name: Option<String>,
    version: Option<String>,
    source: Option<String>,
    checksum: Option<String>,
}

#[derive(Debug)]
struct Scan {
    top_version: Option<u64>,
    packages: Vec<RawPackage>,
}

#[derive(PartialEq)]
enum Section {
    Top,
    Package,
    /// A sub-table of the current package (uv: `[package.metadata]`, ...) or
    /// an explicitly ignorable top-level table. Keys are not read.
    Ignored,
}

/// Bracket depth change of one line, ignoring brackets inside strings and
/// anything after a `#` comment.
fn depth_delta(line: &str) -> i32 {
    let mut d = 0;
    let mut in_str = false;
    let mut esc = false;
    for c in line.chars() {
        if in_str {
            if esc {
                esc = false;
            } else if c == '\\' {
                esc = true;
            } else if c == '"' {
                in_str = false;
            }
            continue;
        }
        match c {
            '"' => in_str = true,
            '#' => break,
            '[' | '{' => d += 1,
            ']' | '}' => d -= 1,
            _ => {}
        }
    }
    d
}

fn strip_comment(s: &str) -> &str {
    let mut in_str = false;
    let mut esc = false;
    for (i, c) in s.char_indices() {
        if in_str {
            if esc {
                esc = false;
            } else if c == '\\' {
                esc = true;
            } else if c == '"' {
                in_str = false;
            }
        } else if c == '"' {
            in_str = true;
        } else if c == '#' {
            return &s[..i];
        }
    }
    s
}

fn unquote(raw: &str, what: &str, line: usize) -> Result<String, String> {
    let r = raw.trim();
    if r.len() >= 2 && r.starts_with('"') && r.ends_with('"') {
        let inner = &r[1..r.len() - 1];
        if !inner.contains('"') && !inner.contains('\\') {
            return Ok(inner.to_string());
        }
    }
    Err(format!(
        "line {line}: `{what}` is not a plain quoted string: {r}"
    ))
}

fn is_bare_key(k: &str) -> bool {
    !k.is_empty()
        && k.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// Line-oriented scan. `ignorable` lists table-header prefixes (without
/// brackets) whose contents are skipped; `package_subtables` allows
/// `package.*` headers (uv) as part of the current package.
fn scan(text: &str, ignorable: &[&str], package_subtables: bool) -> Result<Scan, String> {
    let mut out = Scan {
        top_version: None,
        packages: Vec::new(),
    };
    let mut section = Section::Top;
    let mut depth: i32 = 0;
    for (idx, raw_line) in text.lines().enumerate() {
        let lineno = idx + 1;
        let line = strip_comment(raw_line).trim();
        if depth > 0 {
            depth += depth_delta(line);
            if depth < 0 {
                return Err(format!("line {lineno}: unbalanced brackets"));
            }
            continue;
        }
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') {
            let name = line.trim_start_matches('[').trim_end_matches(']').trim();
            if line == "[[package]]" {
                out.packages.push(RawPackage {
                    line: lineno,
                    ..Default::default()
                });
                section = Section::Package;
            } else if (package_subtables && name.starts_with("package."))
                || ignorable
                    .iter()
                    .any(|p| name == *p || name.starts_with(&format!("{p}.")))
            {
                section = Section::Ignored;
            } else {
                return Err(format!("line {lineno}: unsupported table `{line}`"));
            }
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err(format!("line {lineno}: unrecognised line: {line}"));
        };
        let key = key.trim();
        let value = value.trim();
        if !is_bare_key(key) {
            return Err(format!("line {lineno}: unsupported key `{key}`"));
        }
        depth = depth_delta(value);
        if depth < 0 {
            return Err(format!("line {lineno}: unbalanced brackets"));
        }
        match section {
            Section::Top if key == "version" => {
                let v: u64 = value
                    .parse()
                    .map_err(|_| format!("line {lineno}: lockfile `version` is not an integer"))?;
                out.top_version = Some(v);
            }
            Section::Package => {
                let pkg = out.packages.last_mut().expect("package section has entry");
                match key {
                    "name" => pkg.name = Some(unquote(value, key, lineno)?),
                    "version" => pkg.version = Some(unquote(value, key, lineno)?),
                    "checksum" => pkg.checksum = Some(unquote(value, key, lineno)?),
                    // Cargo: quoted string; uv: inline table (kept raw).
                    "source" => pkg.source = Some(value.to_string()),
                    _ => {}
                }
            }
            _ => {}
        }
    }
    if depth != 0 {
        return Err("unterminated array or inline table at end of file".into());
    }
    Ok(out)
}

fn finish<F>(scan: Scan, eco: Ecosystem, mut each: F) -> Result<Vec<LockEntry>, String>
where
    F: FnMut(&RawPackage, &str) -> Result<Option<(String, Option<String>)>, String>,
{
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for p in &scan.packages {
        let name = p
            .name
            .clone()
            .ok_or_else(|| format!("line {}: [[package]] without a name", p.line))?;
        if let Some((version, foreign_source)) = each(p, &name)? {
            if seen.insert((name.clone(), version.clone())) {
                out.push(LockEntry {
                    ecosystem: eco,
                    name,
                    version,
                    foreign_source,
                });
            }
        }
    }
    Ok(out)
}

const CARGO_DEFAULT_SOURCES: [&str; 2] = [
    "registry+https://github.com/rust-lang/crates.io-index",
    "sparse+https://index.crates.io/",
];

/// Parse a `Cargo.lock` (lockfile versions 3 and 4). Returns the lockfile
/// version and the packages, including the workspace's own crates.
pub fn parse_cargo_lock(text: &str) -> Result<(u64, Vec<LockEntry>), String> {
    let scan = scan(text, &["patch.unused"], false)?;
    let version = scan.top_version.ok_or(
        "Cargo.lock has no top-level `version` (pre-v3 lockfile; run `cargo generate-lockfile`)",
    )?;
    if version != 3 && version != 4 {
        return Err(format!(
            "unsupported Cargo.lock version {version} (supported: 3, 4)"
        ));
    }
    let entries = finish(scan, Ecosystem::Cargo, |p, name| {
        let version = p
            .version
            .clone()
            .ok_or_else(|| format!("line {}: package `{name}` has no version", p.line))?;
        let source = match &p.source {
            None => None, // workspace member or path dependency
            Some(raw) => Some(unquote(raw, "source", p.line)?),
        };
        let foreign = match source {
            Some(s) if CARGO_DEFAULT_SOURCES.contains(&s.as_str()) => {
                if p.checksum.is_none() {
                    return Err(format!(
                        "line {}: registry package `{name}` {version} has no checksum",
                        p.line
                    ));
                }
                None
            }
            Some(s) => Some(s),
            None => None,
        };
        Ok(Some((version, foreign)))
    })?;
    Ok((version, entries))
}

/// Registry URL prefixes treated as the default PyPI index in `uv.lock`.
const PYPI_DEFAULT_REGISTRIES: [&str; 2] = ["https://pypi.org/simple", "https://pypi.org/simple/"];

/// Parse a `uv.lock` (lockfile version 1). Local project packages with no
/// version (virtual/editable roots with dynamic versions) are skipped; every
/// other package must carry a version.
pub fn parse_uv_lock(text: &str) -> Result<(u64, Vec<LockEntry>), String> {
    let scan = scan(text, &["manifest", "options"], true)?;
    let version = scan
        .top_version
        .ok_or("uv.lock has no top-level `version`")?;
    if version != 1 {
        return Err(format!(
            "unsupported uv.lock version {version} (supported: 1)"
        ));
    }
    let entries = finish(scan, Ecosystem::PyPI, |p, name| {
        let raw = p
            .source
            .as_deref()
            .ok_or_else(|| format!("line {}: package `{name}` has no source", p.line))?;
        let inner = raw
            .trim()
            .strip_prefix('{')
            .and_then(|r| r.strip_suffix('}'))
            .ok_or_else(|| {
                format!(
                    "line {}: package `{name}` source is not an inline table: {raw}",
                    p.line
                )
            })?
            .trim();
        let (kind, rest) = inner
            .split_once('=')
            .ok_or_else(|| format!("line {}: package `{name}` source has no key: {raw}", p.line))?;
        let kind = kind.trim();
        let target = unquote(rest.split(',').next().unwrap_or(""), kind, p.line)?;
        let local = matches!(kind, "virtual" | "editable" | "directory" | "path");
        let Some(version) = p.version.clone() else {
            if local {
                return Ok(None);
            }
            return Err(format!("line {}: package `{name}` has no version", p.line));
        };
        let foreign = match kind {
            "registry" if PYPI_DEFAULT_REGISTRIES.contains(&target.as_str()) => None,
            "virtual" | "editable" | "directory" | "path" => None,
            "registry" | "git" | "url" => Some(format!("{kind}: {target}")),
            other => {
                return Err(format!(
                    "line {}: package `{name}` has unsupported source kind `{other}`",
                    p.line
                ))
            }
        };
        Ok(Some((version, foreign)))
    })?;
    Ok((version, entries))
}

#[cfg(test)]
mod tests {
    use super::*;

    const CARGO_ZERO_DEPS: &str =
        include_str!("../../tests/fixtures/lockfiles/cargo-zero-deps.lock");
    const CARGO_DEPS: &str = include_str!("../../tests/fixtures/lockfiles/cargo-deps.lock");
    const UV: &str = include_str!("../../tests/fixtures/lockfiles/uv.lock");

    #[test]
    fn cargo_zero_deps_lists_only_the_crate() {
        let (v, e) = parse_cargo_lock(CARGO_ZERO_DEPS).unwrap();
        assert_eq!(v, 3);
        assert_eq!(e.len(), 1);
        assert_eq!(
            (e[0].name.as_str(), e[0].version.as_str()),
            ("ember-network", "0.0.1")
        );
        assert!(e[0].foreign_source.is_none());
    }

    #[test]
    fn cargo_with_deps_parses_registry_and_git() {
        let (v, e) = parse_cargo_lock(CARGO_DEPS).unwrap();
        assert_eq!(v, 4);
        let names: Vec<_> = e.iter().map(|x| x.name.as_str()).collect();
        assert_eq!(
            names,
            ["demo", "libc", "serde", "serde_derive", "weird-git"]
        );
        assert!(e.iter().filter(|x| x.foreign_source.is_some()).count() == 1);
        assert!(e[4].foreign_source.as_deref().unwrap().starts_with("git+"));
    }

    #[test]
    fn cargo_rejects_old_unknown_and_malformed() {
        assert!(parse_cargo_lock("[[package]]\nname = \"a\"\nversion = \"1\"\n").is_err());
        assert!(parse_cargo_lock("version = 9\n")
            .unwrap_err()
            .contains("unsupported"));
        assert!(parse_cargo_lock("version = 3\n[surprise]\n")
            .unwrap_err()
            .contains("unsupported table"));
        assert!(
            parse_cargo_lock("version = 3\n[[package]]\nversion = \"1\"\n")
                .unwrap_err()
                .contains("without a name")
        );
        let no_sum = "version = 3\n[[package]]\nname = \"a\"\nversion = \"1\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n";
        assert!(parse_cargo_lock(no_sum).unwrap_err().contains("checksum"));
        assert!(
            parse_cargo_lock("version = 3\n[[package]]\nname = \"a\"\ndependencies = [\n").is_err()
        );
    }

    #[test]
    fn uv_lock_parses_packages_and_skips_virtual_root() {
        let (v, e) = parse_uv_lock(UV).unwrap();
        assert_eq!(v, 1);
        let names: Vec<_> = e
            .iter()
            .map(|x| (x.name.as_str(), x.version.as_str()))
            .collect();
        assert_eq!(
            names,
            [
                ("anyio", "4.11.0"),
                ("idna", "3.10"),
                ("mcp", "1.22.0"),
                ("sneaky", "0.1.0")
            ]
        );
        assert!(e.iter().all(|x| x.ecosystem == Ecosystem::PyPI));
        assert_eq!(e.iter().filter(|x| x.foreign_source.is_some()).count(), 1);
    }

    #[test]
    fn uv_rejects_bad_version_and_unknown_table() {
        assert!(parse_uv_lock("version = 2\n")
            .unwrap_err()
            .contains("unsupported"));
        assert!(parse_uv_lock("version = 1\n[nope]\n")
            .unwrap_err()
            .contains("unsupported table"));
        let nover = "version = 1\n[[package]]\nname = \"a\"\nsource = { registry = \"https://pypi.org/simple\" }\n";
        assert!(parse_uv_lock(nover).unwrap_err().contains("no version"));
    }
}

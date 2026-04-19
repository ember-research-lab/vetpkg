//! File-content manifest with per-version caching.
//!
//! Walks an extracted tarball and records (relative_path, sha256) for every
//! file whose extension maps to a known language via
//! analysis::pattern::Language. Only those files feed the Tier 2 pattern
//! matcher.
//!
//! "Changed files" are computed by comparing against the prior version's
//! manifest. The comparison also reports whether >80% of files changed, in
//! which case the caller should suppress "new-in-version" bonuses
//! (wholesale-repackaging guard from the plan resolutions).

use crate::analysis::pattern::Language;
use crate::crypto::sha256::sha256_hex;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

pub const WHOLESALE_REPACKAGE_THRESHOLD: f64 = 0.80;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FileManifest {
    pub files: Vec<(String, String)>,
}

impl FileManifest {
    pub fn lookup(&self, path: &str) -> Option<&str> {
        self.files
            .iter()
            .find(|(p, _)| p == path)
            .map(|(_, h)| h.as_str())
    }
}

#[derive(Debug, Clone)]
pub struct ChangedFile {
    pub rel_path: String,
    pub abs_path: PathBuf,
    pub language: Language,
    pub content: String,
    pub sha256: String,
    pub previously_existed: bool,
}

#[derive(Debug, Clone)]
pub struct DiffReport {
    pub changed: Vec<ChangedFile>,
    pub manifest: FileManifest,
    pub total_analyzed_files: usize,
    pub is_wholesale_repackage: bool,
}

pub fn scan(root: &Path, prior: &FileManifest) -> std::io::Result<DiffReport> {
    let mut manifest = FileManifest::default();
    let mut changed: Vec<ChangedFile> = Vec::new();
    let prior_lookup: HashMap<&str, &str> = prior
        .files
        .iter()
        .map(|(p, h)| (p.as_str(), h.as_str()))
        .collect();

    let mut total_analyzed = 0usize;
    let mut changed_count = 0usize;

    walk(root, root, &mut |rel_path, abs_path| {
        let Some(ext) = abs_path
            .extension()
            .and_then(|e| e.to_str())
            .map(|s| s.to_string())
        else {
            return Ok(());
        };
        let Some(language) = Language::from_extension(&ext) else {
            return Ok(());
        };
        let Ok(bytes) = fs::read(abs_path) else {
            return Ok(());
        };
        let Ok(content) = String::from_utf8(bytes.clone()) else {
            return Ok(());
        };
        let hash = sha256_hex(&bytes);
        manifest.files.push((rel_path.to_string(), hash.clone()));
        total_analyzed += 1;

        let previously_existed = prior_lookup.contains_key(rel_path);
        let changed_flag = match prior_lookup.get(rel_path) {
            Some(prev_hash) => prev_hash != &hash.as_str(),
            None => true,
        };
        if changed_flag {
            changed_count += 1;
            changed.push(ChangedFile {
                rel_path: rel_path.to_string(),
                abs_path: abs_path.to_path_buf(),
                language,
                content,
                sha256: hash,
                previously_existed,
            });
        }
        Ok(())
    })?;

    let ratio = if total_analyzed == 0 {
        0.0
    } else {
        changed_count as f64 / total_analyzed as f64
    };
    let is_wholesale_repackage = !prior.files.is_empty() && ratio > WHOLESALE_REPACKAGE_THRESHOLD;

    manifest.files.sort_by(|a, b| a.0.cmp(&b.0));

    Ok(DiffReport {
        changed,
        manifest,
        total_analyzed_files: total_analyzed,
        is_wholesale_repackage,
    })
}

fn walk<F>(root: &Path, path: &Path, cb: &mut F) -> std::io::Result<()>
where
    F: FnMut(&str, &Path) -> std::io::Result<()>,
{
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let abs = entry.path();
        if abs.is_dir() {
            walk(root, &abs, cb)?;
            continue;
        }
        if let Ok(rel) = abs.strip_prefix(root) {
            let rel_str = rel.to_string_lossy().replace('\\', "/");
            cb(&rel_str, &abs)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::TempDir;

    fn write(root: &Path, rel: &str, content: &str) {
        let p = root.join(rel);
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&p, content).unwrap();
    }

    #[test]
    fn first_scan_reports_every_file_as_changed() {
        let td = TempDir::new("manifest-first").unwrap();
        write(td.path(), "src/a.js", "const x = 1;\n");
        write(td.path(), "lib/b.ts", "export const y = 2;\n");
        write(td.path(), "README.md", "# readme");
        let r = scan(td.path(), &FileManifest::default()).unwrap();
        assert_eq!(r.changed.len(), 2);
        assert_eq!(r.total_analyzed_files, 2);
        assert!(!r.is_wholesale_repackage);
    }

    #[test]
    fn unchanged_file_is_not_reported() {
        let td = TempDir::new("manifest-unchanged").unwrap();
        let content = "const x = 1;\n";
        write(td.path(), "src/a.js", content);
        let bytes = content.as_bytes();
        let prior = FileManifest {
            files: vec![("src/a.js".into(), sha256_hex(bytes))],
        };
        let r = scan(td.path(), &prior).unwrap();
        assert!(r.changed.is_empty());
    }

    #[test]
    fn mixed_changed_and_unchanged() {
        let td = TempDir::new("manifest-mixed").unwrap();
        write(td.path(), "src/a.js", "const x = 1;\n");
        write(td.path(), "src/b.js", "const y = 2;\n");
        let prior = FileManifest {
            files: vec![
                ("src/a.js".into(), sha256_hex(b"const x = 1;\n")),
                ("src/b.js".into(), "deadbeef".into()),
            ],
        };
        let r = scan(td.path(), &prior).unwrap();
        assert_eq!(r.changed.len(), 1);
        assert_eq!(r.changed[0].rel_path, "src/b.js");
        assert!(r.changed[0].previously_existed);
    }

    #[test]
    fn wholesale_repackage_flagged_above_80pct() {
        let td = TempDir::new("manifest-whole").unwrap();
        for i in 0..10 {
            write(
                td.path(),
                &format!("src/f{i}.js"),
                &format!("new version {i}\n"),
            );
        }
        let prior = FileManifest {
            files: (0..10)
                .map(|i| {
                    (
                        format!("src/f{i}.js"),
                        sha256_hex(format!("old version {i}\n").as_bytes()),
                    )
                })
                .collect(),
        };
        let r = scan(td.path(), &prior).unwrap();
        assert!(r.is_wholesale_repackage);
    }

    #[test]
    fn small_change_not_flagged_as_wholesale() {
        let td = TempDir::new("manifest-small").unwrap();
        for i in 0..10 {
            let c = if i == 0 { "new\n" } else { "same\n" };
            write(td.path(), &format!("src/f{i}.js"), c);
        }
        let prior = FileManifest {
            files: (0..10)
                .map(|i| (format!("src/f{i}.js"), sha256_hex(b"same\n")))
                .collect(),
        };
        let r = scan(td.path(), &prior).unwrap();
        assert!(!r.is_wholesale_repackage);
        assert_eq!(r.changed.len(), 1);
    }

    #[test]
    fn non_language_files_ignored() {
        let td = TempDir::new("manifest-nonlang").unwrap();
        write(td.path(), "assets/logo.png", "binary");
        write(td.path(), "docs/README.md", "text");
        let r = scan(td.path(), &FileManifest::default()).unwrap();
        assert_eq!(r.total_analyzed_files, 0);
        assert!(r.changed.is_empty());
    }
}

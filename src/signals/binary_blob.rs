//! BinaryBlobDetection: Tier 1 signal on extracted tarball contents.
//!
//! Scans every non-code file in the extraction directory, computes Shannon
//! entropy, flags per the scoring rules:
//!   - New high-entropy file (>7.0 b/B) in test*/ or fixtures*/ dir → 0.25
//!   - New high-entropy file elsewhere                              → 0.15
//!   - Compressed-within-compressed (.xz/.gz/.bz2/.zip/.7z/.lz/.zst) → 0.20
//!   - Changed content of existing high-entropy file                → 0.10
//!
//! Score is additive but capped at 0.50 (enforced by caller via weight cap).
//! A blob is considered "new" if its path does not appear in the prior
//! BlobInventory. "Changed" means path present but sha256 differs.
//!
//! The `.svg` extension is intentionally NOT on the code-file allowlist
//! because SVGs can embed JavaScript.

use crate::analysis::entropy::shannon_entropy;
use crate::crypto::sha256::{sha256_hex, Sha256};
use crate::types::{BlobKind, Signal};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

pub const ENTROPY_THRESHOLD: f64 = 7.0;

pub const CODE_EXTENSIONS: &[&str] = &[
    "js",
    "mjs",
    "cjs",
    "ts",
    "tsx",
    "jsx",
    "py",
    "rs",
    "c",
    "h",
    "cpp",
    "hpp",
    "go",
    "java",
    "rb",
    "php",
    "swift",
    "kt",
    "scala",
    "sh",
    "bash",
    "zsh",
    "fish",
    "json",
    "yaml",
    "yml",
    "toml",
    "xml",
    "html",
    "css",
    "scss",
    "less",
    "md",
    "txt",
    "rst",
    "csv",
    "sql",
    "graphql",
    "proto",
    "lock",
    "gitignore",
    "eslintrc",
    "prettierrc",
    "editorconfig",
];

pub const CODE_BASENAMES: &[&str] = &[
    "LICENSE",
    "LICENSE.md",
    "LICENSE.txt",
    "README",
    "README.md",
    "CHANGELOG",
    "CHANGELOG.md",
    "Makefile",
    "Dockerfile",
    "Cargo.toml",
    "package.json",
    "tsconfig.json",
    ".npmignore",
    ".gitattributes",
];

pub const COMPRESSED_EXTENSIONS: &[&str] = &["xz", "gz", "bz2", "zip", "7z", "lz", "zst", "rar"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobEntry {
    pub path: String,
    pub sha256: String,
    pub size: u64,
}

#[derive(Debug, Clone, Default)]
pub struct BlobInventory {
    pub blobs: Vec<BlobEntry>,
}

impl BlobInventory {
    pub fn lookup(&self, path: &str) -> Option<&BlobEntry> {
        self.blobs.iter().find(|b| b.path == path)
    }
}

pub fn is_code_file(path: &Path) -> bool {
    if let Some(fname) = path.file_name().and_then(|n| n.to_str()) {
        if CODE_BASENAMES.contains(&fname) {
            return true;
        }
    }
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    CODE_EXTENSIONS.contains(&ext.to_ascii_lowercase().as_str())
}

pub fn is_compressed_extension(path: &Path) -> bool {
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    COMPRESSED_EXTENSIONS.contains(&ext.to_ascii_lowercase().as_str())
}

pub fn is_in_test_dir(rel_path: &str) -> bool {
    let lower = rel_path.to_ascii_lowercase();
    let components: Vec<&str> = lower.split('/').collect();
    components.iter().any(|c| {
        c.starts_with("test")
            || c.starts_with("fixture")
            || c == &"testdata"
            || c == &"__fixtures__"
    })
}

pub struct ScanResult {
    pub signals: Vec<Signal>,
    pub inventory: BlobInventory,
}

pub fn scan_dir(root: &Path, prior: &BlobInventory) -> std::io::Result<ScanResult> {
    let mut inventory = BlobInventory::default();
    let mut signals: Vec<Signal> = Vec::new();
    let prior_lookup: HashMap<&str, &BlobEntry> =
        prior.blobs.iter().map(|b| (b.path.as_str(), b)).collect();

    walk(root, root, &mut |rel_path, abs_path| {
        let metadata = fs::metadata(abs_path)?;
        if !metadata.is_file() {
            return Ok(());
        }
        if is_code_file(Path::new(rel_path)) {
            return Ok(());
        }
        let size = metadata.len();
        let (hash, entropy) = hash_and_entropy(abs_path)?;
        inventory.blobs.push(BlobEntry {
            path: rel_path.to_string(),
            sha256: hash.clone(),
            size,
        });

        let compressed = is_compressed_extension(Path::new(rel_path));
        let high_entropy = entropy > ENTROPY_THRESHOLD;
        let in_test = is_in_test_dir(rel_path);

        match prior_lookup.get(rel_path) {
            None => {
                if compressed {
                    signals.push(Signal::BinaryBlobDetection {
                        kind: BlobKind::CompressedInsideTarball,
                        path: rel_path.into(),
                        detail: format!("new compressed file size={size}"),
                    });
                }
                if high_entropy {
                    let kind = if in_test {
                        BlobKind::NewHighEntropyInTestDir
                    } else {
                        BlobKind::NewHighEntropyElsewhere
                    };
                    signals.push(Signal::BinaryBlobDetection {
                        kind,
                        path: rel_path.into(),
                        detail: format!("entropy={entropy:.2} size={size}"),
                    });
                }
            }
            Some(prev) => {
                if prev.sha256 != hash && high_entropy {
                    signals.push(Signal::BinaryBlobDetection {
                        kind: BlobKind::ChangedExistingBlob,
                        path: rel_path.into(),
                        detail: format!(
                            "sha256 {}→{} entropy={entropy:.2}",
                            &prev.sha256[..8.min(prev.sha256.len())],
                            &hash[..8.min(hash.len())]
                        ),
                    });
                }
            }
        }
        Ok(())
    })?;

    Ok(ScanResult { signals, inventory })
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

fn hash_and_entropy(path: &Path) -> std::io::Result<(String, f64)> {
    let data = fs::read(path)?;
    let hash = sha256_hex(&data);
    let _ = Sha256::new();
    let entropy = shannon_entropy(&data);
    Ok((hash, entropy))
}

pub fn total_blob_score(signals: &[Signal]) -> f64 {
    let sum: f64 = signals
        .iter()
        .filter(|s| matches!(s, Signal::BinaryBlobDetection { .. }))
        .map(|s| s.weight())
        .sum();
    sum.min(0.50)
}

pub fn inventory_paths(inv: &BlobInventory) -> Vec<PathBuf> {
    inv.blobs.iter().map(|b| PathBuf::from(&b.path)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::TempDir;

    fn write(root: &Path, rel: &str, data: &[u8]) {
        let p = root.join(rel);
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&p, data).unwrap();
    }

    fn random_bytes(n: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(n);
        let mut state: u64 = 0x123456789abcdef0;
        while out.len() < n {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            out.extend_from_slice(&state.to_le_bytes());
        }
        out.truncate(n);
        out
    }

    #[test]
    fn low_entropy_zeros_not_flagged() {
        let td = TempDir::new("blob-zero").unwrap();
        write(td.path(), "asset.bin", &vec![0u8; 2048]);
        let r = scan_dir(td.path(), &BlobInventory::default()).unwrap();
        assert!(r.signals.is_empty(), "{:?}", r.signals);
    }

    #[test]
    fn high_entropy_blob_flags_by_location() {
        let td = TempDir::new("blob-hi").unwrap();
        write(td.path(), "tests/data/payload.bin", &random_bytes(4096));
        write(td.path(), "assets/payload.bin", &random_bytes(4096));
        let r = scan_dir(td.path(), &BlobInventory::default()).unwrap();
        assert!(r.signals.iter().any(|s| matches!(
            s,
            Signal::BinaryBlobDetection {
                kind: BlobKind::NewHighEntropyInTestDir,
                ..
            }
        )));
        assert!(r.signals.iter().any(|s| matches!(
            s,
            Signal::BinaryBlobDetection {
                kind: BlobKind::NewHighEntropyElsewhere,
                ..
            }
        )));
    }

    #[test]
    fn code_files_not_entropy_scanned() {
        let td = TempDir::new("blob-code").unwrap();
        write(td.path(), "src/minified.js", &random_bytes(8192));
        let r = scan_dir(td.path(), &BlobInventory::default()).unwrap();
        assert!(r.signals.is_empty(), "{:?}", r.signals);
    }

    #[test]
    fn compressed_extension_flags_even_if_low_entropy() {
        let td = TempDir::new("blob-compressed").unwrap();
        write(td.path(), "tests/files/bad.xz", &vec![0u8; 1024]);
        let r = scan_dir(td.path(), &BlobInventory::default()).unwrap();
        assert!(r.signals.iter().any(|s| matches!(
            s,
            Signal::BinaryBlobDetection {
                kind: BlobKind::CompressedInsideTarball,
                ..
            }
        )));
    }

    #[test]
    fn changed_existing_blob_flags() {
        let td = TempDir::new("blob-changed").unwrap();
        write(td.path(), "assets/thing.bin", &random_bytes(2048));
        let prior = BlobInventory {
            blobs: vec![BlobEntry {
                path: "assets/thing.bin".into(),
                sha256: "abcdef1234567890".into(),
                size: 2048,
            }],
        };
        let r = scan_dir(td.path(), &prior).unwrap();
        assert!(r.signals.iter().any(|s| matches!(
            s,
            Signal::BinaryBlobDetection {
                kind: BlobKind::ChangedExistingBlob,
                ..
            }
        )));
    }

    #[test]
    fn unchanged_existing_blob_does_not_flag() {
        let td = TempDir::new("blob-same").unwrap();
        let bytes = random_bytes(2048);
        write(td.path(), "assets/thing.bin", &bytes);
        let hash = sha256_hex(&bytes);
        let prior = BlobInventory {
            blobs: vec![BlobEntry {
                path: "assets/thing.bin".into(),
                sha256: hash,
                size: 2048,
            }],
        };
        let r = scan_dir(td.path(), &prior).unwrap();
        assert!(r.signals.is_empty(), "{:?}", r.signals);
    }

    #[test]
    fn xz_scenario_reaches_target_score() {
        let td = TempDir::new("blob-xz").unwrap();
        write(td.path(), "tests/files/bad-corrupt.xz", &random_bytes(8192));
        write(td.path(), "src/main.rs", b"fn main() {}\n");
        let r = scan_dir(td.path(), &BlobInventory::default()).unwrap();
        let score = total_blob_score(&r.signals);
        assert!(score >= 0.45, "score was {score}, signals {:?}", r.signals);
    }

    #[test]
    fn total_blob_score_caps_at_0_5() {
        let signals = vec![
            Signal::BinaryBlobDetection {
                kind: BlobKind::NewHighEntropyInTestDir,
                path: "a".into(),
                detail: String::new(),
            },
            Signal::BinaryBlobDetection {
                kind: BlobKind::NewHighEntropyInTestDir,
                path: "b".into(),
                detail: String::new(),
            },
            Signal::BinaryBlobDetection {
                kind: BlobKind::CompressedInsideTarball,
                path: "c".into(),
                detail: String::new(),
            },
        ];
        assert_eq!(total_blob_score(&signals), 0.50);
    }
}

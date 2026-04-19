//! Persisted cross-ecosystem indexes consumed by the correlation engine.
//!
//! MaintainerIndex (email → [(ecosystem, package, last_seen, last_score)])
//!   LRU-capped at MAX_MAINTAINER_ENTRIES (10,000) by oldest last_seen.
//!
//! NameIndex (package_name → [(ecosystem, last_seen, last_score)])
//!   Unbounded per-name but entries older than NAME_RETENTION are pruned
//!   on insert/save. Typical churn is tiny.
//!
//! UrlIndex ((ecosystem, package) → Vec<(url, last_seen)>)
//!   Stores the URLs extracted from sink-matched lines during Tier 2. Used
//!   to answer "same URL across packages within 7 days".

use crate::json::{parse, to_json_string, JsonValue};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const MAX_MAINTAINER_ENTRIES: usize = 10_000;
pub const NAME_RETENTION: Duration = Duration::from_secs(14 * 24 * 3600);
pub const URL_RETENTION: Duration = Duration::from_secs(14 * 24 * 3600);

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Debug, Clone, PartialEq)]
pub struct MaintainerEntry {
    pub ecosystem: String,
    pub package: String,
    pub last_seen: u64,
    pub last_score: f64,
}

#[derive(Debug, Clone, Default)]
pub struct MaintainerIndex {
    by_email: HashMap<String, Vec<MaintainerEntry>>,
}

impl MaintainerIndex {
    pub fn len(&self) -> usize {
        self.by_email.values().map(|v| v.len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn upsert(&mut self, email: &str, ecosystem: &str, package: &str, score: f64, when: u64) {
        let entries = self.by_email.entry(email.to_string()).or_default();
        if let Some(existing) = entries
            .iter_mut()
            .find(|e| e.ecosystem == ecosystem && e.package == package)
        {
            existing.last_seen = when.max(existing.last_seen);
            existing.last_score = score;
        } else {
            entries.push(MaintainerEntry {
                ecosystem: ecosystem.to_string(),
                package: package.to_string(),
                last_seen: when,
                last_score: score,
            });
        }
        self.evict_if_needed();
    }

    fn evict_if_needed(&mut self) {
        let total = self.len();
        if total <= MAX_MAINTAINER_ENTRIES {
            return;
        }
        let mut all: Vec<(String, usize, u64)> = Vec::with_capacity(total);
        for (email, entries) in &self.by_email {
            for (idx, e) in entries.iter().enumerate() {
                all.push((email.clone(), idx, e.last_seen));
            }
        }
        all.sort_by_key(|(_, _, ts)| *ts);
        let to_remove = total - MAX_MAINTAINER_ENTRIES;
        let mut removals: HashMap<String, Vec<usize>> = HashMap::new();
        for (email, idx, _) in all.into_iter().take(to_remove) {
            removals.entry(email).or_default().push(idx);
        }
        for (email, mut indices) in removals {
            indices.sort_unstable_by(|a, b| b.cmp(a));
            if let Some(entries) = self.by_email.get_mut(&email) {
                for idx in indices {
                    if idx < entries.len() {
                        entries.swap_remove(idx);
                    }
                }
                if entries.is_empty() {
                    self.by_email.remove(&email);
                }
            }
        }
    }

    pub fn packages_for(&self, email: &str) -> impl Iterator<Item = &MaintainerEntry> {
        self.by_email
            .get(email)
            .map(|v| v.iter())
            .unwrap_or_else(|| [].iter())
    }

    pub fn load(path: &Path) -> Self {
        let Ok(text) = fs::read_to_string(path) else {
            return Self::default();
        };
        let Ok(v) = parse(&text) else {
            return Self::default();
        };
        let Some(obj) = v.as_object() else {
            return Self::default();
        };
        let mut idx = Self::default();
        for (email, arr_v) in obj {
            if let Some(arr) = arr_v.as_array() {
                let mut entries: Vec<MaintainerEntry> = Vec::new();
                for item in arr {
                    let Some(eco) = item.get("ecosystem").and_then(|s| s.as_str()) else {
                        continue;
                    };
                    let Some(pkg) = item.get("package").and_then(|s| s.as_str()) else {
                        continue;
                    };
                    let Some(ls) = item.get("last_seen").and_then(|n| n.as_f64()) else {
                        continue;
                    };
                    let score = item
                        .get("last_score")
                        .and_then(|n| n.as_f64())
                        .unwrap_or(0.0);
                    entries.push(MaintainerEntry {
                        ecosystem: eco.to_string(),
                        package: pkg.to_string(),
                        last_seen: ls as u64,
                        last_score: score,
                    });
                }
                if !entries.is_empty() {
                    idx.by_email.insert(email.clone(), entries);
                }
            }
        }
        idx
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|e| format!("mkdir {:?}: {e}", parent))?;
            }
        }
        let mut obj: Vec<(String, JsonValue)> = Vec::with_capacity(self.by_email.len());
        for (email, entries) in &self.by_email {
            let arr: Vec<JsonValue> = entries
                .iter()
                .map(|e| {
                    JsonValue::Object(vec![
                        ("ecosystem".into(), JsonValue::Str(e.ecosystem.clone())),
                        ("package".into(), JsonValue::Str(e.package.clone())),
                        ("last_seen".into(), JsonValue::Number(e.last_seen as f64)),
                        ("last_score".into(), JsonValue::Number(e.last_score)),
                    ])
                })
                .collect();
            obj.push((email.clone(), JsonValue::Array(arr)));
        }
        obj.sort_by(|a, b| a.0.cmp(&b.0));
        let json = to_json_string(&JsonValue::Object(obj));
        let tmp = path.with_extension("tmp");
        fs::write(&tmp, json).map_err(|e| format!("write {:?}: {e}", tmp))?;
        fs::rename(&tmp, path).map_err(|e| format!("rename {:?}->{:?}: {e}", tmp, path))?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct NameEntry {
    pub ecosystem: String,
    pub last_seen: u64,
    pub last_score: f64,
}

#[derive(Debug, Clone, Default)]
pub struct NameIndex {
    by_name: HashMap<String, Vec<NameEntry>>,
}

impl NameIndex {
    pub fn upsert(&mut self, package: &str, ecosystem: &str, score: f64, when: u64) {
        let entries = self.by_name.entry(package.to_string()).or_default();
        if let Some(existing) = entries.iter_mut().find(|e| e.ecosystem == ecosystem) {
            existing.last_seen = when.max(existing.last_seen);
            existing.last_score = score;
        } else {
            entries.push(NameEntry {
                ecosystem: ecosystem.to_string(),
                last_seen: when,
                last_score: score,
            });
        }
        self.prune_stale();
    }

    fn prune_stale(&mut self) {
        let threshold = now_unix().saturating_sub(NAME_RETENTION.as_secs());
        for entries in self.by_name.values_mut() {
            entries.retain(|e| e.last_seen >= threshold);
        }
        self.by_name.retain(|_, v| !v.is_empty());
    }

    pub fn entries_for(&self, package: &str) -> impl Iterator<Item = &NameEntry> {
        self.by_name
            .get(package)
            .map(|v| v.iter())
            .unwrap_or_else(|| [].iter())
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct UrlEntry {
    pub ecosystem: String,
    pub package: String,
    pub last_seen: u64,
}

#[derive(Debug, Clone, Default)]
pub struct UrlIndex {
    by_url: HashMap<String, Vec<UrlEntry>>,
}

impl UrlIndex {
    pub fn upsert(&mut self, url: &str, ecosystem: &str, package: &str, when: u64) {
        let entries = self.by_url.entry(url.to_string()).or_default();
        if let Some(existing) = entries
            .iter_mut()
            .find(|e| e.ecosystem == ecosystem && e.package == package)
        {
            existing.last_seen = when.max(existing.last_seen);
        } else {
            entries.push(UrlEntry {
                ecosystem: ecosystem.to_string(),
                package: package.to_string(),
                last_seen: when,
            });
        }
        self.prune_stale();
    }

    fn prune_stale(&mut self) {
        let threshold = now_unix().saturating_sub(URL_RETENTION.as_secs());
        for entries in self.by_url.values_mut() {
            entries.retain(|e| e.last_seen >= threshold);
        }
        self.by_url.retain(|_, v| !v.is_empty());
    }

    pub fn seen_elsewhere<'a>(
        &'a self,
        url: &str,
        ecosystem: &'a str,
        package: &'a str,
    ) -> impl Iterator<Item = &'a UrlEntry> {
        self.by_url
            .get(url)
            .map(|v| v.iter())
            .unwrap_or_else(|| [].iter())
            .filter(move |e| !(e.ecosystem == ecosystem && e.package == package))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::TempDir;

    #[test]
    fn maintainer_upsert_dedupes_same_package() {
        let mut idx = MaintainerIndex::default();
        idx.upsert("a@x.co", "npm", "foo", 0.4, 1_000);
        idx.upsert("a@x.co", "npm", "foo", 0.5, 2_000);
        assert_eq!(idx.len(), 1);
        let entry = idx.packages_for("a@x.co").next().unwrap();
        assert_eq!(entry.last_seen, 2_000);
        assert!((entry.last_score - 0.5).abs() < 1e-9);
    }

    #[test]
    fn maintainer_eviction_keeps_most_recent() {
        let mut idx = MaintainerIndex::default();
        for i in 0..(MAX_MAINTAINER_ENTRIES + 5) {
            let email = format!("u{i}@x.co");
            idx.upsert(&email, "npm", "p", 0.2, i as u64);
        }
        assert_eq!(idx.len(), MAX_MAINTAINER_ENTRIES);
        let oldest_remaining = idx
            .by_email
            .values()
            .flatten()
            .map(|e| e.last_seen)
            .min()
            .unwrap();
        assert!(
            oldest_remaining >= 5,
            "oldest remaining entry should have last_seen ≥ 5; got {oldest_remaining}"
        );
    }

    #[test]
    fn maintainer_round_trips_to_disk() {
        let td = TempDir::new("corr-maintainer").unwrap();
        let path = td.path().join("maintainer_index.json");
        let mut idx = MaintainerIndex::default();
        idx.upsert("a@x.co", "npm", "foo", 0.4, 1_000);
        idx.upsert("a@x.co", "pypi", "foo", 0.3, 1_010);
        idx.save(&path).unwrap();
        let loaded = MaintainerIndex::load(&path);
        assert_eq!(loaded.len(), 2);
    }

    #[test]
    fn name_index_keeps_per_ecosystem_entries() {
        let mut idx = NameIndex::default();
        let now = now_unix();
        idx.upsert("litellm", "npm", 0.35, now);
        idx.upsert("litellm", "pypi", 0.40, now);
        let count = idx.entries_for("litellm").count();
        assert_eq!(count, 2);
    }

    #[test]
    fn url_seen_elsewhere_excludes_self() {
        let mut idx = UrlIndex::default();
        let now = now_unix();
        idx.upsert("https://evil.com/x", "npm", "pkg-a", now);
        idx.upsert("https://evil.com/x", "pypi", "pkg-b", now);
        let others: Vec<_> = idx
            .seen_elsewhere("https://evil.com/x", "npm", "pkg-a")
            .collect();
        assert_eq!(others.len(), 1);
        assert_eq!(others[0].package, "pkg-b");
    }
}

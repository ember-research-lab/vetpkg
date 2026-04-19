use crate::json::JsonValue;
use crate::types::{Ecosystem, InstallHook, PackageIntel, RegistryAdapter};
use std::time::{SystemTime, UNIX_EPOCH};

pub struct NpmAdapter;

impl RegistryAdapter for NpmAdapter {
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Npm
    }
}

pub fn intel_for_version(name: &str, metadata: &JsonValue, version: &str) -> Option<PackageIntel> {
    let versions = metadata.get("versions")?.as_object()?;
    let vobj = versions
        .iter()
        .find(|(k, _)| k == version)
        .map(|(_, v)| v)?;

    let time_obj = metadata.get("time");

    let publish_time_str = time_obj
        .and_then(|t| t.get(version))
        .and_then(|v| v.as_str());
    let publish_time = publish_time_str.and_then(iso_to_unix);

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let age_hours = publish_time.map(|p| ((now.saturating_sub(p)) as f64) / 3600.0);

    let mut publish_history = Vec::new();
    if let Some(obj) = time_obj.and_then(|t| t.as_object()) {
        for (k, v) in obj {
            if k == "created" || k == "modified" {
                continue;
            }
            if let Some(s) = v.as_str() {
                if let Some(u) = iso_to_unix(s) {
                    publish_history.push((k.clone(), u));
                }
            }
        }
    }

    let maintainers: Vec<String> = metadata
        .get("maintainers")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|m| {
                    m.get("email")
                        .and_then(|e| e.as_str())
                        .map(|s| s.to_string())
                })
                .collect()
        })
        .unwrap_or_default();

    let mut dependencies: Vec<String> = vobj
        .get("dependencies")
        .and_then(|d| d.as_object())
        .map(|obj| obj.iter().map(|(k, _)| k.clone()).collect())
        .unwrap_or_default();
    dependencies.sort();

    let install_hooks = extract_install_hooks(vobj);

    Some(PackageIntel {
        ecosystem: Some(Ecosystem::Npm),
        name: name.to_string(),
        version: version.to_string(),
        maintainers,
        prior_maintainers: Vec::new(),
        publish_time,
        publish_history,
        dependencies,
        prior_dependencies: Vec::new(),
        install_hooks,
        advisories: Vec::new(),
        typosquat_matches: Vec::new(),
        age_hours,
        dep_ages: std::collections::HashMap::new(),
        popularity_rank: None,
    })
}

pub fn extract_install_hooks(version_obj: &JsonValue) -> Vec<InstallHook> {
    let scripts = match version_obj.get("scripts").and_then(|s| s.as_object()) {
        Some(s) => s,
        None => return Vec::new(),
    };
    let hook_stages = [
        "preinstall",
        "install",
        "postinstall",
        "prepublish",
        "prepublishOnly",
        "prepare",
    ];
    let mut out = Vec::new();
    for (name, v) in scripts {
        if !hook_stages.iter().any(|s| s == name) {
            continue;
        }
        if let Some(cmd) = v.as_str() {
            out.push(InstallHook {
                stage: name.clone(),
                command: cmd.to_string(),
            });
        }
    }
    out
}

pub const ABBREVIATED_CONTENT_TYPE: &str = "application/vnd.npm.install-v1+json";
pub const FULL_CONTENT_TYPE: &str = "application/json";

pub const DEFAULT_DEP_AGE_MAX_FETCHES: usize = 5;
pub const DEFAULT_DEP_AGE_TIMEOUT_SECS: u32 = 3;

pub fn fetch_metadata(
    base_url: &str,
    package_name: &str,
    timeout_secs: u32,
) -> Result<JsonValue, String> {
    let url = format!(
        "{}/{}",
        base_url.trim_end_matches('/'),
        encode_name_for_url(package_name)
    );
    crate::net::http_client::fetch_json(&url, &[("Accept", FULL_CONTENT_TYPE)], timeout_secs)
}

pub fn resolve_dep_ages_from_registry(
    base_url: &str,
    intel: &mut PackageIntel,
    max_fetches: usize,
    timeout_secs: u32,
) {
    use std::collections::HashSet;
    let prior: HashSet<&String> = intel.prior_dependencies.iter().collect();
    let new_deps: Vec<String> = intel
        .dependencies
        .iter()
        .filter(|d| !prior.contains(*d))
        .take(max_fetches)
        .cloned()
        .collect();
    if new_deps.is_empty() {
        return;
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    for dep_name in new_deps {
        let Ok(metadata) = fetch_metadata(base_url, &dep_name, timeout_secs) else {
            continue;
        };
        let Some(latest) = metadata
            .get("dist-tags")
            .and_then(|t| t.get("latest"))
            .and_then(|s| s.as_str())
        else {
            continue;
        };
        let Some(time_obj) = metadata.get("time") else {
            continue;
        };
        let Some(published) = time_obj.get(latest).and_then(|s| s.as_str()) else {
            continue;
        };
        let Some(unix) = iso_to_unix(published) else {
            continue;
        };
        let age_hours = (now.saturating_sub(unix) as f64) / 3600.0;
        intel.dep_ages.insert(dep_name, age_hours);
    }
}

pub fn encode_name_for_url(name: &str) -> String {
    if let Some(rest) = name.strip_prefix('@') {
        if let Some(slash) = rest.find('/') {
            return format!("@{}%2f{}", &rest[..slash], &rest[slash + 1..]);
        }
    }
    name.to_string()
}

pub fn wants_abbreviated(accept_header: Option<&str>) -> bool {
    let Some(accept) = accept_header else {
        return false;
    };
    accept
        .split(',')
        .map(|s| s.trim())
        .any(|media| media_type_matches(media, ABBREVIATED_CONTENT_TYPE))
}

fn media_type_matches(candidate: &str, target: &str) -> bool {
    let candidate = candidate.split(';').next().unwrap_or("").trim();
    candidate.eq_ignore_ascii_case(target)
}

pub fn to_abbreviated(full: &JsonValue) -> JsonValue {
    let full_obj = match full.as_object() {
        Some(o) => o,
        None => return JsonValue::Object(Vec::new()),
    };

    let mut out: Vec<(String, JsonValue)> = Vec::new();

    if let Some((_, v)) = full_obj.iter().find(|(k, _)| k == "name") {
        out.push(("name".into(), v.clone()));
    }
    if let Some((_, v)) = full_obj.iter().find(|(k, _)| k == "dist-tags") {
        out.push(("dist-tags".into(), v.clone()));
    }
    if let Some((_, v)) = full_obj.iter().find(|(k, _)| k == "modified") {
        out.push(("modified".into(), v.clone()));
    }
    if let Some((_, versions_v)) = full_obj.iter().find(|(k, _)| k == "versions") {
        if let Some(versions) = versions_v.as_object() {
            let stripped: Vec<(String, JsonValue)> = versions
                .iter()
                .map(|(ver, vobj)| (ver.clone(), abbreviated_version(vobj)))
                .collect();
            out.push(("versions".into(), JsonValue::Object(stripped)));
        }
    }
    JsonValue::Object(out)
}

fn abbreviated_version(version_obj: &JsonValue) -> JsonValue {
    let obj = match version_obj.as_object() {
        Some(o) => o,
        None => return version_obj.clone(),
    };
    const KEEP: &[&str] = &[
        "name",
        "version",
        "dependencies",
        "optionalDependencies",
        "peerDependencies",
        "peerDependenciesMeta",
        "bundleDependencies",
        "bundledDependencies",
        "dist",
        "deprecated",
        "engines",
        "_hasShrinkwrap",
        "cpu",
        "os",
        "hasInstallScript",
        "directories",
    ];
    let mut kept: Vec<(String, JsonValue)> = Vec::new();
    for (k, v) in obj {
        if KEEP.iter().any(|n| *n == k) {
            kept.push((k.clone(), v.clone()));
        }
    }
    JsonValue::Object(kept)
}

pub fn strip_version(metadata: &JsonValue, version: &str) -> JsonValue {
    let obj = match metadata.as_object() {
        Some(o) => o,
        None => return metadata.clone(),
    };
    let mut out: Vec<(String, JsonValue)> = Vec::with_capacity(obj.len());
    for (k, v) in obj {
        if k == "versions" {
            if let Some(vs) = v.as_object() {
                let filtered: Vec<(String, JsonValue)> = vs
                    .iter()
                    .filter(|(ver, _)| ver != version)
                    .map(|(ver, vv)| (ver.clone(), vv.clone()))
                    .collect();
                out.push(("versions".into(), JsonValue::Object(filtered)));
                continue;
            }
        }
        if k == "time" {
            if let Some(times) = v.as_object() {
                let filtered: Vec<(String, JsonValue)> = times
                    .iter()
                    .filter(|(ver, _)| ver != version)
                    .map(|(ver, vv)| (ver.clone(), vv.clone()))
                    .collect();
                out.push(("time".into(), JsonValue::Object(filtered)));
                continue;
            }
        }
        if k == "dist-tags" {
            if let Some(tags) = v.as_object() {
                let filtered: Vec<(String, JsonValue)> = tags
                    .iter()
                    .filter(|(_, val)| val.as_str() != Some(version))
                    .map(|(tag, val)| (tag.clone(), val.clone()))
                    .collect();
                out.push(("dist-tags".into(), JsonValue::Object(filtered)));
                continue;
            }
        }
        out.push((k.clone(), v.clone()));
    }
    JsonValue::Object(out)
}

pub fn iso_to_unix(s: &str) -> Option<u64> {
    let year: i64 = s.get(0..4)?.parse().ok()?;
    let month: u32 = s.get(5..7)?.parse().ok()?;
    let day: u32 = s.get(8..10)?.parse().ok()?;
    let hour: u32 = s.get(11..13)?.parse().ok()?;
    let minute: u32 = s.get(14..16)?.parse().ok()?;
    let second: u32 = s.get(17..19)?.parse().ok()?;
    Some(ymdhms_to_unix(year, month, day, hour, minute, second))
}

fn ymdhms_to_unix(year: i64, m: u32, d: u32, h: u32, mi: u32, s: u32) -> u64 {
    let is_leap = |y: i64| (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0);
    let days_in_month = |y: i64, m: u32| -> u32 {
        match m {
            1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
            4 | 6 | 9 | 11 => 30,
            2 => {
                if is_leap(y) {
                    29
                } else {
                    28
                }
            }
            _ => 0,
        }
    };
    let mut days: i64 = 0;
    if year >= 1970 {
        for y in 1970..year {
            days += if is_leap(y) { 366 } else { 365 };
        }
    } else {
        for y in year..1970 {
            days -= if is_leap(y) { 366 } else { 365 };
        }
    }
    for mm in 1..m {
        days += days_in_month(year, mm) as i64;
    }
    days += (d as i64) - 1;
    let secs = days * 86400 + (h as i64) * 3600 + (mi as i64) * 60 + (s as i64);
    secs.max(0) as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json::parse;

    #[test]
    fn iso_parses_epoch() {
        assert_eq!(iso_to_unix("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(iso_to_unix("2020-01-15T10:30:00Z"), Some(1579084200));
    }

    #[test]
    fn detects_abbreviated_accept() {
        assert!(wants_abbreviated(Some(
            "application/vnd.npm.install-v1+json"
        )));
        assert!(wants_abbreviated(Some(
            "application/vnd.npm.install-v1+json; q=1.0"
        )));
        assert!(wants_abbreviated(Some(
            "text/html, application/vnd.npm.install-v1+json, */*"
        )));
        assert!(!wants_abbreviated(Some("application/json")));
        assert!(!wants_abbreviated(Some("*/*")));
        assert!(!wants_abbreviated(None));
    }

    #[test]
    fn abbreviated_strips_expected_fields() {
        let full = parse(
            r#"{
            "name": "tiny",
            "dist-tags": {"latest": "1.0.0"},
            "time": {"1.0.0": "2024-01-01T00:00:00Z"},
            "modified": "2024-01-01T00:00:00Z",
            "readme": "long readme body",
            "description": "short",
            "maintainers": [{"email": "a@b.co"}],
            "author": {"name": "x"},
            "repository": {"url": "git://..."},
            "keywords": ["util"],
            "homepage": "https://example.com",
            "bugs": {"url": "https://example.com/bugs"},
            "versions": {
                "1.0.0": {
                    "name": "tiny",
                    "version": "1.0.0",
                    "dependencies": {"left-pad": "1.0.0"},
                    "dist": {"tarball": "https://x/y.tgz", "shasum": "abc"},
                    "_hasShrinkwrap": false,
                    "devDependencies": {"mocha": "1.0.0"},
                    "scripts": {"test": "mocha"},
                    "readme": "version readme",
                    "description": "v description",
                    "author": {"name": "x"},
                    "repository": {"url": "git://..."},
                    "keywords": ["util"],
                    "homepage": "https://example.com",
                    "bugs": {"url": "https://example.com/bugs"}
                }
            }
        }"#,
        )
        .unwrap();

        let abbr = to_abbreviated(&full);

        assert!(abbr.get("name").is_some());
        assert!(abbr.get("dist-tags").is_some());
        assert!(abbr.get("modified").is_some());
        assert!(abbr.get("versions").is_some());
        assert!(abbr.get("time").is_none());
        assert!(abbr.get("readme").is_none());
        assert!(abbr.get("description").is_none());
        assert!(abbr.get("maintainers").is_none());
        assert!(abbr.get("author").is_none());
        assert!(abbr.get("repository").is_none());
        assert!(abbr.get("keywords").is_none());
        assert!(abbr.get("homepage").is_none());
        assert!(abbr.get("bugs").is_none());

        let vobj = abbr.get("versions").unwrap().get("1.0.0").unwrap();
        assert!(vobj.get("dependencies").is_some());
        assert!(vobj.get("dist").is_some());
        assert!(vobj.get("_hasShrinkwrap").is_some());
        assert!(vobj.get("devDependencies").is_none());
        assert!(vobj.get("scripts").is_none());
        assert!(vobj.get("readme").is_none());
        assert!(vobj.get("description").is_none());
    }

    #[test]
    fn strip_version_removes_from_all_maps() {
        let full = parse(
            r#"{
            "name": "tiny",
            "dist-tags": {"latest": "1.1.0", "bad": "1.0.1"},
            "time": {"1.0.0": "t0", "1.0.1": "t1", "1.1.0": "t2"},
            "versions": {
                "1.0.0": {"name":"tiny","version":"1.0.0"},
                "1.0.1": {"name":"tiny","version":"1.0.1"},
                "1.1.0": {"name":"tiny","version":"1.1.0"}
            }
        }"#,
        )
        .unwrap();
        let pruned = strip_version(&full, "1.0.1");
        let versions = pruned.get("versions").unwrap().as_object().unwrap();
        assert!(versions.iter().all(|(k, _)| k != "1.0.1"));
        assert_eq!(versions.len(), 2);

        let time = pruned.get("time").unwrap().as_object().unwrap();
        assert!(time.iter().all(|(k, _)| k != "1.0.1"));

        let tags = pruned.get("dist-tags").unwrap().as_object().unwrap();
        assert!(tags.iter().all(|(k, _)| k != "bad"));
        assert!(tags.iter().any(|(k, _)| k == "latest"));
    }

    #[test]
    fn abbreviated_on_non_object_returns_empty() {
        let v = to_abbreviated(&JsonValue::Null);
        assert_eq!(v, JsonValue::Object(Vec::new()));
    }

    #[test]
    fn intel_basics() {
        let j = parse(
            r#"{
            "name": "tiny",
            "versions": {
                "1.0.0": {
                    "name": "tiny",
                    "version": "1.0.0",
                    "dependencies": {"left-pad": "1.0.0"},
                    "scripts": {"postinstall": "node setup.js", "test": "ok"}
                }
            },
            "time": {"1.0.0": "2024-01-01T00:00:00Z"},
            "maintainers": [{"name": "a", "email": "a@b.co"}]
        }"#,
        )
        .unwrap();
        let intel = intel_for_version("tiny", &j, "1.0.0").unwrap();
        assert_eq!(intel.name, "tiny");
        assert_eq!(intel.dependencies, vec!["left-pad".to_string()]);
        assert_eq!(intel.maintainers, vec!["a@b.co".to_string()]);
        assert_eq!(intel.install_hooks.len(), 1);
        assert_eq!(intel.install_hooks[0].stage, "postinstall");
    }
}

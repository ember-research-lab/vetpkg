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

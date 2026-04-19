//! GitHub Actions workflow traversal helpers built on top of YamlValue.
//! Placeholder — the audit-ci command uses the base parser directly.

use super::YamlValue;

pub fn find_jobs(root: &YamlValue) -> Option<&[(String, YamlValue)]> {
    root.get("jobs").and_then(|v| v.as_map())
}

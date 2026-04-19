//! Action reference scanner + permission + secret exposure checks.

use super::{Check, Finding, Severity};
use crate::yaml::YamlValue;

pub fn scan_workflow(file: &str, root: &YamlValue) -> Vec<Finding> {
    let mut findings = Vec::new();
    findings.extend(scan_permissions(file, root));
    findings.extend(scan_actions_and_secrets(file, root));
    findings
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefType {
    Sha,
    Tag,
    Branch,
    Docker,
    Local,
}

pub fn classify_ref(uses: &str) -> (RefType, &str, &str) {
    if let Some(rest) = uses.strip_prefix("docker://") {
        return (RefType::Docker, rest, "");
    }
    if uses.starts_with("./") || uses.starts_with("../") || uses == "." {
        return (RefType::Local, uses, "");
    }
    let Some((owner_action, ref_part)) = uses.split_once('@') else {
        return (RefType::Branch, uses, "");
    };
    let rt = if is_sha(ref_part) {
        RefType::Sha
    } else if looks_like_version_tag(ref_part) {
        RefType::Tag
    } else {
        RefType::Branch
    };
    (rt, owner_action, ref_part)
}

fn is_sha(s: &str) -> bool {
    s.len() >= 40 && s.chars().all(|c| c.is_ascii_hexdigit())
}

fn looks_like_version_tag(s: &str) -> bool {
    if let Some(rest) = s.strip_prefix('v') {
        let head = rest.split(['.', '-']).next().unwrap_or(rest);
        return head.parse::<u32>().is_ok();
    }
    s.split(['.', '-'])
        .all(|part| part.chars().all(|c| c.is_ascii_digit()))
}

pub fn scan_actions_and_secrets(file: &str, root: &YamlValue) -> Vec<Finding> {
    let mut findings = Vec::new();
    let Some(jobs) = root.get("jobs").and_then(|v| v.as_map()) else {
        return findings;
    };
    for (_job, job_val) in jobs {
        let job_perms = job_val
            .get("permissions")
            .map(describe_permissions)
            .unwrap_or_default();
        if let Some(steps) = job_val.get("steps").and_then(|v| v.as_list()) {
            for step in steps {
                if let Some(uses) = step.get("uses").and_then(|v| v.as_str()) {
                    if let Some(f) = classify_action(file, uses) {
                        findings.push(f);
                    }
                    if let Some(env) = step.get("env").and_then(|v| v.as_map()) {
                        findings.extend(scan_env_secret_exposure(file, uses, env));
                    }
                    if uses.starts_with("actions/upload-artifact") {
                        if let Some(with) = step.get("with") {
                            if let Some(path) = with.get("path").and_then(|v| v.as_str()) {
                                if is_sensitive_path(path) {
                                    findings.push(Finding {
                                        severity: Severity::Medium,
                                        file: file.to_string(),
                                        line: 0,
                                        check: Check::SecretExposure,
                                        message: format!(
                                            "upload-artifact path {path:?} matches sensitive location"
                                        ),
                                        subject: Some(path.to_string()),
                                    });
                                }
                            }
                        }
                    }
                }
                if let Some(run) = step.get("run").and_then(|v| v.as_str()) {
                    findings.extend(scan_run_secret_exposure(file, run));
                }
            }
        }
        let _ = job_perms;
    }
    findings
}

fn classify_action(file: &str, uses: &str) -> Option<Finding> {
    let (rt, target, reference) = classify_ref(uses);
    match rt {
        RefType::Sha => Some(Finding {
            severity: Severity::Info,
            file: file.to_string(),
            line: 0,
            check: Check::UnpinnedAction,
            message: format!("{target}@{reference}: pinned to commit SHA"),
            subject: Some(uses.to_string()),
        }),
        RefType::Tag => {
            let severity = if target.starts_with("actions/") {
                Severity::Medium
            } else {
                Severity::High
            };
            Some(Finding {
                severity,
                file: file.to_string(),
                line: 0,
                check: Check::UnpinnedAction,
                message: format!("{target}@{reference}: tag-pinned; tags are mutable"),
                subject: Some(uses.to_string()),
            })
        }
        RefType::Branch => Some(Finding {
            severity: Severity::High,
            file: file.to_string(),
            line: 0,
            check: Check::UnpinnedAction,
            message: format!("{uses}: branch-pinned; consider pinning to full SHA"),
            subject: Some(uses.to_string()),
        }),
        RefType::Docker => Some(Finding {
            severity: Severity::Low,
            file: file.to_string(),
            line: 0,
            check: Check::UnpinnedAction,
            message: format!("{uses}: docker reference; different trust model"),
            subject: Some(uses.to_string()),
        }),
        RefType::Local => Some(Finding {
            severity: Severity::Info,
            file: file.to_string(),
            line: 0,
            check: Check::LocalAction,
            message: format!("{uses}: local action; in-repo"),
            subject: Some(uses.to_string()),
        }),
    }
}

fn scan_env_secret_exposure(file: &str, uses: &str, env: &[(String, YamlValue)]) -> Vec<Finding> {
    let mut out = Vec::new();
    for (var, val) in env {
        let Some(s) = val.as_str() else { continue };
        if !contains_secret_reference(s) {
            continue;
        }
        if is_github_token_reference(s) {
            continue;
        }
        let is_github_action = uses.starts_with("actions/");
        let severity = if is_github_action {
            Severity::Low
        } else {
            Severity::Medium
        };
        out.push(Finding {
            severity,
            file: file.to_string(),
            line: 0,
            check: Check::SecretExposure,
            message: format!(
                "{uses}: env var {var} receives a secret; be careful exposing to third-party"
            ),
            subject: Some(var.clone()),
        });
    }
    out
}

fn scan_run_secret_exposure(file: &str, run: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    for secret in extract_secret_references(run) {
        if is_github_token_reference_name(&secret) {
            out.push(Finding {
                severity: Severity::Low,
                file: file.to_string(),
                line: 0,
                check: Check::SecretExposure,
                message: format!("run block references {secret} (auto-rotated GitHub token)"),
                subject: Some(secret),
            });
        } else {
            out.push(Finding {
                severity: Severity::High,
                file: file.to_string(),
                line: 0,
                check: Check::SecretExposure,
                message: format!(
                    "run block references {secret} — raw secrets in shell can leak to logs"
                ),
                subject: Some(secret),
            });
        }
    }
    out
}

fn extract_secret_references(s: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut i = 0;
    let bytes = s.as_bytes();
    while let Some(pos) = find_subslice(&bytes[i..], b"${{") {
        let abs = i + pos;
        let end = find_subslice(&bytes[abs..], b"}}").map(|p| abs + p);
        let Some(end) = end else {
            break;
        };
        let inner = s[abs + 3..end].trim();
        if let Some(stripped) = inner.strip_prefix("secrets.") {
            let name_end = stripped
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .unwrap_or(stripped.len());
            let name = &stripped[..name_end];
            if !name.is_empty() {
                let full = format!("secrets.{name}");
                if !out.contains(&full) {
                    out.push(full);
                }
            }
        }
        i = end + 2;
    }
    out
}

fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn contains_secret_reference(s: &str) -> bool {
    !extract_secret_references(s).is_empty()
}

fn is_github_token_reference(s: &str) -> bool {
    extract_secret_references(s)
        .iter()
        .all(|r| r == "secrets.GITHUB_TOKEN")
}

fn is_github_token_reference_name(s: &str) -> bool {
    s == "secrets.GITHUB_TOKEN"
}

fn is_sensitive_path(p: &str) -> bool {
    const SENSITIVE: &[&str] = &[
        ".ssh", ".aws", ".env", ".npmrc", ".docker", ".kube", ".netrc",
    ];
    let lower = p.to_ascii_lowercase();
    SENSITIVE.iter().any(|s| lower.contains(s))
}

pub fn describe_permissions(v: &YamlValue) -> String {
    match v {
        YamlValue::Str(s) => s.clone(),
        YamlValue::Map(m) => {
            let entries: Vec<String> = m
                .iter()
                .map(|(k, v)| format!("{}={}", k, summarize(v)))
                .collect();
            format!("{{{}}}", entries.join(","))
        }
        _ => "?".into(),
    }
}

fn summarize(v: &YamlValue) -> String {
    match v {
        YamlValue::Str(s) => s.clone(),
        YamlValue::Bool(b) => b.to_string(),
        _ => "?".into(),
    }
}

pub fn scan_permissions(file: &str, root: &YamlValue) -> Vec<Finding> {
    let mut out = Vec::new();
    match root.get("permissions") {
        None => {
            if root.get("jobs").and_then(|j| j.as_map()).is_some()
                && !has_any_per_job_permissions(root)
            {
                out.push(Finding {
                    severity: Severity::Medium,
                    file: file.to_string(),
                    line: 0,
                    check: Check::PermissionScope,
                    message: "no permissions key — inherits repository defaults".into(),
                    subject: None,
                });
            }
        }
        Some(v) => {
            if let Some(s) = v.as_str() {
                let severity = match s {
                    "write-all" => Severity::High,
                    "read-all" => Severity::Low,
                    _ => Severity::Info,
                };
                out.push(Finding {
                    severity,
                    file: file.to_string(),
                    line: 0,
                    check: Check::PermissionScope,
                    message: format!("top-level permissions: {s}"),
                    subject: Some(s.into()),
                });
            }
        }
    }
    out
}

fn has_any_per_job_permissions(root: &YamlValue) -> bool {
    root.get("jobs")
        .and_then(|v| v.as_map())
        .map(|jobs| jobs.iter().any(|(_, job)| job.get("permissions").is_some()))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::yaml::parse_yaml;

    #[test]
    fn sha_pin_is_info() {
        let uses = "actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11".to_string();
        let r = classify_ref(&uses);
        assert_eq!(r.0, RefType::Sha);
    }

    #[test]
    fn version_tag_actions_is_medium() {
        let y = parse_yaml(
            "jobs:\n  build:\n    runs-on: x\n    steps:\n      - uses: actions/checkout@v4\n",
        )
        .unwrap();
        let findings = scan_actions_and_secrets("ci.yml", &y);
        let f = findings
            .iter()
            .find(|f| f.check == Check::UnpinnedAction)
            .unwrap();
        assert_eq!(f.severity, Severity::Medium);
    }

    #[test]
    fn third_party_tag_is_high() {
        let y = parse_yaml(
            "jobs:\n  build:\n    runs-on: x\n    steps:\n      - uses: hashicorp/setup-terraform@v3\n",
        )
        .unwrap();
        let findings = scan_actions_and_secrets("ci.yml", &y);
        let f = findings
            .iter()
            .find(|f| f.check == Check::UnpinnedAction)
            .unwrap();
        assert_eq!(f.severity, Severity::High);
    }

    #[test]
    fn branch_pin_is_high() {
        let y = parse_yaml(
            "jobs:\n  build:\n    runs-on: x\n    steps:\n      - uses: someone/action@main\n",
        )
        .unwrap();
        let findings = scan_actions_and_secrets("ci.yml", &y);
        assert!(findings.iter().any(|f| f.severity == Severity::High));
    }

    #[test]
    fn docker_is_low() {
        let y = parse_yaml(
            "jobs:\n  build:\n    runs-on: x\n    steps:\n      - uses: docker://node:18\n",
        )
        .unwrap();
        let findings = scan_actions_and_secrets("ci.yml", &y);
        assert!(findings.iter().any(|f| f.severity == Severity::Low));
    }

    #[test]
    fn local_action_is_info() {
        let y = parse_yaml(
            "jobs:\n  build:\n    runs-on: x\n    steps:\n      - uses: ./.github/actions/custom\n",
        )
        .unwrap();
        let findings = scan_actions_and_secrets("ci.yml", &y);
        let f = findings
            .iter()
            .find(|f| f.check == Check::LocalAction)
            .unwrap();
        assert_eq!(f.severity, Severity::Info);
    }

    #[test]
    fn run_block_with_secret_is_high() {
        let run = "echo ${{ secrets.API_KEY }}";
        let findings = scan_run_secret_exposure("ci.yml", run);
        assert!(findings.iter().any(|f| f.severity == Severity::High));
    }

    #[test]
    fn run_block_with_github_token_is_low() {
        let run = "echo ${{ secrets.GITHUB_TOKEN }}";
        let findings = scan_run_secret_exposure("ci.yml", run);
        assert!(findings.iter().all(|f| f.severity == Severity::Low));
    }

    #[test]
    fn upload_artifact_sensitive_path_is_medium() {
        let y = parse_yaml(
            r#"jobs:
  b:
    runs-on: x
    steps:
      - uses: actions/upload-artifact@v4
        with:
          path: ~/.ssh
"#,
        )
        .unwrap();
        let findings = scan_actions_and_secrets("ci.yml", &y);
        assert!(findings.iter().any(|f| f.severity == Severity::Medium));
    }

    #[test]
    fn no_permissions_key_is_medium() {
        let y =
            parse_yaml("jobs:\n  b:\n    runs-on: x\n    steps:\n      - run: echo hi\n").unwrap();
        let findings = scan_permissions("ci.yml", &y);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn write_all_is_high() {
        let y = parse_yaml("permissions: write-all\njobs:\n  b:\n    runs-on: x\n").unwrap();
        let findings = scan_permissions("ci.yml", &y);
        assert!(findings.iter().any(|f| f.severity == Severity::High));
    }

    #[test]
    fn explicit_scoped_permissions_clean() {
        let y = parse_yaml(
            "permissions: {contents: read, pull-requests: write}\njobs:\n  b:\n    runs-on: x\n",
        )
        .unwrap();
        let findings = scan_permissions("ci.yml", &y);
        assert!(
            findings.iter().all(|f| f.severity <= Severity::Info),
            "{:?}",
            findings
        );
    }
}

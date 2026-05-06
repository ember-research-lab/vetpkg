# Threat-Intel Changelog — vetpkg

All changes to the shipped rule library, signal catalog, or fixture set
go here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions track `Cargo.toml`'s `version`.

## [Unreleased]

### Substrate
- Initial threat-intel directory established. Existing attack-pattern
  coverage lives as inline unit tests; future patterns land here as
  named fixtures.

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

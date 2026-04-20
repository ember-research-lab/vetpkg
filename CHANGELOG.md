# Changelog

All notable changes to vetpkg are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). This project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] — 2026-04-19

Initial public release.

### Added

- **Local proxy registry** (`vetpkg daemon`) — intercepts npm installs on
  `http://127.0.0.1:9451`, scores every package against supply-chain
  signals, strips blocked versions from metadata responses, streams
  clean tarballs through untouched, buffers suspect tarballs for
  deeper analysis.
- **Tiered analysis engine**:
  - Tier 0 (< 100 ms, metadata-only): `AdvisoryCheck`,
    `MaintainerChangeCheck`, `HookCheck`, `NewDependencyCheck`,
    `PopularityAnomalyCheck`, `FreshPackageCheck`, `TyposquatCheck`,
    `PublishAnomalyCheck`.
  - Tier 1 (< 500 ms, on `SuspicionMap` hit): `BinaryBlobDetection`,
    `BuildScriptDiff`.
  - Tier 2 (< 5 s, when still in warn band): `TaintDetection`
    (source/sink line matcher with concat-aware string folding),
    cross-ecosystem correlation multipliers (maintainer, name, URL),
    `InfiniteLoopDetection`, `BinShadow`.
- **Lockfile audit** (`vetpkg audit`) — npm v2/v3, offline-only by
  default, `--full` for upstream metadata, `--json`, `--fail-on-warn`
  for CI gating. Includes resolved-URL tampering detection.
- **CI workflow audit** (`vetpkg audit-ci`) — flags unpinned actions,
  permission-scope issues, secret exposure, `upload-artifact` with
  sensitive paths. `--online --strict` adds tag-mutation detection
  with per-(owner/action@tag) SHA cache.
- **Utility commands**: `status`, `policy`, `init`.
- **Cross-ecosystem adapters** (ready behind the proxy routes): npm
  (Registry v1 JSON), PyPI (Simple API HTML tokenizer, PEP 503),
  Cargo (sparse-index protocol).
- **Attack-matrix benchmark** (`tests/attack_matrix.rs`) — 24 named
  historical attack fixtures (axios 1.14.1, Shai-Hulud, XZ Utils,
  @nx, ua-parser-js, event-stream, colors/faker, Gluestack,
  twilio-npm, tj-actions, and more) plus 3 documented `#[ignore]`
  gaps for future work (node-ipc protestware, time-delayed
  triggers, prototype pollution at install).
- **Dual licensing**: MIT OR Apache-2.0 (`LICENSE-MIT`,
  `LICENSE-APACHE`).
- **Platform coverage**: Linux, macOS, Windows. CI matrix is
  `{ubuntu, macos, windows}-latest × {stable, 1.75}`. Release builds
  fan out to 5 targets (linux-x86_64, linux-aarch64, darwin-x86_64,
  darwin-aarch64, windows-x86_64-msvc) with SHA-256 companions.
- **Docs**: README, CONTRIBUTING, SECURITY, phase-plan specs under
  `docs/plan/`, worked config example at `docs/examples/config.toml`.

### Security invariants

- `Cargo.toml` `[dependencies]` is empty, CI-gated on every commit.
- `#[forbid(unsafe_code)]`, `#[deny(clippy::all)]` at crate root.
- Single runtime dependency: `curl`, resolved to an absolute path at
  startup.
- Argv-separated process spawn only. URLs and header values are
  rejected if they contain `\r`, `\n`, `\0`, or (for URLs) any
  non-printable character.
- `VETPKG_NO_EXTERNAL_NETWORK=1` hard-disables non-localhost HTTP.
- No `cargo install` path; only build-from-source is supported.

### Known gaps

- Proxy routes for PyPI and Cargo are pending (adapters ready, HTTP
  dispatch returns `501 Not Implemented` for those prefixes).
- `#[ignore]`d fixtures for node-ipc geo-conditional protestware,
  time-delayed trigger detection, and install-time prototype pollution.

[Unreleased]: https://github.com/ember-research-lab/vetpkg/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/ember-research-lab/vetpkg/releases/tag/v0.3.0

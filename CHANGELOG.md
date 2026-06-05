# Changelog

All notable changes to vetpkg are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). This project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- New `PublishAnomalyKind::DormantMaintainer` signal. Catches the
  hijack-of-popular-package shape: maintainer set unchanged +
  previous publish > 12 months ago + ≥1 prior version in
  publish_history. Weight 0.30 (higher than other publish
  anomalies because dormant-account compromise is high-confidence).
  Closes the gap originally pinned by the
  `is_package_jul2025` threat-intel fixture; that fixture's
  verdict moves Warn → Block as a result.

## [0.3.0] — 2026-04-20

Initial public release. Includes the security hardening pass
described below.

### Security (hardening pass pre-release)

Systematic hardening across every attacker-reachable parser and
process-spawn site. Surfaced by a six-agent security audit of the
codebase; none of these were exploited in the wild.

- **JSON parser**: recursion-depth cap (128), input-size cap (128 MB),
  per-string cap (16 MB), per-collection cap (1M items). Rejects
  overlong UTF-8 continuation bytes. Prevents stack overflow, OOM,
  and path-smuggling via encoding tricks.
- **DEFLATE**: `MAX_OUTPUT` now enforced inside `inflate_block`, not
  only at block boundaries. Overlapping back-references can no longer
  balloon a single block past the cap before the check fires. Stored
  blocks pre-check saturating_add overflow.
- **gzip**: FHCRC flag skip now bounds-checks before advancing `pos`
  (prevents slice panic on crafted truncated header).
- **tar**: PAX record parser now validates `len >= space + 2` and the
  trailing `\n` before slicing, eliminating a remote-DoS panic on
  crafted records. Entry-count cap (100 000), total-size cap (512 MB),
  per-entry cap (256 MB), saturating_add on body-end offset.
- **HTTP server**: per-line bounded reads (8 KB request line, 8 KB
  header line, 100 headers max, 64 MB body max). Header values
  containing `\r`/`\n`/`\0` rejected; header names must be printable
  ASCII. Mitigates slow-loris, request-smuggling, and
  response-splitting probes.
- **HTTP client/streaming**: every curl spawn now scrubs dangerous env
  vars (`HTTP_PROXY`, `HTTPS_PROXY`, `CURL_HOME`, `SSL_CERT_*`,
  `LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`, etc.) so a compromised process
  environment can't redirect curl traffic, swap TLS trust, or preload
  libraries.
- **URL validator (`is_safe_url`)**: now rejects percent-encoded CRLF
  (`%0d`/`%0a`), `%00`, userinfo-containing URLs (`user@host`),
  non-printable ASCII, and non-ASCII bytes. Curl will not see any
  path where it could decode CRLF into the request line.
- **Header validator**: printable-ASCII-only (0x20..=0x7E). Tabs and
  DEL now rejected.
- **Proxy**: connection write-deadline (90 s) added to complement the
  per-read timeout, defeating slow-loris. Fail-CLOSED on
  gunzip/tar-extract errors for already-suspect packages (was
  fail-OPEN). `BoundedBuffer` sink enforces 200 MB tarball cap
  *during* streaming rather than after. `DeferredChunkedWriter`
  delays emitting HTTP 200 headers until upstream proves success —
  upstream 4xx/5xx now correctly propagates as 502 rather than
  corrupting the client install. Tarball filename validated against
  the whitelist charset before URL composition.
- **GitHub API paths (`pin_check`)**: owner/repo/tag values validated
  against `[a-zA-Z0-9._/-]+` with no-`..` and no-leading-`.` rules
  before composition. `validate_sha_like` gates the annotated-tag
  second hop.
- **Signal scanners**: per-line cap (64 KB) in matcher and
  infinite_loop; per-hook-command cap (8 KB); typosquat
  Damerau-Levenshtein short-circuits on names > 256 chars; taint-path
  and variable-flow output caps (256 each) to bound quadratic
  explosion. Pattern-list dedup now `HashSet`-based (O(N) instead of
  O(N²)).
- **Build-diff / binary-blob / manifest**: file-size caps before
  `fs::read` (16 MB manifest, 64 MB blob, 4 MB build file). Myers
  diff hard-caps combined line count at 10 000 with graceful
  degradation.
- **Engine orchestrator**: `RwLock::read()` now recovers from
  poisoning via `into_inner`, preventing a single index-update panic
  from cascading into permanent DoS of every subsequent request.

New unit tests cover each fix with positive and negative cases: 309
library unit tests total (was 291) with the six regression fixtures
directly exercising the most serious findings.

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

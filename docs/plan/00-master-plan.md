# vetpkg Master Plan (v2 — resolutions applied)

## Core Principle
A supply-chain security tool must not itself be a supply-chain risk. vetpkg compiles with **zero crate dependencies** — `Cargo.toml` `[dependencies]` is empty. The entire codebase is auditable by one person. Trust anchors are rustc, stdlib, and one runtime dependency (pinned curl binary).

## Platform Posture
**Linux, macOS, Windows** all supported from v1. Cross-platform achieved by:
- File locking via atomic sentinel files (stdlib `OpenOptions::create_new`), **zero FFI**
- Config path resolution: `$XDG_CONFIG_HOME` / `$HOME/.config` on Unix, `%APPDATA%` on Windows
- curl auto-resolution at startup: `/usr/bin/curl` (Unix), `C:\Windows\System32\curl.exe` (Windows ≥ build 17063), or env override `VETPKG_CURL_PATH`
- Path handling via `PathBuf` throughout; no string path concatenation
- CI matrix: `ubuntu-latest`, `macos-latest`, `windows-latest`

## Trust Anchors (README obligation)
1. Rust toolchain (rustc + cargo + stdlib)
2. curl binary, resolved to absolute path at startup, validated by version check
3. Nothing else

## Threat Model
Unchanged from v1. See `01-phase0-foundation.md` for the matrix.

## Architecture

### Tiered Analysis Pipeline
```
Tier 0 (metadata, <100ms): AdvisoryCheck, MaintainerChange, FreshPackage,
  PopularityAnomaly, Typosquat, NewDependency, PublishAnomaly (cadence/hour/seq)
→ Clean (<0.15): streaming forward (curl stdout → client socket in chunks, O(64KB) memory)
→ Suspicious (0.15–0.6): annotate in SuspicionMap (TTL 30 min)
→ Block (≥0.6): strip from metadata response

Tier 1 (tarball surface, <500ms): BinaryBlobDetection, BuildScriptDiff, HookCheck
→ triggered only for SuspiciousMap hits on tarball requests

Tier 2 (deep, <5s): TaintDetection (source/sink), PublishAnomaly sub-check (c),
  cross-ecosystem correlation multipliers
```

### Key Clarifications vs v1
- **"Streaming forward" replaces "passthrough"**: curl-shelling precludes true TCP splice. Byte-level streaming with fixed chunk buffer (64KB). O(chunk) memory, not O(tarball).
- **Cargo proxy uses sparse index**, not api/v1 (which cargo doesn't hit during install). Routes: `/cargo/index/{ch1}{ch2}/{ch3}{ch4}/{crate}`, `/cargo/download/{crate}/{version}`.
- **OSV integration via on-demand API** with 1-hour local cache + stale-on-failure.

### Concurrency Model
Thread-per-connection with **bounded semaphore (32 concurrent)** to prevent self-DoS. Shared state via `Arc<RwLock<_>>`. No async runtime.

## Module Layout
See `src/` under project root. Each module maps to an `.rs` file with a test sub-module.

## Implementation Sequence
```
Phase 0: zero-dep foundation    (this is the biggest phase)
Phase 1: npm polish              (scoped pkgs, abbreviated metadata, OSV, lockfile audit)
Phase 2: tarball signals         (SuspicionMap, 3 signals, streaming-forward proxy)
Phase 3: deep analysis           (pattern matcher, TaintDetection, FP suite)
Phase 4: cross-ecosystem         (PyPI Simple tokenizer, Cargo sparse index, correlation)
Phase 5: CI guard                (YAML with flow-style, annotated tag 2-hop, audit-ci cmd)
```

## Testing Rules (All Phases)
1. **No external network.** Tests bind localhost TcpListeners with mock responses. Integration tests fail-closed if they attempt a resolvable host other than `127.0.0.1` / `::1`.
2. **Temp isolation.** Tests use `std::env::temp_dir()` with process-unique subdirs; cleanup via `Drop`.
3. **Cross-platform.** Every test must pass on Linux, macOS, Windows. CI is the gate.
4. **Deterministic.** No time-dependent assertions without injected clocks.
5. **Perf gates.** One pathological fixture per tier with hard-timeout `assert!(elapsed < limit)`.

## LoC Budget (target, not hard ceiling)
| Layer | LoC |
|---|---|
| Infrastructure (net, json, compress, crypto, store) | ~4,400 |
| Adapters (npm, pypi, cargo) | ~1,600 |
| Signals (all 11) | ~2,100 |
| Correlation | ~650 |
| CI audit | ~900 |
| CLI + proxy orchestration | ~850 |
| Tests | ~2,700 |
| **Total** | **~13,200** |

Windows support adds ~200 LoC vs the v1 estimate.

## Open Decisions (non-blocking)
1. **DEFLATE budget**: 2 working days on pure-Rust attempt. If not passing tests, vendor miniz.c (public domain, single file) and document the decision.
2. **Community blocklist**: NO for v1. Everything local.
3. **Update mechanism**: rebuild from source. No self-update. Signed git tags + published SHA-256 per release.

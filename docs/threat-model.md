# Internal Threat Model — vetpkg

This document is about vetpkg's *own* posture, not the threats it
detects. Same structure as
`ember-agent-monitor/docs/internal-threat-model.md`; specific to
the install-time supply-chain layer.

## 1. The substrate sits in the install-time critical path

vetpkg listens on a loopback HTTP port and proxies requests for
package managers (npm, pip, cargo). Compromising vetpkg means
compromising what the user installs — every package that flows
through the proxy. The blast radius is the user's entire installed
state.

That makes vetpkg's substrate a high-value target. The disciplines
below address each surface.

## 2. Disciplines

### 2a. Zero dependencies, period

`Cargo.toml` has empty `[dependencies]` and empty `[dev-dependencies]`.
Every primitive — JSON parsing, gzip/deflate, tar extraction, SHA-256,
HTTP server, lockfile parsing — is implemented in this repo. Same
reason as agent-monitor: a single compromised supply-chain entry
defeats the entire tool, and with zero deps the trust anchors are
just `rustc` + `std` + (when invoked) the system `curl`.

### 2b. `#![forbid(unsafe_code)]` is non-negotiable

Top of `lib.rs`. No exceptions. If a hot path looks like it needs
unsafe, that's a redesign signal.

### 2c. Path normalization at every input boundary

Tarball filename validation (`is_safe_tarball_filename` in
`net/proxy.rs`), package-name validation (`parse_npm_path`), lockfile
path resolution — every path-like value is validated *before* it
reaches a filesystem or URL composition step.

The discipline: zone tagging never receives a raw string. If a
match runs on raw input, that's a bug.

### 2d. Output escaping at every user-facing surface

JSON output for `audit --json`, the proxy's response bodies, and the
new findings log all go through `json::to_json_string`. Never
construct JSON via `format!` — the audit-side `{:?}` Debug
serialization for signals was a real instance of this drift, fixed in
the same release that established this document.

### 2e. Configuration vs state are separate stores

PolicyConfig is loaded once at startup from a TOML file under
`~/.ember/vetpkg/`. There is no per-session state in the proxy that
could bleed across requests. As vetpkg grows (per-user allowlists,
CI-mode overrides), the rule is: anything operator-set lives in
`config/`; anything observed-at-runtime lives in `state/`. Never
share a backing store.

### 2f. Adversarial input parsing fails closed

Tarball decompression, tar extraction, lockfile parsing — every input
reader is sized-bounded and treats parse errors as adversarial signal
(score upward), not graceful-degradation noise (score downward).
Documented at the relevant call sites.

### 2g. Eat own dog food in CI

The release process runs `vetpkg audit` against this crate's own
lockfile (which is empty, so it's a tautology — but the *discipline*
is: if we ever add a transitive dep, vetpkg has to clear it first).
Threat-intel fixtures run on every change. Adversarial test failures
block the release.

### 2h. AI-assisted-development discipline

Same posture as agent-monitor's threat model §2h. Code touching
`net/proxy.rs`, `engine/`, `signals/`, the JSON parser, or the
findings-log integration surface gets two-human review regardless
of size — the threat surface justifies the friction.

## 3. Trust anchors

1. The Rust toolchain (`rustc`, `std`, `cargo`).
2. The system `curl` binary used for upstream fetches.
3. The kernel's filesystem and TCP semantics.
4. The vetpkg binary the user actually installed (verified via
   release-time hash; we publish hashes alongside binaries).

## 4. What vetpkg does NOT protect against

- An attacker who already has filesystem write to `~/.ember/vetpkg/`.
  They can edit the cache, the findings log, or the config. The
  cache is verifiable by re-running the analysis; the findings log
  is consumed by agent-monitor and would surface if poisoned. v1 of
  the suite has no log signing — documented gap.
- An attacker who replaces the binary on disk. Mitigation: shipped
  hashes; user verifies.
- A package whose attack lives entirely in runtime behavior (no
  installation-time signal). vetpkg is install-time; runtime detection
  belongs to ember-agent-monitor (Tool 2).
- Side-channel attacks against the rule library. The rules are public;
  layer-orthogonal coverage across the suite is the defense.

## 5. Operating expectations

- Routine release cycle: every 2-4 weeks for the rule library,
  slower for substrate.
- Substrate changes (anything in `net/`, `engine/`, JSON parser, or
  the findings-log integration) require both an internal threat-model
  review (this doc gets updated) and a CHANGELOG entry under both
  `CHANGELOG.md` and `threat-intel/CHANGELOG.md`.
- Threat-intel fixtures run on every PR. A fixture that drops a
  pinned verdict is red; a fixture that gains an unexpected verdict
  is also red (false positives matter as much as false negatives in
  the install-time critical path).

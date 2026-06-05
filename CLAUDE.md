# CLAUDE.md — vetpkg

Orientation for anyone (human or Claude) working in this repo. Read this first; it's the context a fresh session doesn't have.

## What this is

A **zero-dependency supply-chain security proxy** for npm (with PyPI and Cargo adapters) plus a lockfile auditor and a GitHub-Actions auditor. `vetpkg daemon` runs a localhost proxy registry that package managers point at; it fetches upstream metadata, scores each package against supply-chain signals across three tiers (Tier 0 metadata <100ms → Tier 1 tarball <500ms → Tier 2 deep <5s), strips blocked versions from responses, annotates suspicious ones, and streams clean ones through untouched. `vetpkg audit` scores a lockfile; `vetpkg audit-ci` scores CI workflows.

**The product is the premise: a supply-chain security tool must not itself be a supply-chain risk.** The whole codebase is auditable by one person in an afternoon. Everything below exists to keep it that way.

## Read before substantial work

- [`README.md`](README.md) — usage, the trust-anchor contract, threat-model coverage matrix, the architecture diagram.
- [`docs/threat-model.md`](docs/threat-model.md) — vetpkg's *own* posture (not what it detects). The disciplines: fail-closed parsing, path normalization at every boundary, output escaping, config/state separation, two-human review for substrate code.
- [`docs/plan/00-master-plan.md`](docs/plan/00-master-plan.md) — rationale for zero-deps and stdlib-threads-over-async; `01`–`06` are the phase specs.
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — the dependency rule, what does/doesn't belong, how to add a signal/pattern.
- [`threat-intel/README.md`](threat-intel/README.md) — the attack-fixture catalog and how to extend it.

## Non-negotiable house rules

1. **ZERO external dependencies.** `Cargo.toml` `[dependencies]` and `[dev-dependencies]` are both empty and stay that way. Every primitive — JSON parser, gzip/deflate, tar, SHA-256, HTTP server, lockfile parsing — is implemented in `src/`. CI's **"Check zero dependencies"** step parses `[dependencies]` and fails the build if it is non-empty. A PR that adds a dependency does not get fixed; it gets closed. If a task seems to need one, either the task doesn't belong here or we write the code ourselves, scoped to exactly what's needed.
2. **Trust anchors are exactly: the Rust toolchain (rustc + cargo + stdlib), and the system `curl` binary** (auto-resolved to an absolute path at startup; override via `VETPKG_CURL_PATH`). Nothing else. HTTPS is curl shelled out with argv-separated args (no shell interpolation); URLs/headers are validated against control chars before any spawn.
3. **`#![forbid(unsafe_code)]`** sits at the top of `lib.rs`. No exceptions — a hot path that looks like it needs `unsafe` is a redesign signal.
4. **fmt + clippy + tests + cargo-deny must all pass.** CI enforces the same gate locally devs run, across `ubuntu × macos × windows` on Rust `stable` and `1.75` (the MSRV). Don't break MSRV.

## Fixture discipline

vetpkg's adversarial coverage is a **named-attack-fixture catalog** under `threat-intel/fixtures/<codename>_<vector>_<date>/` (e.g. `phantomraven_rdd_aug2025`, `s1ngularity_nx_aug2025`, `promptmink_famous_chollima_apr2026`). Each directory drops in artifacts plus an `expected.json` pinning verdict + signal short-labels; `tests/threat_intel_fixtures.rs` discovers and runs them all — **adding a fixture is a directory drop, no code change**. Three shapes: `lockfile.json` (audit path), `intel.json` alone (Tier 0 metadata), or `intel.json` + `extracted/` (full tarball path).

- **A regression is red both ways**: a fixture that *drops* a pinned verdict is red, and a fixture that *gains* an unexpected verdict is red too. **False positives matter as much as false negatives** in the install-time critical path.
- **Honest-negative fixtures are first-class.** Clean packages that must verdict `Allow` belong in the catalog and in the false-positive suites (`tests/phase3_fp_suite.rs`, `tests/phase4_fp_50.rs`) — proving a signal does *not* misfire is as load-bearing as proving it fires.
- Pin signal labels via the same `signal_short_label` vetpkg uses internally, so the test fails when label format drifts.

## Commands

```sh
cargo build
cargo test                                          # full suite (>300 tests); must not contact external hosts
cargo clippy --all-targets --no-deps -- -D warnings # must be clean
cargo fmt --all -- --check
cargo deny check advisories bans sources            # supply-chain policy (see deny.toml)
```

All four (build/test/clippy/fmt) must pass locally before opening a PR. Integration tests spawn a localhost `TcpListener` with canned responses — never reach a real host; `VETPKG_NO_EXTERNAL_NETWORK=1` (set in CI) trips an error in the HTTP client if you accidentally try.

## Adding a signal (the house pattern)

1. Add a variant to `types::Signal` + a weight in `Signal::weight()`.
2. New module under `src/signals/`: implement the `Check` trait (Tier 0) or a `scan_dir(...)` fn (Tier 1).
3. Wire into `engine::SecurityEngine::new()` (Tier 0) or `engine::orchestrator` (Tier 1/2).
4. Unit tests for firing **and** non-firing cases; add a clean-package entry to a false-positive suite.
5. Update the README threat-model matrix if it covers a new attack class.

## Honest scope — what vetpkg does NOT do

- **Not a runtime detector.** It is install-time only; runtime behavior with no install-time signal is out of scope (that's a separate tool's job).
- **No SolarWinds-class / vendor-build-system coverage** — that needs reproducible builds + SLSA attestation upstream of the proxy. Explicitly out of scope (see README matrix).
- **No async runtime, no GUI/dashboard, no remote state sync** — stdlib threads on purpose; all state is local.
- **No `cargo install vetpkg`, no self-update.** Build-from-source is the only supported install/upgrade path — that's precisely the attack vector vetpkg defends against. A `vetpkg` crate on crates.io is not us.
- **Known v1 gaps are documented, not hidden** — e.g. the findings log is unsigned (see `docs/threat-model.md` §4). Don't paper over them.

## Commit format

`type(scope): description — detail`, e.g. `fix(proxy): validate tarball filename before fs access — closes path-escape gap`. Types: `feat`, `fix`, `test`, `docs`, `refactor`, `chore`, `style`, `ci`. One logical change per commit; every commit must build, pass `cargo test`, and pass clippy `-D warnings`. Substrate changes (`net/`, `engine/`, the JSON parser, signals, findings-log surface) get two-human review and a CHANGELOG entry under both `CHANGELOG.md` and `threat-intel/CHANGELOG.md`. Security issues go through `SECURITY.md`, never a public issue.

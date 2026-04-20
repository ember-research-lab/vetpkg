# vetpkg

A local proxy registry that intercepts package-manager installs (npm, with PyPI and Cargo adapters available) and scores them against supply-chain security signals. Blocks known-bad versions, annotates suspicious ones, streams clean ones through untouched.

## Design principle

**A supply-chain security tool must not itself be a supply-chain risk.**

vetpkg compiles with **zero crate dependencies** — `Cargo.toml` `[dependencies]` is empty. The entire codebase is auditable by one person in an afternoon. There is no transitive dependency graph to vet, no `cargo install` surface to compromise.

## Trust anchors

Exactly three things:

1. The Rust toolchain (rustc + cargo + stdlib)
2. A `curl` binary, auto-resolved to an absolute path at startup. Override via `VETPKG_CURL_PATH`.
3. Nothing else.

HTTPS is handled by shelling out to curl with argv-separated arguments (no shell interpolation, no CRLF injection). All URLs and header values are validated against control characters before any process spawn.

## Installation

**Only one supported install path: build from source.**

```bash
git clone https://github.com/ember-research-lab/vetpkg.git
cd vetpkg
# Read the code. Run `cargo audit` style scrutiny on what you build.
cargo build --release
# Binary is at target/release/vetpkg
```

**There is no `cargo install vetpkg` from crates.io, and there will not be.** That is precisely the attack vector vetpkg is designed to defend against. If someone ships a crate named `vetpkg` on crates.io, it is not us.

### Release binaries

Release tags on GitHub attach binaries for `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`, `x86_64-apple-darwin`, `aarch64-apple-darwin`, and `x86_64-pc-windows-msvc`, each with a `.sha256` companion. Verify the hash out-of-band before running. The build is reproducible from the source at the tagged commit.

## Platform support

Linux, macOS, Windows. CI runs every commit against `ubuntu-latest × macos-latest × windows-latest` with Rust stable and 1.75. File locking uses atomic `OpenOptions::create_new` (zero FFI, works on both POSIX and Windows).

## Usage

### `vetpkg daemon` — start the proxy

```bash
vetpkg daemon
# vetpkg 0.3.0 listening on http://127.0.0.1:9451
#   npm    /npm/*     active
#   pip    /pip/*     adapter ready, proxy route pending
#   cargo  /cargo/*   adapter ready, proxy route pending
```

Point your package manager at the proxy:

```bash
# npm (temporary, per-shell)
npm --registry http://127.0.0.1:9451/npm/ install express

# npm (persistent via .npmrc)
echo "registry=http://127.0.0.1:9451/npm/" >> .npmrc
```

The proxy fetches metadata from the real registry, runs Tier 0 scoring against each package, strips blocked versions from the response, and forwards the filtered JSON back to your client. Tarball requests stream through untouched unless the scorer annotated the requested version, in which case the tarball is buffered and Tier 1/2 analysis runs before forwarding or blocking.

### `vetpkg audit` — score a lockfile

```bash
vetpkg audit --path ./my-project
# vetpkg Lockfile Audit
# ═════════════════════
#
# lockfile  : ./my-project/package-lock.json (v3)
# packages  : 1247
# elapsed   : 892 ms
#
# BLOCK  requets@1.0.0  score=0.35
#         Typosquat { matched: "requests", distance: 0.07 }
#
# Summary: 1 blocked, 0 warnings, 1246 clean
```

Flags: `--path DIR|FILE` (default `.`), `--full` (fetch upstream metadata for each entry — slower, more accurate), `--json` (machine-readable), `--fail-on-warn` (exit 1 on Warn verdicts for CI gating).

### `vetpkg audit-ci` — audit GitHub Actions workflows

```bash
vetpkg audit-ci --path .
# Flags unpinned actions, permission-scope issues, secret exposure in run: blocks,
# upload-artifact with sensitive paths.

vetpkg audit-ci --online --strict
# Adds tag-mutation detection: caches commit SHA per (owner/action@tag),
# flags Critical if upstream SHA drifts from cache.
```

Flags: `--path DIR`, `--online` (fetch GitHub tag refs for mutation detection), `--strict` (exit 1 on any Medium+ finding), `--json`.

### `vetpkg status`, `vetpkg policy`, `vetpkg init`

- `status` — check if the daemon is running on the configured port
- `policy` — print effective threshold and upstream configuration
- `init` — write default config + pattern files to `{config_dir}/vetpkg/`

## Architecture

```
  npm client
     │  GET /npm/axios  (or /-/axios-1.14.0.tgz)
     ▼
  ┌──────────────────────────────────────────────────────┐
  │  net::proxy           localhost HTTP server         │
  │   │                                                  │
  │   ▼                                                  │
  │  net::package_path    parse + validate              │
  │   │                                                  │
  │   ▼                                                  │
  │  adapter::npm         fetch upstream metadata via    │
  │                       net::http_client (curl-shelled │
  │                       for HTTPS, direct TCP for      │
  │                       localhost mocks)               │
  │   │                                                  │
  │   ▼                                                  │
  │  engine::TierOrchestrator                            │
  │    Tier 0 (<100ms):                                  │
  │      AdvisoryCheck, MaintainerChange, HookCheck,     │
  │      NewDependency, PopularityAnomaly, FreshPackage, │
  │      Typosquat, PublishAnomaly                       │
  │    ↳ [warn..block) → SuspicionMap (TTL 30 min)       │
  │    ↳ ≥ block        → strip from response            │
  │                                                      │
  │    Tier 1 (<500ms, on tarball with SuspicionMap hit):│
  │      BinaryBlobDetection, BuildScriptDiff            │
  │                                                      │
  │    Tier 2 (<5s, when post-Tier-1 still in warn):     │
  │      TaintDetection (source/sink line-matcher),      │
  │      correlation multipliers (maintainer, name, URL) │
  │                                                      │
  │   ▼                                                  │
  │  filtered JSON / 200 OK (streamed tarball) / 403     │
  └──────────────────────────────────────────────────────┘
```

Signal weights and thresholds live in `src/types.rs`. Pattern corpora live in `data/patterns/*.txt` (user-extensible at `{config_dir}/vetpkg/patterns/`).

## Threat model coverage

| Attack | Year | Technique | Coverage |
|---|---|---|---|
| Axios RAT | 2026 | Maintainer cred theft → postinstall + new dep | ✅ HookCheck + MaintainerChange + NewDependency |
| Gluestack | 2025 | Stolen token → backdoor 17 packages | ✅ MaintainerChange + PublishAnomaly |
| Shai-Hulud 1+2 | 2025 | Compromised maintainers → preinstall → worm | ✅ HookCheck + TaintDetection |
| @nx/s1ngularity | 2025 | Build-time exfil via legitimate APIs | ✅ TaintDetection (source/sink on changed files) |
| XZ Utils | 2024 | 2yr social eng → binary blob → build script extraction | ✅ BinaryBlobDetection + BuildScriptDiff |
| Vercel (2026) | 2026 | Stolen tokens → potential poisoned update | ✅ PublishAnomaly (log-normal cadence, hour-of-day) |
| TeamPCP | 2026 | Cross-ecosystem coordinated compromise | ✅ Maintainer/Name/URL correlation multipliers |
| tj-actions | 2025 | GitHub Actions PAT theft → tag hijack → CI exfil | ✅ `audit-ci --online` tag-mutation detection |
| SolarWinds | 2020 | Build server implant → code injection at compile | ❌ Out of scope — vendor-side SLSA responsibility |

SolarWinds-class attacks (vendor build system compromise) are explicitly out of scope. That requires reproducible builds and SLSA attestation upstream of the proxy.

## Configuration

See `docs/examples/config.toml` for a fully-commented example. Default locations:
- Unix: `$XDG_CONFIG_HOME/vetpkg/config.toml` or `$HOME/.config/vetpkg/config.toml`
- Windows: `%APPDATA%\vetpkg\config.toml`

## Development

See `CONTRIBUTING.md` for local build/test/CI expectations. Security issues: `SECURITY.md`. Architecture + phase specifications: `docs/plan/*.md`.

## License

Dual-licensed under your choice of Apache License 2.0 (`LICENSE-APACHE`) or MIT (`LICENSE-MIT`).

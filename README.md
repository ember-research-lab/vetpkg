# vetpkg

A local proxy registry that intercepts package manager installs (npm, PyPI, Cargo) and scores them against supply-chain security signals. Block known-bad versions; annotate suspicious ones.

## Design principle

A supply-chain security tool must not itself be a supply-chain risk. vetpkg compiles with **zero crate dependencies** — `Cargo.toml` `[dependencies]` is empty. The entire codebase is auditable by one person.

## Trust anchors

Exactly three things:

1. The Rust toolchain (rustc + cargo + stdlib)
2. A curl binary, auto-resolved to an absolute path at startup (`/usr/bin/curl` on Unix, `System32\curl.exe` on Windows). Override via `VETPKG_CURL_PATH` environment variable.
3. Nothing else.

No crate dependencies means no transitive supply-chain surface via Cargo. HTTPS is handled by shelling out to curl with argv-separated arguments (no shell interpolation, no CRLF injection).

## Platform support

Linux, macOS, Windows (all first-class in v1). CI gates every commit against all three.

## Status

Under active development. See `docs/plan/00-master-plan.md` for the master plan and `docs/plan/0[1-6]-*.md` for per-phase specs.

Phase 0 (foundation) implementation in progress.

## License

Dual-licensed under MIT or Apache-2.0 at your option.

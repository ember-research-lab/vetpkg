# Contributing to vetpkg

## The rule that shapes every other rule

**Zero crate dependencies. Ever.**

`Cargo.toml` `[dependencies]` must stay empty. Every PR that adds a dependency will be closed, no exceptions. This is not a style preference — it is the entire security premise of the project.

If a task seems to demand a dependency, either (a) the task doesn't belong in vetpkg, or (b) we write the code ourselves with scope constrained to exactly what we need. The DEFLATE decompressor is ~500 lines; the JSON parser is ~400; the YAML parser is ~500. Everything we need fits in one person's head.

## What contributions are welcome

- **Bug fixes** with a regression test demonstrating the prior-broken behaviour.
- **New signals** with synthetic fixture + false-positive-suite entry.
- **Adapter improvements** (npm metadata shapes, PyPI Simple quirks, Cargo sparse-index edge cases) with a minimal reproducer.
- **Threat-model coverage** additions: new attack pattern → new signal or signal-weight adjustment with evidence.
- **Portability fixes** for Windows/macOS edge cases.
- **Documentation**: clarifications, typo fixes, worked examples.

## What does NOT belong in vetpkg

- Anything requiring a crate dependency.
- Async runtime integration (we use stdlib threads on purpose; context explained in `docs/plan/00-master-plan.md`).
- Web dashboards, GUIs, or remote state sync — all state is local.
- Automatic self-update — rebuild from source is the only supported upgrade path.
- "Helpful" crate-ecosystem integrations that touch `cargo install`, `npm publish`, or similar. The tool defends against these, not integrates with them.

## Development workflow

```bash
git clone https://github.com/ember-research-lab/vetpkg.git
cd vetpkg
cargo build
cargo test                                    # runs the full suite (>300 tests)
cargo clippy --all-targets --no-deps -- -D warnings
cargo fmt --all -- --check
```

All four must pass locally before you open a PR. CI enforces the same gate across Linux, macOS, and Windows on Rust stable and 1.75.

### Adding a test

Tests live next to the code (`#[cfg(test)] mod tests` inside the module) for unit scope, and in `tests/phase*_*.rs` for integration scope. Integration tests **must not** contact external hosts; spawn a localhost `TcpListener` with canned responses. The `VETPKG_NO_EXTERNAL_NETWORK` env var trips an error in the HTTP client if you accidentally try.

### Adding a signal

1. Add a variant to `types::Signal` and a weight in `Signal::weight()`.
2. Create a module under `src/signals/` implementing the `signals::Check` trait for a Tier 0 signal, or a `scan_dir(extracted_dir, prior_artifact)` function for a Tier 1 signal.
3. Wire it into `engine::SecurityEngine::new()` (Tier 0) or `engine::orchestrator::score_tarball_with_context` (Tier 1/2).
4. Add unit tests covering both firing and non-firing cases.
5. Add an entry to the Phase 3 / Phase 4 false-positive suite (`tests/phase3_fp_suite.rs` or `tests/phase4_fp_50.rs`) demonstrating that the signal does not misfire on a representative clean package.
6. Update the threat-model matrix in `README.md` if the signal covers a new attack class.

### Adding a pattern

Patterns for the Tier 2 source/sink matcher live in `data/patterns/*.txt` and are compiled in via `include_str!`. Add the pattern, add a matcher test with a synthetic exfil fixture, and re-run `cargo test --test phase3_fp_suite --test phase4_fp_50` to confirm no false positives.

## Commit hygiene

- One logical change per commit.
- Messages: `feat(area): description`, `fix(area): description`, `test(area): …`, `docs: …`, `refactor(area): …`.
- Include a short rationale in the body when the change is non-obvious.
- All commits must compile, pass `cargo test`, and pass `cargo clippy -- -D warnings`.

## Security issues

Do not open a public issue. Follow `SECURITY.md`.

## License

By contributing you agree your contributions will be licensed under the dual MIT OR Apache-2.0 license of the project.

# Security Policy

## Philosophy

vetpkg is a supply-chain security tool. Its own supply chain is the thing attackers would most want to compromise. Every design choice reflects that.

- **Zero crate dependencies.** `Cargo.toml` `[dependencies]` is empty. There is no transitive graph. Every line of vetpkg's logic is committed to this repository.
- **No crates.io publication.** There is no `cargo install vetpkg` path. If a crate by that name exists on crates.io it is not from this project. Install only by cloning the source repository and building from it.
- **Single runtime dependency, pinned.** `curl`, resolved to an absolute path at startup (checked against known install locations before falling back to `PATH`). Override via `VETPKG_CURL_PATH`. The trust assumption on curl is documented and can be audited independently.
- **Argv-separated shell invocation.** Every process spawn uses `Command::arg()` individually. No shell interpolation. URLs and header values are rejected if they contain `\r`, `\n`, `\0`, or (for URLs) any non-printable character.
- **No self-update channel.** Upgrading means pulling the new source, reading the diff, and running `cargo build --release` again.
- **Opt-in network.** Set `VETPKG_NO_EXTERNAL_NETWORK=1` in CI or on air-gapped hosts; the HTTP client refuses any non-localhost call with a clear error.

## Reporting a vulnerability

Please email `abenshalom305@gmail.com` with subject `vetpkg security: <one-line summary>`. Include:

- Affected version (tag or commit SHA of the repository you built from)
- Reproduction steps — ideally a minimal fixture demonstrating the issue
- Impact analysis — what an attacker can do, and under what preconditions
- Suggested fix if you have one

You should receive an acknowledgement within **72 hours**. I will work with you privately to validate, fix, and coordinate disclosure. Fixed versions ship on a new git tag; I will credit you in the release notes unless you prefer otherwise.

Please do not open a public GitHub issue for a vulnerability before a fix has landed in a tagged release.

## Scope

**In scope:**
- Any path in vetpkg that would let a malicious upstream registry response compromise the user running vetpkg
- Any argv-injection, CRLF-injection, path-traversal, or other input-handling bug in the proxy, CLI, or adapters
- Any DoS that crashes the daemon given a bounded upstream response (unbounded responses are handled by explicit caps already)
- Any signal that can be suppressed by input crafted to hit a parser edge case
- Any false negative on a realistic attack pattern

**Out of scope:**
- The trust model of curl itself (that is explicitly one of our three trust anchors)
- Attacks requiring modification of the installed vetpkg binary (SolarWinds-class — you cannot defend against it without SLSA upstream)
- Social-engineering attacks on a contributor's GitHub account (though I will treat those seriously if reported)
- Theoretical attacks on the Rust toolchain itself

## Defence-in-depth choices

- All tarballs have a 200MB hard cap before buffering. Exceeding it returns 413, not a crash.
- All response headers read from curl are capped at 256KB before bailing with an error.
- DEFLATE input cap: 512MB. DEFLATE output cap: 512MB.
- Tar extraction refuses any path containing `..`, `/` not within `dest`, or absolute paths.
- Thread-per-connection is bounded by a 32-permit semaphore to prevent self-DoS.
- File locking uses atomic `OpenOptions::create_new` (zero FFI). Stale locks clear on timeout.
- All tests bind `127.0.0.1` only. No test reaches an external host.
- CI matrix runs every commit on Linux, macOS, and Windows.

## What an attacker cannot easily do

- Get code execution by sending a malformed tarball. Tar extraction is in-process with path validation; malformed gzip fails cleanly.
- Exfiltrate data via vetpkg itself — it does not send anything to any host you have not configured it to contact.
- Ship a crate to crates.io that users accidentally `cargo install` — you cannot, because we never take that install path and users are instructed to ignore it.
- Bypass scoring by adding versions after the initial metadata fetch. The SuspicionMap is scoped per (package, version); every tarball request re-checks it.

# Phase 0: Zero-Dependency Foundation (v2)

## Goal
Replace all external crates with stdlib-only infrastructure. `[dependencies]` is empty. Preserve signal logic via algorithmic reference from prior impl (`~/ember-tasks/vetpkg-core/output/vetpkg/src/engine/checks/`).

## Threat Model
| Attack | Year | Target Coverage |
|---|---|---|
| Axios RAT | 2026 | ✅ caught via HookCheck + NewDependency |
| Gluestack | 2025 | ✅ via MaintainerChange + PublishAnomaly (Phase 2) |
| Shai-Hulud 1+2 | 2025 | ✅ via HookCheck + TaintDetection (Phase 3) |
| @nx/s1ngularity | 2025 | ✅ via TaintDetection (Phase 3) |
| XZ Utils | 2024 | ✅ via BinaryBlob + BuildScriptDiff (Phase 2) |
| Vercel 2026 | 2026 | ✅ via PublishAnomaly (Phase 2) |
| TeamPCP | 2026 | ✅ via cross-ecosystem correlation (Phase 4) |
| tj-actions | 2025 | ✅ via audit-ci command (Phase 5) |
| SolarWinds | 2020 | ❌ OOS (vendor build compromise; requires SLSA) |

## Task 1: Project Scaffold + Core Types

`cargo init` produces empty `[dependencies]`. Create module tree. Port types from prior impl (`src/types.rs`) but strip all serde derives.

**Types** (`src/types.rs`):
- `Ecosystem` enum: `Npm`, `PyPI`, `Cargo`
- `PackageIntel` struct — package metadata after adapter normalization
- `Signal` enum — all signal variants (7 for Phase 0, +4 by Phase 3)
- `RiskScore { score: f64, signals: Vec<Signal> }`
- `Verdict` enum: `Allow`, `Warn`, `Block`
- `PolicyConfig` — thresholds, upstream URLs, port
- `RegistryAdapter` trait

**Platform helpers** (`src/platform.rs`):
- `config_dir() -> PathBuf` — `$XDG_CONFIG_HOME`/`%APPDATA%`/fallback
- `data_dir() -> PathBuf` — derived
- `resolve_curl() -> io::Result<PathBuf>` — scan `$PATH`, prefer `/usr/bin/curl` on Unix and `System32\curl.exe` on Windows, env override `VETPKG_CURL_PATH`

## Task 2: JSON Parser + Writer

`src/json/parser.rs`, `src/json/writer.rs`.

- `JsonValue` enum (Null, Bool, Number(f64), Str, Array, Object with Vec preserving order)
- Streaming on `BufReader<R: Read>` for full parse
- Schema-targeted extraction: given key paths, skip everything else
- Full JSON syntax including `\uXXXX` + surrogate pairs
- **Perf target: 1.5MB in <100ms** (pathological fixture in tests)

## Task 3: HTTP Server

`src/net/http_server.rs`. Localhost only. Request parser, response writer, chunked transfer. Case-insensitive header lookup via a helper (do not lowercase in-place).

## Task 4: HTTP Client (curl shelling, pinned path)

`src/net/http_client.rs`.

**Startup:** `resolve_curl()` from `platform.rs` runs once, result cached in a `OnceLock<PathBuf>`. If resolution fails, daemon refuses to start with clear error.

**Request:** `Command::new(curl_path)` with args `["-sS", "-i", "-L", "--max-redirs", "5", "--connect-timeout", "10", "--max-time", "30"]` + `-H` pairs + URL. argv-separated; never shell.

**Validation:** URL and header values rejected if they contain `\r`, `\n`, or `\0`. Prevents CRLF injection.

**Non-TLS (test):** direct `TcpStream` path for localhost mock tests.

## Task 5: Compression + Archive

- `compress/deflate.rs` — RFC 1951 decompression only (pure Rust attempt, **2-day timebox**, then vendor miniz.c). ~500–1000 LoC realistic.
- `compress/gzip.rs` — RFC 1952 header + deflate + CRC32.
- `archive/tar.rs` — ustar + **PAX headers (type `x`)** for long filenames. GNU `@@LongLink` not required (npm uses PAX).

## Task 6: SHA-256

`src/crypto/sha256.rs`. FIPS 180-4. Streaming via `Sha256 { ... update ... finalize }`. NIST test vectors.

## Task 7: Myers Diff + Entropy

`src/diff/myers.rs`, `src/analysis/entropy.rs`. Standard implementations; nothing novel.

## Task 8: Storage (Cross-Platform Atomic + Lock)

`src/store/mod.rs`, `src/store/cache.rs`, `src/store/config.rs`.

**Atomic write:** temp file + `fs::rename`. Both Unix and Windows support atomic rename on same filesystem.

**File lock (zero FFI):**
```rust
pub struct FileLock { path: PathBuf }
impl FileLock {
    pub fn acquire(target: &Path, stale_after: Duration) -> io::Result<Self>
    // OpenOptions::new().create_new(true).write(true).open(lockfile)
    // Retry with 50ms backoff. Break stale locks by mtime.
}
impl Drop for FileLock { /* remove lockfile */ }
```
`create_new` maps to `O_EXCL` (Unix) and `CREATE_NEW` (Windows) — both atomic.

**TOML parser:** minimal subset (key = value, `[section]`, string/int/bool), ~150 LoC.

## Task 9: CLI + Proxy Wiring

`src/cli/mod.rs`. Hand-rolled arg parser on `std::env::args()`. Subcommands: `daemon`, `init`, `status`, `policy`, `audit`, `audit-ci`.

**Proxy** (`src/net/proxy.rs`):
- `TcpListener::bind(127.0.0.1:9451)`
- Accept loop guarded by bounded semaphore (32 permits), one thread per accepted connection
- Graceful shutdown on SIGINT/SIGTERM via `AtomicBool`
- Routes: `/npm/*` active; `/pip/*`, `/cargo/*` return 501 in Phase 0

## Task 10: Signal Port

Port 7 signals from `ember-tasks/vetpkg-core/output/vetpkg/src/engine/checks/`:
`advisory`, `dep_diff` (→ `dependency.rs` with NewDependency), `freshness` (→ `fresh.rs`), `hooks` (→ `hook.rs`), `maintainer`, `popularity`, `typosquat`. Jaro-Winkler reimplemented in ~50 LoC. `top_npm.txt` via `include_str!`.

`SecurityEngine` in `src/engine/mod.rs` orchestrates. Policy thresholds from `PolicyConfig`.

## Test Rules (repeat)
- All network tests spawn a localhost mock upstream (random port, 127.0.0.1).
- `assert!(elapsed < perf_target)` for Tier 0 fixture.
- Temp dirs auto-cleaned via `Drop`.
- Integration test: proxy serves `/npm/express` against mock, verifies score=0.

## Success Criteria
1. `[dependencies]` empty ✔
2. Zero warnings on Linux/macOS/Windows ✔
3. All signal tests ported and passing (target ~50 tests carried from prior impl)
4. Axios fixture → `Block` with score ≥ 0.6
5. Clean express fixture → `Allow` with score < 0.3
6. `vetpkg daemon` starts, responds to `GET /npm/express` (mock upstream) in integration test
7. JSON parser handles 1.5MB in <100ms on CI
8. Gzip+tar extracts fixture with PAX long-filename entry correctly
9. Full test suite < 3 min on single core (one of the three OSes)

# Phase 2: Tarball Signals (v2)

**Prerequisite:** Phases 0–1 complete.

## Task 1: SuspicionMap + Streaming Forward
**Shared state:** `Arc<RwLock<HashMap<(String, String), Tier0Result>>>` with `Tier0Result { score, signals, timestamp }`.

**Lifecycle:** entries written by metadata handler when 0.15 ≤ score < 0.6. TTL **30 min**. Cleanup thread every 60s.

**Tarball interception** (`/npm/{pkg}/-/{file}.tgz` + scoped variants):
- Match URL → extract `(package, version)`
- SuspicionMap miss or score < 0.15: **streaming forward** — spawn curl, pipe stdout through 64KB buffer chunks directly to client socket. O(chunk) memory.
- Hit with score ≥ 0.15: buffer tarball to temp file (RAII `TempDir` with `Drop`), run Tier 1

**TempDir guard:**
```rust
struct TempDir(PathBuf);
impl Drop for TempDir { /* fs::remove_dir_all ignoring errors */ }
```

## Task 2: PublishAnomaly Signal (Tier 0)

Sub-checks (weights sum capped at 0.35):
- **Cadence (0.15):** compute `log(inter-publish interval in seconds)` over last 20 versions. Mean + MAD. Flag if latest `|log(i) - mean| > 3.5 × MAD`. Skip if <5 versions.
- **Hour-of-day (0.10):** histogram of publish hours (UTC). Flag if latest hour has <5% historical frequency.
- **Version sequence (0.10):** patch bump within 4h of major/minor when historical median patch interval >48h.
- Sub-check (c) tarball-git divergence is in **Tier 2** (Phase 4 correlation step).

## Task 3: BinaryBlobDetection Signal (Tier 1)

Non-code file entropy scan. Code-file allowlist unchanged from v1 **except remove `.svg`** (can embed JS).

**Scoring (capped 0.50):**
- New high-entropy (>7.0 bits/byte) file in `test*/` or `fixture*/`: 0.25
- New high-entropy file elsewhere: 0.15
- Compressed-within-compressed (`.xz`/`.gz`/`.bz2`/`.zip`/`.7z`/`.lz`/`.zst` inside tarball): 0.20
- Changed content of existing high-entropy file: 0.10

## Task 4: BuildScriptDiff Signal (Tier 1)

Tracked patterns: `Makefile`, `GNUmakefile`, `configure*`, `*.m4`, `CMakeLists.txt`, `*.cmake`, `binding.gyp`, `*.gyp*`, `rollup.config.*`, `webpack.config.*`, `vite.config.*`, `esbuild.*`, `build.rs`, `setup.py`, `setup.cfg`, `meson.build`.

Myers diff against cached prior version. Insertion patterns (narrowed to reduce Makefile false positives):
- Shell exec: `eval`, `exec`, `system(`, `popen(`, `sh -c`, `bash -c`, backtick execution
- Pipe chains: `| sh`, `| bash`, `| python`, `| perl`, `| ruby`, `| node`
- **Narrowed `$(` patterns:** `$(shell`, `$(curl`, `$(wget`, `$(eval`, `$(exec`
- Reading from test/data: `tests/`, `test/`, `fixtures/`, `testdata/` + `cat `/`xz -d`/`gzip -d` preceding
- Env: `export PATH=`, `export LD_PRELOAD`, `export LD_LIBRARY_PATH`
- Security removal: `landlock`, `seccomp`, `--disable-sandbox`, `--no-sandbox`

**Scoring:** shell exec 0.20, test/data read 0.25, decompression of test fixture 0.25, env manipulation 0.15, security removal 0.20, build-change-in-patch 0.10. Caps apply.

## Task 5: Tiered Orchestration

Tier 0 score + Tier 1 additive. Re-evaluate verdict after Tier 1. Only run Tier 2 if post-Tier-1 score ∈ [warn, block).

**Logging:** `[vetpkg] {pkg}@{ver} t0={s:.2} t1={s:.2} t2={s:.2} total={s:.2} verdict={v}`

## Test Rules
- XZ scenario: synthetic fixture with `tests/files/bad-corrupt.xz` + Makefile reading from it → score ≥ 0.70
- Stolen-token scenario: synthetic fixture with Sunday-3am publish vs Tuesday-afternoon history → PublishAnomaly ≥ 0.25
- Perf gate: Tier 1 on 5MB synthetic tarball < 600ms (20% headroom over 500ms target)
- No real package downloads; all tarballs in `tests/fixtures/tarballs/` pre-built

## Success Criteria
1. SuspicionMap TTL + cleanup verified with short-TTL test variant
2. Streaming-forward verified: serve 50MB tarball through proxy, measure peak process RSS < 10MB over baseline
3. XZ scenario blocked
4. Stolen-token scenario warns
5. All prior tests pass

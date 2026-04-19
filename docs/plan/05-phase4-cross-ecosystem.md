# Phase 4: Cross-Ecosystem Correlation (v2)

**Prerequisite:** Phases 0–3 complete.

## Task 1: PyPI Adapter

**Simple API (PEP 503):** `GET https://pypi.org/simple/{pkg}/` returns HTML.

**Tokenizer (not line-based):** scan for `<a ` and `</a>`, extract `href=` attribute, allow content across line breaks. ~20 LoC.

**JSON API:** `GET https://pypi.org/pypi/{pkg}/json` — standard metadata extraction.

**Proxy routes:** `/pip/simple/{pkg}/`, `/pip/packages/*` (tarball).

Python hook patterns added to `HookCheck`: shell-execution calls (the Python `os` and `subprocess` modules), `__init__.py` side effects, `setup.py` custom `cmdclass`.

## Task 2: Cargo Adapter (sparse index)

**Cargo install flow (correct model):**
1. Sparse index lookup: `GET index.crates.io/{ch1}{ch2}/{ch3}{ch4}/{crate}` returns JSON lines, one per version
2. Tarball download: `GET static.crates.io/crates/{crate}/{crate}-{version}.crate`

**Proxy routes:**
- `/cargo/index/{ch1}{ch2}/{ch3}{ch4}/{crate}` — intercept index, parse JSON lines, score per version, re-emit filtered JSON-lines response
- `/cargo/download/{crate}/{version}` — tarball interception

**User config to use proxy:** `.cargo/config.toml`:
```toml
[source.crates-io]
replace-with = "vetpkg"
[source.vetpkg]
registry = "sparse+http://127.0.0.1:9451/cargo/index/"
```
Documented in README.

**Metadata enrichment:** additionally query api/v1 once per crate for owner info (not on install hot path — async background enrichment).

Rate limit: 1 req/sec to `crates.io/api/v1/*`. User-Agent header mandatory.

## Task 3: Maintainer Correlation

`maintainer_index.json`: `email → [{ecosystem, package, last_seen}]`.

**LRU cap: 10,000 entries** by `last_seen`. Eviction on insert.

Multipliers: 2 ecosystems anomalous within 24h → 1.5×; 3+ ecosystems → 2.0×.

## Task 4: Package Name + URL Correlation

**Name correlation:** same-named anomalous (score > 0.15) package in another ecosystem within 48h → 2.0×. Rationale: cross-ecosystem name squatting spans hours, not weeks.

**URL correlation:** extract URLs from sink-matched lines during Tier 2 pattern matching.

**URL extraction rule:**
- If line contains a string literal (single/double/backtick quoted) containing `http://` or `https://`: extract URL up to the closing quote.
- Else: extract from `http` prefix to next whitespace or `<`/`>`.

Same URL in 2+ packages within 7 days → 2.5×. Rationale: attacker infrastructure is reused across weeks.

**Multiplier stacking** (cap 3.0): `final = min(base × maintainer × name × url, 1.0)`.

## Task 5: FP Corpus Expansion

Extend FP suite from 8 → **50+ packages** (Phase 3 deferred work). Document per-package score in test assertions for regression tracking.

## Test Rules
- All correlation tests use in-memory fixture index; no external writes
- Multiplier stacking test verifies cap at 3.0
- TeamPCP scenario: two packages share maintainer email, both PublishAnomaly 0.35 → after maintainer×1.5 × name×2.0 = 3.0 (cap) → 0.35 × 3.0 = 1.05 → clamp 1.0 → Block

## Success Criteria
1. PyPI Simple tokenizer handles multi-link-per-line and line-wrapped HTML
2. Cargo sparse index proxy intercepts real `cargo install` (verified via `.cargo/config.toml` + cargo's debug trace in integration test using mock sparse upstream)
3. Maintainer index bounded at 10,000
4. TeamPCP scenario blocked via correlation
5. FP suite: 50+ packages, all <0.15
6. All prior tests pass

# Phase 3: Deep Analysis (v2)

**Prerequisite:** Phases 0–2 complete.

## Task 1: Pattern Files

Built-in defaults via `include_str!` for JS/TS, Python, Rust. User overrides in `{config_dir}/patterns/` merged by union. Directive `# replace` in a user file excludes built-ins for that language.

Source/sink lists per `00-master-plan.md` linked reference; same as v1 Phase 3.

## Task 2: File Change Detection

Compute SHA-256 of each code file in extracted tarball. Compare against `file_manifest.json` from prior version. Only changed files analyzed in Task 3.

**Wholesale-repackaging guard:** if >80% of files changed vs prior version, suppress "new" scoring bonuses (treat as first-scan baseline). Applies per-version, not per-run.

## Task 3: Pattern Matcher

Line-by-line literal `contains()`. Comment handling:
- Skip line if starts with `//`, `#`, or is inside `/* */` block
- **Also strip trailing `//` and trailing ` #` before matching** (5 LoC delta)

**Assignment tracking:**
- Simple: `let`/`const`/`var`/`=` → extract identifier → check sink lines
- **Destructuring added:** `const { A, B } = source(...)` → record `A`, `B`. `const [a, b] = source()` likewise.

Language detection by extension. `.ts`/`.tsx` use JS patterns.

## Task 4: TaintDetection Signal (Tier 2)

Scoring (cap 0.50):
- Same-scope path (source+sink within 30 lines), new-in-version: 0.35
- Variable-name flow source→sink, new: 0.30
- File-level co-occurrence, new: 0.15
- Lone source or sink, new: 0.05

"New" gated by Task 2's repackaging guard.

## Task 5: False-Positive Suite

Phase 3 acceptance: 8 packages (express, react, lodash, next, axios, webpack, typescript, eslint) score <0.15.

**Deferred to Phase 4:** expand to **50+ packages**. Documented in Phase 4 constraints.

## Test Rules
- All fixtures are synthetic tarballs built at test-setup time via stdlib `tar+gzip`-format-writer helper (small utility, not production code — lives under `tests/fixtures/build.rs`)
- No real package downloads

## Success Criteria
1. @nx scenario fixture scores ≥ 0.35 via TaintDetection
2. 8 popular packages score <0.15
3. Repackaging guard verified: synthetic "everything-changed" fixture doesn't fire bonuses
4. User pattern file with `# replace` directive overrides built-ins
5. Destructuring test: `const { SECRET } = process.env; fetch(url, {body: SECRET})` → detected
6. All prior tests pass

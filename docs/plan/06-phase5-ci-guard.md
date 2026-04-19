# Phase 5: CI Pipeline Audit (v2)

**Prerequisite:** Phases 0–4 complete.

## Task 1: YAML Parser (flow-style included)

Line-oriented, indent-tracking, plus **minimal flow-style subset**:
- Block: key/value, nested maps, lists, `|` and `>` multiline blocks, comments
- **Flow (new):** single-line `{key: val, key2: val2}` and `[a, b, c]`
- NOT supported: anchors, aliases, tags, multi-document, complex keys

`YamlValue` enum with `get`/`as_str`/`as_list`/`as_map` accessors.

## Task 2: Action Reference Scanner

Parse each `.github/workflows/*.y{,a}ml`. Walk `jobs.*.steps[].uses` and `jobs.*.uses`.

**Severity:**
- SHA-pinned (40 hex chars): `Info`
- **`actions/*` tag-pinned: Medium** (GitHub-maintained; still mutable)
- Third-party tag-pinned: `High`
- Branch-pinned anything: `High`
- `docker://` reference: `Low`
- Local action (`./...`): `Info`

**Fix severity test to match rule** (v1 contradiction resolved).

## Task 3: Permission Scope

- No `permissions` key → `Medium`
- `permissions: write-all` → `High`; `read-all` → `Low`
- Specific: `contents: write`, `id-token: write`, `packages: write` scored per policy

## Task 4: Secret Exposure

- `${{ secrets.NON_GITHUB_TOKEN }}` inside `run:` → `High`
- `${{ secrets.GITHUB_TOKEN }}` in `run:` → `Low` (auto-rotated, scoped)
- Secret passed to third-party action via `env:` → `Medium`; to `actions/*` → `Low`
- `upload-artifact` with `path:` matching `.ssh`/`.aws`/`.env`/`.npmrc`/`.docker`/`.kube` → `Medium`

## Task 5: Tag Mutation Detection (`--online`)

`GET api.github.com/repos/{o}/{a}/git/ref/tags/{tag}`.

**Annotated tag handling (new):** if `object.type == "tag"`, follow `git/tags/{object.sha}` to extract the underlying commit. Compare resolved commit SHA.

**Cache** `ci_cache.json`: `{action@tag: {sha, checked_at, tag, resolution_path}}`. Valid 24h.

**First-scan honesty:** report wording distinguishes:
- "baseline established (first scan — no prior reference)"
- "baseline verified against scan from {Nd ago}"

Rate limit: pause online checks when `X-RateLimit-Remaining < 10`, continue offline.

## Task 6: CLI + Report

`vetpkg audit-ci [--path DIR] [--online] [--strict] [--json]`

Exit codes: 0 = ok (or non-strict), 1 = strict + findings, 2 = error.

Report format per v1, with `--json` structured output.

## Test Rules
- YAML fixtures covering flow-style, multiline `run:`, reusable workflows
- Mock GitHub API server for `--online` tests
- Annotated tag fixture: response has `object.type: "tag"` → verify 2-hop resolution

## Success Criteria
1. Flow-style YAML parses: `permissions: {contents: read}` correctly
2. Annotated tag fixture resolves to underlying commit
3. First-scan report wording explicit about lack of prior baseline
4. `--strict` with findings exits 1
5. All prior tests pass
6. **Final**: all 6 phases complete, ~13,000 LoC, zero crate deps, cross-platform CI green

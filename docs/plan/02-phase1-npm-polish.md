# Phase 1: npm Polish (v2)

**Prerequisite:** Phase 0 complete.

## Task 1: Scoped Packages
- Router matches `/@scope%2f*` and `/@scope/*`, decodes to `(@scope, package)`
- Upstream URL: `https://registry.npmjs.org/@scope%2fpackage`
- Expand `top_npm.txt` to 1,200+ entries including `@babel/*`, `@types/*`, `@angular/*`, `@vue/*`, `@vercel/*`, `@typescript-eslint/*`, `@eslint/*`, `@nestjs/*`
- Typosquat compares full `@scope/name` string

## Task 2: Abbreviated Metadata
- Detect `Accept: application/vnd.npm.install-v1+json` in request
- Proxy always fetches full metadata upstream (need maintainers/time for scoring)
- Strip to abbreviated shape on response when client asks: keep `name`, `dist-tags`, `versions.{v}.{name,version,dependencies,dist,_hasShrinkwrap}`, `modified`
- Return `Content-Type: application/vnd.npm.install-v1+json`

## Task 3: Dep Age Auto-Resolution
- On `NewDependency`, fetch each new dep's metadata (max 5 deps per scoring run)
- Extract `time.{latest}` → age_hours
- Per-fetch timeout 3s; on timeout, proceed without that dep's age
- `FreshPackage` consumes `dep_ages: HashMap<String, f64>`

## Task 4: Live OSV (on-demand API)
- `POST https://api.osv.dev/v1/query` with `{package: {name, ecosystem}, version}`
- **Severity extraction order:** (a) `vulns[].severity[0].score` (CVSS v3 string) → normalize to CRITICAL/HIGH/MEDIUM/LOW via score bands; (b) `vulns[].database_specific.severity` string; (c) default HIGH
- Weights: CRITICAL=0.5, HIGH=0.4, MEDIUM=0.2, LOW=0.1
- Cache in `osv_cache.json` keyed by `(ecosystem, name, version)` with 1-hour TTL
- On API failure: use cached value (even if expired) + log warning. Never block scoring.

## Task 5: Lockfile Audit
`vetpkg audit [--path DIR] [--full] [--json] [--fail-on-warn]`

Parse `package-lock.json` v2/v3 (v1 explicitly unsupported with clear error). Score each resolved package.

**Performance SLA:**
- Without `--full`: metadata-only scoring from lockfile data, **< 30s for 1,000 packages**
- With `--full`: parallel upstream fetches via 10-thread pool, **< 120s for 1,000 packages**

**Report:** human-readable (grouped by verdict, sorted by score desc) or JSON.

## Test Rules
- Mock OSV API via localhost server with canned responses
- Mock npm registry for dep-age fetches
- Lockfile fixture in `tests/fixtures/package-lock-v3.json`

## Success Criteria
1. `@vercel/next` routes and scores
2. Abbreviated metadata returned when requested, with correct Content-Type
3. OSV severity extraction via the 3-tier fallback works on fixture responses
4. `vetpkg audit` completes SLA on 1,000-package fixture lockfile
5. All Phase 0 tests still pass

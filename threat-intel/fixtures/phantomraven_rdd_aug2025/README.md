# phantomraven_rdd_aug2025

## Pattern

PhantomRaven was disclosed by Koi Security in late Oct 2025 after
running active in npm from August 2025. **126 npm packages, 86,000+
installs.**

The novel TTP is **Remote Dynamic Dependencies (RDD)**: packages
declare *HTTP-URL* dependencies in their package.json or lockfile,
pointing at attacker-controlled domains (`packages.storeartifact.com`,
others). npm fetches the URL at install time. Registry-based scanners
look at the registry metadata for declared dependencies and ignore
the URL — static analysis reports "0 dependencies" while the install
actually pulls arbitrary code from the attacker's CDN.

## Why vetpkg catches this

vetpkg's `check_resolved_urls` (in `src/cli/audit.rs`) walks every
package in the lockfile and asserts the `resolved` field's host
matches the configured registry (default `registry.npmjs.org`). Any
non-registry host fires `Signal::ResolvedUrlMismatch` with the
mismatched URL captured for the audit log.

This fixture's lockfile contains:
- `phantomraven-bait@1.2.3` resolving to `packages.storeartifact.com`
- `@helpful-utils/parser@2.0.0` resolving to `cdn.attacker.example`
  (uses `http://` rather than `https://`, doubly suspicious)

Both should fire `WARN` with `ResolvedUrlMismatch`. The two clean
packages (`express`, `lodash`) should resolve to npm and verdict
`Allow`.

## Severity calibration target

The corpus extension §2.1 argues HTTP-URL deps should be **CRITICAL**
not WARN — non-registry resolution is a zero-trust signal. The v0.3
catch fires WARN. This fixture pins current behaviour; severity
escalation will be detectable when it lands. Tracked as v1.5
hardening.

## Sources

- Koi Security, "PhantomRaven", Oct 29 2025.
- CSO Online, PhantomRaven analysis, Oct 30 2025.
- Dark Reading, PhantomRaven RDD coverage, Oct 31 2025.

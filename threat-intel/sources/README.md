# Monitored Sources — vetpkg

Curated list of feeds, advisories, and research streams that surface
new package-supply-chain attack patterns. Living document; add via PR
with rationale, remove when a source goes dark.

## Vulnerability databases (high-signal, structured)

- **OSV** — `https://osv.dev/`. Multi-ecosystem; primary signal for
  the `Advisory` rule.
- **GitHub Security Advisories** — `https://github.com/advisories`.
  Often include reproduction notes that translate directly into
  fixtures.
- **Snyk Vulnerability DB** — `https://security.snyk.io/`. Useful
  cross-check; verify against OSV/GHSA before adding fixtures.
- **PyPA advisory database** — `https://github.com/pypa/advisory-database`
  for PyPI specifically.
- **RustSec advisory database** — `https://rustsec.org/` for Cargo.

## Research streams

- **Phylum, Sonatype, Socket** quarterly threat reports — supply-chain
  attack trends (typosquats, dependency confusion, install-script
  payloads).
- **Snyk security blog** — concrete attack walkthroughs.
- **Aqua Nautilus** — npm/PyPI ecosystem research.
- **GitGuardian** — credential-leak research that overlaps with the
  build-script analysis path.

## Standards

- **OWASP Software Supply Chain Top 10** — categorical reference.
- **NIST SSDF** — structured framework, useful for mapping rules to
  recognized categories in customer conversations.

## Internal sources

- **Issue tracker** — anything we discover in our own dogfooding or
  reported by users.
- **Agent monitor's findings** — the cross-tool integration. If
  the agent monitor catches a tool poisoning at runtime that vetpkg
  *should* have caught at install time, that's a vetpkg gap and lands
  here.

## Process

Each PR that adds a fixture or rule cites at least one source from
this list (or a new one with rationale). CHANGELOG.md aggregates these
citations at release time.

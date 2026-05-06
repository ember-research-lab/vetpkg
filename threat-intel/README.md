# Threat-Intel — vetpkg

Same shape and discipline as `ember-agent-monitor/threat-intel/`: every
attack pattern adopted into the vetpkg rule library lands here as a
fixture with pinned expected verdicts. CI runs every fixture on every
change; a regression that drops a verdict is a red build.

## Sources we monitor

See `sources/README.md`. Curated list of feeds, advisory databases, and
research streams that surface new package-supply-chain attack patterns.

## Fixture format

```
fixtures/<name>/
├── README.md              — what attack class, source citation, severity
├── tarball.tgz            — synthetic malicious tarball (or raw files)
├── lockfile.json          — synthetic lockfile referencing it
├── metadata.json          — synthetic npm/PyPI metadata
└── expected.json          — pinned verdict + signal short-labels
```

The runner loads the fixture, drives the appropriate analysis path
(metadata-only or full-tarball), and asserts the vetpkg orchestrator's
verdict + signals match `expected.json`.

## Adding a fixture

1. Add the synthetic artifacts under a new directory.
2. Pin expected verdict + signal short-labels via the same
   `signal_short_label` function vetpkg uses internally (so the test
   fails when label format drifts).
3. Add a CHANGELOG.md entry citing the source.
4. Run the regression test.

## What this directory replaces

Previously, vetpkg's adversarial coverage lived as inline unit tests
(e.g., the XZ-style scenario in `engine/orchestrator.rs`'s test module).
Inline tests are fine for fast iteration during initial development;
they're not the right home for a *catalog* of attack patterns that
needs to grow over years and be audit-readable across releases. The
threat-intel/ dir is that catalog.

Inline tests stay; new attack patterns and migrated existing patterns
both land here.

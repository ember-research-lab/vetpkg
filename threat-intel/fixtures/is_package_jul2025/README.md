# is_package_jul2025

## Pattern

Jul 19 2025: the popular `is` npm package — millions of weekly
downloads — was hijacked. Malicious versions 3.3.1 and 5.0.0 were
published from the legitimate maintainer's account after that
account was compromised (phishing, leaked token, or social
engineering — exact vector public-disclosed in subsequent CrowdStrike
analysis).

The shape that distinguishes this from a fresh-publisher attack:
**same maintainer account, but long-dormant.** No new maintainers
were added. Pure account-compromise → publish.

## Why this fires only Warn (not Block)

vetpkg's `MaintainerChange` signal catches *new* maintainers (added
to a package). It does NOT catch dormant-account-suddenly-active.
Two other signals do fire on the malicious version:

- `Hook(postinstall:matches 'node -e')` — the postinstall command
  exfiltrates hostname via a node one-liner
- `Fresh(0.5h)` — publish-time below the freshness floor

These compose to **Warn**, not Block. An honest gap.

## What's needed for Block

A new `DormantMaintainer` signal that compares
`publish_time` of the current version against the most recent prior
publish from the same maintainer. Long gap (e.g., > 1 year) +
publish = strong dormant-account signal. Tracked for v1.5
hardening.

This fixture pins the *current* behaviour. When the new signal
lands, expected.json gets bumped from Warn → Block, the new signal
gets added to `signals_contain`, and the fixture serves as the
regression test for the hardening.

## Sources

- Avertium / CrowdStrike, hijack-of-`is` analysis, Jul 18-19 2025.
- Socket, malicious-`is` versions writeup.
- Corpus extension §2.1.

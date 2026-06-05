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

## Status update (2026-05-09): gap closed

This fixture was originally landed as a gap pin: vetpkg's
`MaintainerChange` signal caught new maintainers but NOT
dormant-then-active accounts. Verdict was Warn, not Block.

The new `DormantMaintainer` `PublishAnomalyKind` (committed
2026-05-09) closes the gap. Detection: maintainer set unchanged
+ previous publish > 12 months ago + ≥1 prior version in
publish_history. Weight 0.30 — heavier than other publish
anomalies because dormant-account compromise with new behavior
is a strong-signal hijack pattern, not a calibration blip.

The fixture now serves as the regression test for the new signal.

## Pinned findings (current behaviour)

Four signals fire → **Block**:

- `Hook(postinstall:matches 'node -e')` — the postinstall
  command exfiltrates hostname via a node one-liner
- `Fresh(0.5h)` — publish-time below the freshness floor
- `Publish(Cadence)` — 7-year gap is a wild outlier vs. the
  historical mean (the existing cadence rule fires for free now
  that publish_history is populated)
- `Publish(DormantMaintainer)` — the new signal: 7-year gap from
  the previous publish, same maintainer set

## Historical context

Original framing (now superseded but preserved as the canonical
example of how the corpus tracks gaps):

> vetpkg's `MaintainerChange` signal catches *new* maintainers
> (added to a package). It does NOT catch dormant-account-
> suddenly-active. Two other signals do fire on the malicious
> version: `Hook(postinstall)` and `Fresh(0.5h)`. These compose
> to **Warn**, not Block. An honest gap.

The fixture explicitly documented the expected fix path: "When
the new signal lands, expected.json gets bumped from Warn →
Block, the new signal gets added to `signals_contain`, and the
fixture serves as the regression test for the hardening." That
forecast is now realized.

## Sources

- Avertium / CrowdStrike, hijack-of-`is` analysis, Jul 18-19 2025.
- Socket, malicious-`is` versions writeup.
- Corpus extension §2.1.

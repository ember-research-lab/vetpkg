# promptmink_famous_chollima_apr2026

## Pattern

Apr 29 2026 ReversingLabs disclosure. 60+ npm packages, 300+
versions, 4 distinct payload architectures, 20+ pieces of C2
infrastructure. Attributed to **Famous Chollima** (DPRK).

The novel TTP, called **LLM Optimization (LLMO)** by ReversingLabs:
the campaign is engineered to deceive AI coding agents rather than
human developers. Documentation quality and semantic fit are gamed
for AI dependency selection — analog to SEO for human search results.

Layered architecture:
- **Layer 1** packages accumulate reputation (downloads, stars,
  realistic dependency relationships)
- **Layer 2** packages are expendable ammunition. When burned,
  byte-identical code republishes under a new name with sequential
  version (e.g., `@hash-validator/v2` → `@validate-sdk/v2` starting
  at `v1.22.11`), and Layer 1's dependency pointer swaps same-day.
  No operational downtime.

Defeat strategy against LLM source review: pivot to **SEA bundles**
(Single Executable Application) + **NAPI-RS Rust addons** (`.node`
files). A reviewer reads the JS shim and sees nothing wrong; the
harm lives in the binary.

## Why this is the canonical tarball-driven fixture

It exercises `BinaryBlobDetection` — vetpkg's catch on the
LLM-defeating delivery shape. The rule fires on any high-entropy
(>7.0) non-source file outside a test directory. Both planted
binaries (`native/addon.node` + `dist/sea-bundle`) trigger.

The synthetic file content is `/dev/urandom` bytes. **No real
malware ships in this fixture.** The structural harm — putting a
high-entropy binary in `node_modules/<pkg>/native/` — is what gets
caught, not the specific bytes inside.

## Pinned outcome

- 2× `BinaryBlobDetection` (NewHighEntropyElsewhere) on
  `dist/sea-bundle` and `native/addon.node`
- Verdict: **Warn**

Block would require additional signals. The full LLMO catch
needs:
1. `DormantMaintainer` (tracked for v1.5 hardening, see
   `is_package_jul2025` fixture).
2. A yet-unimplemented `LLMOPattern` signal that fingerprints
   sequential republishing across sibling names — corpus
   extension §3.4 calls for `vetpkg flags Layer 2 packages
   and tracks burn-and-replace pattern as critical signal`.

These are tracked as v1.5+ hardening; this fixture pins the
binary-blob layer's catch independently so the additions are
detectable.

## Sources

- ReversingLabs, "PromptMink: DPRK npm campaign", Apr 29 2026.
- Barrack AI, "PromptMink: How North Korea Tricked Claude Into
  Installing npm Malware", May 2026.
- Corpus extension §2.1 + §3.4.

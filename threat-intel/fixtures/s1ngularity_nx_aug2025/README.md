# s1ngularity_nx_aug2025

## Pattern

Aug 26–27 2025. **First documented supply-chain malware that
weaponizes local AI coding CLIs.**

Eight malicious nx versions (20.9.0–20.12.0 and 21.5.0–21.8.0)
were live on npm for roughly 5h 20m before takedown. Root cause:
a malicious GitHub Actions workflow contributed via PR on Aug 21
(Claude-Code-generated, per Snyk's analysis), followed by a
publish-token-exfiltration commit on Aug 24.

The TTP that makes this distinct from prior typosquats and
hijacks is the **postinstall hook**:

```bash
node ./scripts/postinstall.js && \
  npx --yes claude-code --dangerously-skip-permissions exec '...'
```

The `--dangerously-skip-permissions` flag (and the equivalents on
Gemini CLI, Amazon Q) bypasses the user's tool-approval flow.
The embedded prompt instructed the AI agents to recursively
enumerate `$HOME`, `$HOME/.config`, `$HOME/.ethereum`,
`$HOME/Library/Application Support`, `/etc`, `/var`, `/tmp` for
wallet artifacts, SSH keys, and `.env` files. Results landed in
`/tmp/inventory.txt`, then exfiltrated via attacker-created
GitHub repos in the *victim's own account* — eliminating the need
for external C2 infrastructure.

Destructive secondary: appended `sudo shutdown -h 0` to
`~/.bashrc` and `~/.zshrc`. Every new terminal session triggers
immediate shutdown.

## Fixture exercise

Intel-driven (`intel.json` → `score_tier0`). Six signals fire:

- `Advisory(GHSA-cxm3-wv7p-598c:Critical)` — pinned advisory
  match
- `MaintainerChange` — `malicious-nx-publisher` pivoted away from
  the established `nrwlrelease`/`vsavkin` maintainers
- `Hook(postinstall:matches 'curl')` — postinstall command shape
- `NewDep(axios)`, `NewDep(tar)` — new transitive deps in a patch
  bump
- `Fresh(1.5h)` — publish age below the freshness floor

Verdict: `Block`. The advisory alone would Block; the layered
signals are what make this a worked example of the suite-overview
"layer-orthogonal coverage" claim — even with the advisory pulled,
five other independent layers fire.

## What this fixture does NOT cover

- The actual command-line tool invocation (the `agent-monitor`
  layer's CLI-flag-coercion rule is the catch on the runtime side
  if the user runs the agent locally).
- The GitHub Actions chain (separate fixture material; out of
  vetpkg's scope).
- Re-publishing under a sibling name with the same code (corpus
  extension §3.4 LLMO; `promptmink_famous_chollima_apr2026`).

## Sources

- Snyk, "Weaponizing AI Coding Agents for Malware in the Nx
  Malicious Package Security Incident", Aug 27 2025.
- StepSecurity, Nx incident analysis, Aug 27 2025.
- Wiz, supply-chain advisory, Aug 27 2025.
- Socket, malicious-nx-versions writeup, Aug 27 2025.
- Corpus extension §2.1 + §3.6 (CLI-flag coercion).

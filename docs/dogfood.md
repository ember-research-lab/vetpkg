This page describes the Ember lab's own setup as an example; paths and unit names are the lab's, adapt them to your machine.

## Dogfood (Ember lab)

```bash
# lockfile-less CI audit over the lab repos (exit 1 on any Medium+ with --strict):
vetpkg audit-ci --strict --path ~/ember-research-lab/ember-local
# proxy as a user service (npm route active; pip/cargo routes are pending, see the README):
cp contrib/systemd/vetpkg.service ~/.config/systemd/user/ && systemctl --user enable --now vetpkg
# findings land in ~/.ember/vetpkg/findings.jsonl (read by ember-agent-monitor's integrate module)
# periodic CI audit: contrib/systemd/vetpkg-audit-ci.{service,timer}
```

`audit` reads `package-lock.json`, `Cargo.lock` and `uv.lock`: `--path DIR` audits every one found in
DIR and lists them, and errors (exit 2, naming the supported files) when there is none. The lab's Rust
repos therefore audit today (`vetpkg audit --path ~/ember-research-lab/ember-network`). ember-local
(PEP 723 inline `mcp>=1.22.0,<2`, no lockfile yet) needs a `uv.lock`; `requirements.txt` with hashes is
still open (#14).

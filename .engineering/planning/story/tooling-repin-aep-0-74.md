---
format: aep.planning-md/3
id: story:tooling-repin-aep-0-74
kind: story
status: active
title: Move the planning store and pins to AEP 0.74.0
relations:
- decomposes: epic:foundations
- serves: vision:mandate
revision: 3
transitions:
- {from: "draft", to: "proposed", at: "2026-10-16T21:58:37Z", actor: "human:timo", revision: 2, decided_on: {"asserted":{"review_outcome":1}}}
- {from: "proposed", to: "active", at: "2026-10-16T21:58:37Z", actor: "human:timo", revision: 3, decided_on: {"asserted":{"review_outcome":1}}}
---
# Move the planning store and pins to AEP 0.74.0

## Acceptance

Given AEP 0.74.0 is the `aep` on this machine's PATH, when the repository's pins, `README.md`'s tool
lines and `cargo xtask check`'s required version name 0.74.0 and the store is migrated if 0.74.0
asks for a migration (`aep plan store migrate git --dry-run`, then `--verify`), then
`aep plan artifact validate` is valid under 0.74.0 and `task check` passes with the `aep` on PATH,
without a scratch shim to an older binary.

## Scope

- `xtask/src/main.rs` (the `version("aep", …)` line of `check`)
- `README.md`, `docs/public/development.md` (tool lines)
- `.engineering/` (only through `aep plan store migrate`, if 0.74.0 asks for it)
- CI workflow pins of `aep`, if any

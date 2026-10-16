---
format: aep.planning-md/3
id: story:tooling-repin-0-73-0-60
kind: story
status: implemented
title: Move the store and the pins to AEP 0.73.0 and ESS 0.60.0
relations:
- decomposes: epic:foundations
- serves: vision:mandate
revision: 4
transitions:
- {from: "draft", to: "proposed", at: "2026-10-15T13:00:01Z", actor: "human:timo", revision: 2}
- {from: "proposed", to: "active", at: "2026-10-15T13:00:01Z", actor: "human:timo", revision: 3}
- {from: "active", to: "implemented", at: "2026-10-15T21:47:36Z", actor: "human:timo", revision: 4, decided_on: {"recorded":{"test_result":1}}}
---
# Move the store and the pins to AEP 0.73.0 and ESS 0.60.0

## Acceptance

Given `cargo xtask check` requires `aep 0.71.2` and `ess 0.59.0` (`xtask/src/main.rs:112`, `:595`), the workspace pins the ESS crates at 0.59.0 (`Cargo.toml:24-26`) and CI installs `ess:0.59.0 aep:0.71.2` (`.github/workflows/ci.yml:24`), when every pin moves to AEP 0.73.0 and ESS 0.60.0, then:

- `aep plan store migrate git --dry-run` under 0.73.0 reports the store already on `aep.project/5` with nothing to migrate, and `aep plan artifact validate` prints `valid`;
- `systems/mandate/ess-inputs.yaml` declares `requires: ess 0.60.0`, and `ess specify validate --strict-requires --path systems/mandate` under 0.60.0 exits 0; `cargo xtask check` runs that strict form;
- `cargo xtask generate` under 0.60.0 reproduces `generated/` with no drift, and `cargo xtask conform` states its scenario counts beside the 0.59.0 counts, each changed scenario named on the wave page;
- `cargo deny --locked check` passes with no advisory ignore: ESS 0.60.0 no longer depends on `serde_yaml`, so `unsafe-libyaml` leaves the lock;
- an `ess:hardening` pass on the green suite is recorded on the wave page, its findings fixed or filed as stories;
- `README.md`, `AGENTS.md` and `docs/public/development.md` name Rust 1.98.1 (`rust-toolchain.toml`), ESS 0.60.0 and AEP 0.73.0.

## Scope

- `Cargo.toml`, `Cargo.lock`, `deny.toml`
- `systems/mandate/ess-inputs.yaml`, `generated/`
- `xtask/src/main.rs`, `xtask/src/conform.rs`, `xtask/src/emit.rs`
- `.github/workflows/ci.yml`
- `README.md`, `AGENTS.md`, `docs/public/development.md`, `docs/handoff.md`

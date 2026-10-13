---
format: aep.planning-md/3
id: story:aep-repin-0-71
kind: story
status: implemented
title: Move the planning tooling pin to AEP 0.71.2
relations:
- decomposes: epic:foundations
- serves: vision:mandate
revision: 4
transitions:
- {from: "draft", to: "proposed", at: "2026-10-13T05:20:16Z", actor: "human:timo", revision: 2}
- {from: "proposed", to: "active", at: "2026-10-13T05:20:16Z", actor: "human:timo", revision: 3}
- {from: "active", to: "implemented", at: "2026-10-13T06:26:29Z", actor: "human:timo", revision: 4, decided_on: {"recorded":{"test_result":1}}}
---
# Move the planning tooling pin to AEP 0.71.2

## Acceptance

Given `cargo xtask check` requires `aep 0.69.1` (`xtask/src/main.rs:595`) and CI installs `aep:0.69.1` (`.github/workflows/ci.yml:24`), when every pin moves to 0.71.2, then `cargo xtask check` passes with `aep 0.71.2` first on `PATH`, the CI job installs 0.71.2 and passes, and `AGENTS.md`, `README.md` and `docs/handoff.md` name 0.71.2.

## What changes between 0.69.1 and 0.71.2

Read from the AEP release notes 0.70.0 to 0.71.2: `migrate git` takes `--planning-scope` and derives the scope from `origin`; `project.yaml` admits an optional `findings_required_since` (this store does not set it, so `validate` behaves as before); `evidence` admits ordinary ESS conformance suites and the `go-scenario-status/2` producer profile. No change to the `aep.project/5` layout or to the evidence record files `cargo xtask conform --release` reads is announced; the conformance tests that read that layout are the check.

## Scope

- `xtask/src/main.rs` — cited
- `.github/workflows/ci.yml` — cited
- `AGENTS.md`, `README.md`, `docs/handoff.md` — cited
- `xtask/tests/conform.rs`, `xtask/tests/adversary_conform_1.rs` — cited, doc comments naming the measured version

---
format: aep.planning-md/3
id: story:audit-docs-truth
kind: story
status: implemented
title: Public and architecture documents state what 0.9.0 ships
relations:
- decomposes: epic:foundations
- serves: vision:mandate
revision: 4
transitions:
- {from: "draft", to: "proposed", at: "2026-10-16T20:19:46Z", actor: "human:timo", revision: 2}
- {from: "proposed", to: "active", at: "2026-10-16T20:19:46Z", actor: "human:timo", revision: 3}
- {from: "active", to: "implemented", at: "2026-10-16T21:02:49Z", actor: "human:timo", revision: 4, decided_on: {"recorded":{"test_result":1}}}
---
# Public and architecture documents state what 0.9.0 ships

## Acceptance

Given the documents the audit names, when each claim is checked against `crates/mandate-server/src/routes.rs` (nine routes), the `serve` flags in `services/control-plane/src/main.rs`, `CHANGELOG.md` 0.9.0 and the obligations ledger (41 rows on `decision-blocker:guards`, 34 of them deferred, 2 on `decision-blocker:audit-routing`), then every route list, flag list, count, version, binary description and release-link reference agrees with the code, `README.md:7` describes 0.9.0 as the changelog records it, the tool-pin lines (`README.md` "Use Rust …", `docs/public/development.md` "Install Rust …") are left to their own owner, and `cargo xtask documents` passes. Implemented in this wave by the documentation pass on the integration branch.

## Scope

- `README.md`, `CHANGELOG.md`
- `docs/public/architecture.md`, `docs/public/contracts.md`, `docs/public/development.md`, `docs/public/roadmap.md`, `docs/public/federated-login.md`
- `docs/handoff.md`
- `docs/architecture/command-obligations.md`, `docs/architecture/adapter-contract.md`, `docs/architecture/federated-login.md`
- `bins/mandate/src/main.rs` (the `--help` doc comment)

## Source

Audit G-34, G-37, G-72, G-73, G-74, G-75, G-76, G-77, G-78, G-79, G-80, G-81, G-82 (doc part), G-83, G-84, G-85, G-86, G-88, G-89, and the doc sentence of G-01.

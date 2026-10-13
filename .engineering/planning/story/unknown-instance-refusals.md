---
format: aep.planning-md/3
id: story:unknown-instance-refusals
kind: story
status: implemented
title: Declare the unknown-instance refusal on commands that act on an existing record
relations:
- decomposes: epic:foundations
- serves: vision:mandate
revision: 8
transitions:
- {from: "draft", to: "proposed", at: "2026-10-13T05:20:16Z", actor: "human:timo", revision: 2}
- {from: "proposed", to: "active", at: "2026-10-13T05:20:16Z", actor: "human:timo", revision: 3}
- {from: "active", to: "implemented", at: "2026-10-13T06:26:29Z", actor: "human:timo", revision: 8, decided_on: {"recorded":{"test_result":1}}}
---
# Declare the unknown-instance refusal on commands that act on an existing record

## Why

Under ESS 0.59.0 the conformance synthesizer writes a `wrong-state` scenario for a command acting on an identity no record carries; that is ESS's decided rule (absence is wrong-state unless the command declares an `unknown_instance:` outcome). Mandate's handlers answer `denied` for an unknown identity, so 15 synthesized `<Command>/outcome/wrong-state` scenarios fail: credential (`DisableResourceServer`, `RedeemAuthorizationCode`, `RetireSigningKey`, `RevokeAccessCredential`, `RevokeSigningKey`), federation (`DisableFederationConnection`, `DisableOAuthClient`, `UnlinkExternalPrincipal`), graph (`DeregisterResource`), identity (`RevokeSession`), tenancy (`CloseOrganization`, `RemoveOrganizationMembership`, `RemoveTeamMembership`, `RetireSpace`, `RetireTeam`). A handler that answers `denied` for 15 of 15 passes once the scenario expects that refusal.

`unknown_instance:` is an `ess/15` construct; `systems/mandate/system.yaml` declares `format: ess/4`, so the specification's format is raised first. A probe raising it to `ess/22` dropped 20 synthesized wrong-state scenarios (180 to 160); the raise must name every scenario it removes and why.

## Outcome

Narrowed 2026-10-13: the specification is on the newest format ESS 0.59.0 accepts, and every synthesized scenario the raise removes is named. The 15 `unknown_instance:` declarations are `story:unknown-instance-non-disclosing`.

## Acceptance

Narrowed 2026-10-13, after the wave 6 measurement. `systems/mandate/system.yaml` declares `format: ess/24`, the newest format ESS 0.59.0 accepts, `ess specify validate --path systems/mandate` exits 0, `cargo xtask generate` reproduces `generated/` with no drift, and `cargo xtask conform` runs the synthesized suite at 181 scenarios beside 201 at `ess/4`, with each of the 20 removed scenarios named on the wave 6 page (`docs/plans/2026-10-13-wave-6-execution.md`). No handler changes its answer.

Declaring `unknown_instance:` on the 15 commands moved to `story:unknown-instance-non-disclosing`: under ESS 0.59.0 the declaration needs a distinct outcome, which would disclose whether a record exists.

## Scope

- `systems/mandate/system.yaml`, `systems/mandate/domains/{credential,federation,graph,identity,tenancy}.yaml` — inferred
- `generated/` — regenerated
- `contracts/expected-outcomes.json`, `contracts/conformance/injections.json` — inferred
- `crates/mandate-conformance/src/commands/` — inferred, if a target adapter must report the new outcome

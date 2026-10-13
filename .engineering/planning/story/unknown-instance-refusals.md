---
format: aep.planning-md/3
id: story:unknown-instance-refusals
kind: story
status: active
title: Declare the unknown-instance refusal on commands that act on an existing record
relations:
- decomposes: epic:foundations
- serves: vision:mandate
revision: 3
transitions:
- {from: "draft", to: "proposed", at: "2026-10-13T05:20:16Z", actor: "human:timo", revision: 2}
- {from: "proposed", to: "active", at: "2026-10-13T05:20:16Z", actor: "human:timo", revision: 3}
---
# Declare the unknown-instance refusal on commands that act on an existing record

## Why

Under ESS 0.59.0 the conformance synthesizer writes a `wrong-state` scenario for a command acting on an identity no record carries; that is ESS's decided rule (absence is wrong-state unless the command declares an `unknown_instance:` outcome). Mandate's handlers answer `denied` for an unknown identity, so 15 synthesized `<Command>/outcome/wrong-state` scenarios fail: credential (`DisableResourceServer`, `RedeemAuthorizationCode`, `RetireSigningKey`, `RevokeAccessCredential`, `RevokeSigningKey`), federation (`DisableFederationConnection`, `DisableOAuthClient`, `UnlinkExternalPrincipal`), graph (`DeregisterResource`), identity (`RevokeSession`), tenancy (`CloseOrganization`, `RemoveOrganizationMembership`, `RemoveTeamMembership`, `RetireSpace`, `RetireTeam`). A handler that answers `denied` for 15 of 15 passes once the scenario expects that refusal.

`unknown_instance:` is an `ess/15` construct; `systems/mandate/system.yaml` declares `format: ess/4`, so the specification's format is raised first. A probe raising it to `ess/22` dropped 20 synthesized wrong-state scenarios (180 to 160); the raise must name every scenario it removes and why.

## Outcome

Each of the 15 commands declares its unknown-identity refusal as an `unknown_instance:` outcome with the error the handler already returns; the synthesized scenarios expect it and pass.

## Acceptance

`cargo xtask conform` reports the 15 scenarios above `passed`, and no scenario is attributed to this story; the suite's scenario count after the format raise is stated beside the 0.59.0 count (200), with every removed scenario named.

## Scope

- `systems/mandate/system.yaml`, `systems/mandate/domains/{credential,federation,graph,identity,tenancy}.yaml` — inferred
- `generated/` — regenerated
- `contracts/expected-outcomes.json`, `contracts/conformance/injections.json` — inferred
- `crates/mandate-conformance/src/commands/` — inferred, if a target adapter must report the new outcome

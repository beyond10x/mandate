# Wave 6 (unknown-instance refusals, AEP repin): execution

Opened 2026-10-13 on `integration/wave-20261013-001`, cut from `main` at `4b1ed8a` (0.7.0).
Coordinator: a session running `aep:implementing` in wave mode, approved by the operator on
2026-10-13 before it was proposed. Epic: `epic:foundations`.

Purpose: the 15 synthesized `wrong-state` scenarios for commands acting on a record that does not
exist expect the refusal Mandate already gives, and the planning tooling moves to the newest AEP.

## Units

| unit | story | branch | managed id | scratch | stage |
|---|---|---|---|---|---|
| U1 | `story:aep-repin-0-71` | `impl/aep-repin-0-71` | `mandate-w6-aep-repin` | `~/.cache/mandate-w6/u1/` | merged `f9aa1c7` (unit head `d96b79f`) |
| U2 | `story:unknown-instance-refusals` | `impl/unknown-instance-refusals` | `mandate-w6-unknown-instance` | `~/.cache/mandate-w6/u2/` | merged `8b80a9f` (unit head `4da1f1e`) |

U1 and U2 share one line, `AGENTS.md:13`, which names both the AEP pin and the ESS format. U1 lands
first; U2 is cut from the integration branch after U1's merge and owns the format words on that line.
Builds run one at a time, each in its own tree's `target/`.

## Decisions this wave rests on

- `decision-blocker:identity-uniqueness` (cleared 2026-10-13): the external-principal, audience and
  exchange-source keys are decided on the shipped command-path refusals and fold conflict views;
  ceiling data enters only through `SupersedeAgentCapabilityCeiling`. Atomic storage enforcement
  moved to `decision-blocker:identity-uniqueness-storage`, which blocks
  `story:domain-folds-over-the-kit`. This frees `story:agent-security` for the next wave; it is not
  in this wave.
- `story:unknown-instance-refusals` raises `systems/mandate` past `ess/4`. The raise must name every
  synthesized scenario it removes; a probe to `ess/22` removed 20 (180 to 160).

## Commits this wave authorises

The opening store commit with this page; one commit per unit, plus adversary test files and unit
fix-ups; the merges into the integration branch; the closing store commit; one PR from the
integration branch to `main` and its bot merge on green CI; the release through this repository's
process (`AGENTS.md`, standing cadence).

## Pre-flight

| check | reading |
|---|---|
| primary checkout | `main` at `4b1ed8a`, clean but for an untracked `.agents/` that is not this wave's |
| Gates baseline | `4b1ed8a` (`gates-policy/policy.json`, read 2026-10-13) |
| free disk | 62G at 05:20Z (`df -BG /`) |
| build budget | at most 10G du per build target; pause under 15G free, resume over 17G |
| load | 7.70 (`/proc/loadavg`) |
| tools | `aep 0.71.2`, `ess 0.59.0` (newest ESS release, `gh release list -R beyond10x/ess`) |

## Stage log

- 05:20Z opening store commit: `story:aep-repin-0-71` created; both stories moved to active;
  `decision-blocker:identity-uniqueness` cleared; `decision-blocker:identity-uniqueness-storage`
  created.
- U1 pin edits (aep 0.71.2 in `xtask/src/main.rs`, `ci.yml`, `AGENTS.md`, `README.md`,
  `docs/handoff.md`). A probe recorded evidence with aep 0.71.2 into a scratch copy of the store:
  the record file layout is unchanged. Package gate `cargo test -p xtask`: 1 failure,
  `coverage::the_committed_manifest_agrees_with_...`: 16 coverage entries were deferred on the
  blocker the opening commit cleared. Target du 3.4G. Fix-up dispatched in the U1 tree: the 16
  entries become `declared` on `story:agent-security`, the registries and fixtures follow.
- U1 fix-up (`d96b79f`): the 16 entries `declared` on `story:agent-security`, the registries drop
  the blocker, the relabel and blocker mutant cases move to `mandate.audit.RedactAuditEvent`, and
  two architecture documents carry the blocker as cleared. `cargo test -p xtask`: 245 passed, 1
  ignored; `cargo test -p mandate-authz`: 125 passed; clippy of both and fmt clean;
  `cargo xtask coverage`: 293 mapped, 211 implemented, 41 declared, 41 deferred;
  `cargo xtask documents`: 20 row sets match. Peak target du 4.1G. Merged as `f9aa1c7`.
- U2 first pass (uncommitted, backed up in scratch): format raised to `ess/24` (ESS 0.59.0 accepts
  `ess/1` to `ess/24`; `unknown_instance:` needs `ess/15`). Synthesized scenarios: 201 at `ess/4`
  to `ess/6`, 181 at `ess/7` to `ess/24`. Declaring `unknown_instance:` on the 15 commands passed
  one (`RevokeSession`) and showed the story's premise wrong: ESS 0.59.0 compares the outcome by
  name (`ESS-CF-OUTCOME`) and refuses the flag on `denied` (`ESS-COMMAND-004`), so passing needs a
  distinct `unknown-instance` answer, which tells a caller whether a record exists. The handlers
  answer an unknown identity like a record the caller may not see, on purpose (`redemption.rs`;
  `crates/mandate-model/tests/tenancy.rs`; `revoke_session`). Seven credential and federation
  commands would also fail their passing `/outcome/denied` scenario. Peak target du 5.0G.
- Coordinator decision, confirmed by the operator: keep the non-disclosure. U2 ships the format
  raise alone; the 15 declarations moved to `story:unknown-instance-non-disclosing`, waiting on
  an ESS release that admits an unknown identity answered by an existing refusal outcome (asked
  of ESS). Store commit on the unit branch. Second pass dispatched.
- U2 second pass (`4da1f1e`): the raise alone; no `unknown_instance:` declaration, no handler
  change. `ess specify validate` exits 0 with the 2 `ESS-ENTITY-019` warnings on `AuditEvent` it
  gave at `ess/4`. `cargo xtask conform`: 181 scenarios, 40 passed, 63 failed, 78 unsupported
  (201: 40 / 78 / 83 at `ess/4`). The OpenAPI projections change only their digest lines.
  `cargo test -p xtask` on the committed unit head: every binary ok; `mandate-sts` 252,
  `mandate-conformance` 47; clippy and fmt clean. Peak target du 5.0G. No adversary pass: no
  handler or library code changed. Merged as `8b80a9f`.
- `story:refusal-discriminators` has no scenario left: its one, `Organization/state/Closed/refuses/
  CloseOrganization`, is among the 20 removed. The story stays draft; its handler work still stands.
- Closing store commit: both stories `implemented` on recorded test results.

## The 20 scenarios the raise removes

ESS 0.59.0 synthesizes 201 scenarios from `systems/mandate` at `ess/4` and 181 at `ess/24`. No
scenario is added. The 20 below are no longer emitted; the suite records each as a refusal with
`code: ESS-SYNTH-001`, `effect: candidate_not_emitted`. The format probes put the drop at `ess/7`
(201 through `ess/6`, 181 from `ess/7` on).

Why, the same for all 20 (`generated/conformance/suite.json`): a wrong-state refusal is "observed
through a view of the entity projecting its identity, and none shows this row" — no declared view of
the entity projects its identity and its state, so the synthesizer has no witness that the refused
record is unchanged. ESS's help: "declare a view of the entity that projects its identity and its
state; a wrong-state refusal is observed through any identity view, `eventual` included".

Each is listed with its `ess/4` ledger outcome and owner (`contracts/expected-outcomes.json`):

- `mandate.audit.AuditEvent/state/Redacted/refuses/mandate.audit.RedactAuditEvent` — unsupported, `story:audit-worker-delivery`
- `mandate.credential.AccessCredential/state/Revoked/refuses/mandate.credential.RevokeAccessCredential` — unsupported, `story:constrained-exchange`
- `mandate.credential.AuthorizationCode/state/Consumed/refuses/mandate.credential.RedeemAuthorizationCode` — failed, `story:ess-synthesizer-prerequisites`
- `mandate.credential.ResourceServer/state/Disabled/refuses/mandate.credential.DisableResourceServer` — failed, `story:ess-synthesizer-prerequisites`
- `mandate.credential.SigningKey/state/Retired/refuses/mandate.credential.RetireSigningKey` — failed, `story:ess-synthesizer-prerequisites`
- `mandate.credential.SigningKey/state/Revoked/refuses/mandate.credential.RetireSigningKey` — failed, `story:ess-synthesizer-prerequisites`
- `mandate.credential.SigningKey/state/Revoked/refuses/mandate.credential.RevokeSigningKey` — failed, `story:ess-synthesizer-prerequisites`
- `mandate.delegation.Delegation/state/Revoked/refuses/mandate.delegation.RevokeDelegation` — unsupported, `story:agent-security`
- `mandate.directory.DirectoryGroupTeamMapping/state/Removed/refuses/mandate.directory.RemoveDirectoryGroupTeamMapping` — unsupported, `story:directory-provenance`
- `mandate.federation.ExternalPrincipal/state/Unlinked/refuses/mandate.federation.UnlinkExternalPrincipal` — failed, `story:ess-synthesizer-prerequisites`
- `mandate.federation.FederationConnection/state/Disabled/refuses/mandate.federation.DisableFederationConnection` — failed, `story:ess-synthesizer-prerequisites`
- `mandate.federation.OAuthClient/state/Disabled/refuses/mandate.federation.DisableOAuthClient` — failed, `story:ess-synthesizer-prerequisites`
- `mandate.graph.Relation/state/Removed/refuses/mandate.graph.RemoveRelation` — unsupported, `story:graph-policy-adapter`
- `mandate.graph.Resource/state/Deregistered/refuses/mandate.graph.DeregisterResource` — failed, `story:ess-synthesizer-prerequisites`
- `mandate.identity.Session/state/Revoked/refuses/mandate.identity.RevokeSession` — failed, `story:ess-synthesizer-prerequisites`
- `mandate.tenancy.Organization/state/Closed/refuses/mandate.tenancy.CloseOrganization` — failed, `story:refusal-discriminators` (its only attributed scenario; the story has none left)
- `mandate.tenancy.OrganizationMembership/state/Removed/refuses/mandate.tenancy.RemoveOrganizationMembership` — failed, `story:ess-synthesizer-prerequisites`
- `mandate.tenancy.Space/state/Retired/refuses/mandate.tenancy.RetireSpace` — failed, `story:ess-synthesizer-prerequisites`
- `mandate.tenancy.Team/state/Retired/refuses/mandate.tenancy.RetireTeam` — failed, `story:ess-synthesizer-prerequisites`
- `mandate.tenancy.TeamMembership/state/Removed/refuses/mandate.tenancy.RemoveTeamMembership` — failed, `story:ess-synthesizer-prerequisites`

Totals: 15 failed and 5 unsupported rows leave the ledgers; `cargo xtask conform` moves from
40 passed / 78 failed / 83 unsupported (201) to 40 / 63 / 78 (181). Per owner:
`story:ess-synthesizer-prerequisites` 62 → 48, `story:agent-security` 17 → 16,
`story:audit-worker-delivery` 7 → 6, `story:constrained-exchange` 5 → 4,
`story:directory-provenance` 19 → 18, `story:graph-policy-adapter` 13 → 12,
`story:refusal-discriminators` 1 → 0.

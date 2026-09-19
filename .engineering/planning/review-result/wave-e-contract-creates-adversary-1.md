---
format: aep.planning-md/1
id: review-result:wave-e-contract-creates-adversary-1
kind: review-result
status: active
title: Adversary pass 1 — contract-creates
relations:
- reviews: story:contract-creates
revision: 1
---
```
unit: story:contract-creates — systems/mandate/domains/*.yaml (10 files), uncommitted on impl/contract-creates at base 9401ab9
verdict: needs-change
cases: 11 probes in scratch over the compiled IR and the synthesized suite, red 8 (3 held); no Rust executed beyond cargo xtask corpus
findings: 11 — 2 blockers, 6 warnings, 3 notes
```

```findings
- file: systems/mandate/domains/credential.yaml
  line: 232
  category: contract-drift
  severity: blocker
  verdict: CONFIRMED
  origin: introduced
  message: a replayed authorization code now has two declared outcomes — the synthesized suite requires wrong-state (HTTP 409) while command-obligations.md:16, crates/mandate-federation/src/authorize.rs:293 and tests/authorize.rs:259 all require denied (HTTP 502), and nothing says which a caller gets.
- file: systems/mandate/domains/federation.yaml
  line: 251
  category: contract-drift
  severity: blocker
  verdict: CONFIRMED
  origin: introduced
  message: creates mandate.identity.Session names FederationAuthenticated, which carries none of organization_id, epochs or expires_at, while mandate.identity.SessionOpened carries the whole record and no command outcome emits it.
- file: systems/mandate/domains/credential.yaml
  line: 293
  category: contract-drift
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: six of nineteen declared creators emit an event that cannot materialize the record they claim to create, against ADR 0009's rule that the events are the record.
- file: docs/architecture/command-obligations.md
  line: 16
  category: contract-drift
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: the wrong-state outcome adds 34 HTTP 409 responses and 34 wrong-state response schemas to the generated OpenAPI, and the 59-row obligations table carries no account of them because xtask obligations() selects only the externally caused outcome.
- file: systems/mandate/domains/credential.yaml
  line: 287
  category: property
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: the three generated credential_id instance identities and Relation.id are shape-checked only, so an implementation returning one constant UUID for every credential conforms, unlike the fifteen creators cross-checked by expect_response_payload.
- file: systems/mandate/domains/delegation.yaml
  line: 306
  category: acceptance
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: two of the fifty-nine remaining refusals are ESS-SYNTH-011 on mandate.delegation.Delegation, an entity this unit gave a creator and which the story's named creator-less set does not contain, so the refusals did not drop to exactly that set.
- file: systems/mandate/domains/identity.yaml
  line: 8
  category: contract-drift
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: nothing states that FederationAuthenticated precedes SessionOpened or that their session identities are the same, while IdentityLog::try_record refuses a second open of any session a recorded event already names.
- file: crates/mandate-types/tests/adversary_fold_inputs.rs
  line: 445
  category: contract-drift
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: the new credential_id field changes AccessCredential's closest carrier and fails the pinned-residue case in the tree as handed over, green only with an out-of-scope coordinator patch.
- file: systems/mandate/domains/federation.yaml
  line: 251
  category: mutant
  severity: warning
  verdict: INFEASIBLE
  origin: introduced
  message: declaring the wrong entity of a shared identity type passes validate and yields the identical 132 scenarios and 59 refusals, so the unit's gate cannot discriminate Principal from Agent, Organization from OrganizationSecurityEpoch, or FederationConnection from FederationSecurityEpoch — no live mis-declaration exists, the adversary constructed the state.
- file: systems/mandate/domains/federation.yaml
  line: 291
  category: judgement
  severity: note
  verdict: INFEASIBLE
  origin: introduced
  message: the residue is honestly exactly twenty, but Principal is the one creator-less entity a declared command actually creates and ESS refuses two subjects on one outcome, so story:declared-writers cannot close it with a creates.
- file: systems/mandate/domains/federation.yaml
  line: 291
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: the new ProvisionExternalPrincipal summary says the outcome creates exactly one record while docs/architecture/federated-login.md, unchanged and out of scope, says it creates the principal and the ExternalPrincipal.
```

Held under attack: 34 movers ↔ 34 wrong-state outcomes, sets equal, each the command's own domain `Denied`, none combined with `external:`, `SYNTH-012` 0, all 16 terminal-refusal scenarios present; counts 59/72/110/36 exact; a mistyped `instance:` refused by ESS (`ESS-COMMAND-002`); dropping one `creates:` moves the suite (132 → 129, 59 → 62); synthesis deterministic; per-component synthesis intact (control-plane 83, authorization 17, sts 26, worker 6); responses 23 → 24. Probes and evidence under the unit's scratch `adversary1/` (35 MB), outside the tree.

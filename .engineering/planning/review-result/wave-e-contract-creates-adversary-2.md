---
format: aep.planning-md/1
id: review-result:wave-e-contract-creates-adversary-2
kind: review-result
status: active
title: Adversary pass 2 — contract-creates
relations:
- reviews: story:contract-creates
revision: 1
---
```
unit: story:contract-creates — systems/mandate/domains/*.yaml (10), docs/architecture/{command-obligations,federated-login}.md, uncommitted on impl/contract-creates at base 9401ab9, after correction round 1
verdict: needs-change
cases: 19 probes in scratch, red 12; repository suite 615 executed, 2 red (the residue pins outside the story's scope, awaiting the regeneration commit)
findings: 19 — 7 marked blocker by the adversary (2 are the residue pins, 5 substantive), 8 warnings/major, 4 notes; coordinator routing in the ruling
```

```findings
- file: crates/mandate-types/tests/adversary_fold_inputs.rs
  line: 438
  category: contract-drift
  severity: blocker
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'the pinned fold residue is stale: the unit made AccessCredential, AuthorizationCode and Resource rebuildable and the literal set was not updated, so an existing repository case is red until the regeneration commit re-pins it.'
- file: crates/mandate-types/tests/adversary_fold_inputs_2.rs
  line: 370
  category: contract-drift
  severity: blocker
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'the exact-type residue reader now finds three entities an event can rebuild where the wave recorded none, and the assertion expects an empty map; same regeneration-commit re-pin.'
- file: systems/mandate/domains/graph.yaml
  line: 180
  category: correctness
  severity: blocker
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'ResourceRegistered.space_id is sourced generated, minting a foreign key into mandate.tenancy.Space that no CreateSpace produced, and RegisterResource has no space input to source it from.'
- file: .engineering/planning/story/declared-writers.md
  line: 113
  category: contract-drift
  severity: blocker
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'Resource.space_id is story:declared-writers own deliverable, planned to arrive as a new input on RegisterResource, and this unit added it event-only with an untruthful source ahead of the story that depends on it.'
- file: .engineering/planning/story/tenancy-graph-events.md
  line: 68
  category: contract-drift
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: 'coordinator ruling PS3/D2, recorded in seven story files, names a four-field ResourceRegistered payload and the yaml emitted five before this round.'
- file: docs/architecture/command-obligations.md
  line: 3
  category: prose-drift
  severity: blocker
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'the new header defines the wrong-state branch as the entity terminal states which no declared transition starts from, and SigningKey.revoke starts from the terminal state Retired, so the document tells an adapter to refuse the emergency revocation of a retired signing key that the contract accepts.'
- file: docs/architecture/command-obligations.md
  line: 3
  category: prose-drift
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: 'the header claims the wrong-state refusal is accounted per command in this registry and none of the 59 rows distinguishes the 34 commands that declare one from the 25 that do not.'
- file: crates/mandate-graph/src/record.rs
  line: 109
  category: contract-drift
  severity: blocker
  verdict: CONFIRMED
  origin: introduced
  message: 'four shipped records document that repeating the command is accepted and return MutationOutcome::AlreadyRecorded for the state the wrong-state outcome now declares an HTTP 409 error (RemoveRelation, RevokeGrant, SupersedeAuthorizationModel, SupersedePolicy); contract-versus-implementation drift the enforcement surfaced, routed to the code stories.'
- file: crates/mandate-federation/src/authorize.rs
  line: 295
  category: contract-drift
  severity: blocker
  verdict: CONFIRMED
  origin: introduced
  message: 'a consumed authorization code still returns DenialReason::Denied (502) with two cases asserting it, while the contract now routes that state to wrong-state (409), and the comment at :293 quotes the yaml text this unit deleted; routed to story:federation-identity-alignment.'
- file: systems/mandate/domains/federation.yaml
  line: 244
  category: correctness
  severity: warning
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'Session.principal_id is declared generated on the event that creates the Session, so the one field naming whose session it is has no truthful source and the suite shape-checks it as any uuid.'
- file: systems/mandate/domains/graph.yaml
  line: 176
  category: correctness
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: 'ResourceRegistered carries the created resource identity twice, from the response and from input.resource.resource_id, with no declared equality; the contract mandates both (instance plus ResourceRef) and decide guarantees equality (tenancy-graph-events adversary-2 case).'
- file: systems/mandate/domains/federation.yaml
  line: 342
  category: spec-gap
  severity: warning
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'AuthorizePublicClient mints a code_id and carries six of the nine AuthorizationCode record fields while declaring no subject, so the entity has a declared creator and a second undeclared one.'
- file: .engineering/planning/story/contract-creates.md
  line: 39
  category: acceptance
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: 'the Acceptance requires the refusals to drop to exactly the named creator-less set and two of the fifty-nine are ESS-SYNTH-011 on Delegation, which has a creator; restated by ruling as creator-less set plus the invariant-without-view class, both named.'
- file: systems/mandate/domains/credential.yaml
  line: 291
  category: spec-gap
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: 'seven optional record fields the unit declared generated carry optional true in the synthesized shape, so an implementation that never emits AccessCredential.epochs or reference_verifier conforms; a presence pin is an authored scenario (story:authored-denial-scenarios).'
- file: systems/mandate/domains/identity.yaml
  line: 8
  category: prose-drift
  severity: warning
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'the rewritten header states that a second open of a session_id is refused and the compiled model declares no invariant, view, open command or outcome that could refuse it, while the two events name the record identity by different field names (id, session_id).'
- file: docs/architecture/federated-login.md
  line: 50
  category: prose-drift
  severity: warning
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'the step table still documents AuthenticateFederation as returning SessionId alone after this unit widened its response.'
- file: docs/architecture/federated-login.md
  line: 49
  category: prose-drift
  severity: note
  verdict: NEEDS-CHANGE
  origin: pre-existing
  message: 'the step table row still says provisioning creates the principal, the identical claim this same diff corrected in the diagram.'
- file: .engineering/planning/story/contract-creates.md
  line: 65
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: 'docs/architecture/command-obligations.md is named in the story Excluded list and the unit changed it under the pass-1 scope extension; the Excluded line is superseded.'
- file: docs/architecture/federated-login.md
  line: 47
  category: judgement
  severity: note
  verdict: NEEDS-CHANGE
  origin: pre-existing
  message: 'every federation.yaml line citation in the step table is stale and this unit moved the targets a further eight lines.'
```

Held: no `CredentialSecret`/`CredentialProof` on any event through any type path (72 walked); zero terminal-state text left in the 34 external denials (matcher calibrated red against the pre-correction IR); all 19 creating outcomes carry `creates:` + `instance:`, all instances response-sourced; 0 record fields unchecked; `components.yaml` consistent with the cross-domain create; OpenAPI 202 × 59, 409 × 34, 502 × 59; compile and synthesize byte-identical across three runs. Mutation probes: a creator on an event missing record fields, and `credential_id` back to `generated`, pass `ess specify validate` and leave the suite at 132/59 — only the probes catch them; this is the ESS gap `creates-record-carriage` for the ESS wave. Evidence under the unit's scratch `adversary2/`.

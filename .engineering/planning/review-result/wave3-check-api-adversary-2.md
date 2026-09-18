---
format: aep.planning-md/1
id: review-result:wave3-check-api-adversary-2
kind: review-result
status: active
title: Adversary pass 2 — story:check-api
tags:
- model-deviation-opus
relations:
- reviews: story:check-api
revision: 1
---
```
unit: story:check-api after correction round 1 — working tree at <worktree>, branch impl/check-api, uncommitted, base 0d1947d
verdict: CONFIRMED
cases: executed 59→71, red 3
origin: introduced 4 / pre-existing 0 / undecided 0
wrote-outside-worktree: 2 paths (<scratch>/suite-pass2-oYXBRk.log, <scratch>/suite-pass2-final-i0Xb41.log)
needs-coordinator: whether mandate.core.DecisionChallenge gaining a requirement field is a contract story's, or whether authz refuses a Reauthentication as Unavailable until it can express one (G3)
```

The round-1 corrections hold: F1–F4 pass the probes written against them end to end through `check` (9 green cases); F6's new test drives all six reasons through `check`. Adversary file: `crates/mandate-authz/tests/adversary_check_2.rs` (12 cases; 3 red, 9 green; one green case added after the first run as a mutant guard, disclosed). `adversary_check.rs` unchanged (7/7).

## Findings

```yaml
findings:
  - id: G1
    severity: medium
    verdict: CONFIRMED
    origin: introduced
    location: "crates/mandate-authz/src/evaluate.rs:157"
    message: "requested() matches AuthorityScope.resources by whole-ResourceRef equality while mandate-graph matches the same field of the same contract type by resource_id alone and documents why (double.rs:182-190; graph.yaml:8-11 makes the type a field of the record, not part of identity), so one decision applies two identity rules: the graph finds the authority and the requested-authority bound refuses it. Closed direction, a false deny; fix is to compare resource_id."
  - id: G2
    severity: medium
    verdict: INFEASIBLE
    origin: introduced
    location: "crates/mandate-authz/src/decision.rs:225"
    message: "The F3 correction propagates a port denial of DenialReason::ApprovalRequired and leaves the challenge behind, producing Decision { allowed: false, reason: ApprovalRequired, challenge: None } — the shape the story's acceptance statement and mandate.core.Decision's own approval sample (model/lib.rs:180-188) forbid. No adapter or double in the tree emits that error today."
  - id: G3
    severity: medium
    verdict: CONFIRMED
    origin: introduced
    location: "crates/mandate-authz/src/decision.rs:214"
    message: "precedence::strictest chooses between an approval a second party must give and a reauthentication the caller clears alone (combined.md:67), and the choice is recorded nowhere: DecisionChallenge declares approver_policy and expires_at and no requirement, so PolicyDouble::require_approval with Approval and with Reauthentication produce byte-identical decisions and the PEP cannot tell its caller what to do."
  - id: G4
    severity: low
    verdict: CONFIRMED
    origin: introduced
    location: "crates/mandate-authz/src/lib.rs:206"
    message: "Neither scope wiring line at the check entry point (lib.rs:191 Binding, lib.rs:206 Read) is covered by any case of the unit's suite — every check_contract.rs request passes scope: None and the scope tests call evaluate and bind directly — so replacing either with None leaves the unit's 52 cases green; only the adversary files go red."
```

## Mutant table

Remove `requested(...)` from the fold (`evaluate.rs:288`) → `tests/evaluate.rs:899` red. Wire `scope: None` into `Read` (`lib.rs:206`) or `Binding` (`lib.rs:191`) → no unit case red; only the adversary files (G4).

## Attacked and could not break

`direct()` (four non-direct shapes refuse, actor == subject allows); port refusal round-trip (7 reasons × 2 ports + 6 `CouldNotAnswer`); deny + challenge stays deny; allow + challenge + no approver fails closed; scope action patterns (equality, never `covers`); scope vs ancestry (closed, a judgement to record); scope + ceiling both refusing (one reason); stale `resource_type` at placement (dead end).

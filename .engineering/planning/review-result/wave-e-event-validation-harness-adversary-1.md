---
format: aep.planning-md/1
id: review-result:wave-e-event-validation-harness-adversary-1
kind: review-result
status: active
title: Adversary pass 1 — event-validation-harness
relations:
- reviews: story:event-validation-harness
revision: 1
---
```
unit: story:event-validation-harness — crates/mandate-testkit/{src/contract.rs, src/lib.rs, tests/contract.rs}, uncommitted on impl/event-validation-harness at base 9401ab9
verdict: needs-change
cases: executed 24 → 37, red 4 (adversary file tests/adversary_contract_1.rs, 13 cases: 9 held, 4 confirmed)
findings: 8 — 1 blocker, 2 warnings, 5 notes
```

```findings
- file: crates/mandate-testkit/src/contract.rs
  line: 213
  category: acceptance
  severity: blocker
  verdict: CONFIRMED
  origin: introduced
  message: check_payload_sources reports a failure when an optional input the contract permits to be absent is absent, so it refuses a root-resource payload that check_event_conforms accepts and the contract declares legal.
- file: crates/mandate-testkit/src/contract.rs
  line: 180
  category: contract-drift
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: the documented Errors clause promises that a failure means the event carries something the contract did not declare, but an event field with no declared source is accepted.
- file: crates/mandate-testkit/src/contract.rs
  line: 247
  category: boundary
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: a generated target whose value is JSON null passes the presence check, although null is the spelling the contract does not declare.
- file: crates/mandate-testkit/src/contract.rs
  line: 56
  category: boundary
  severity: note
  verdict: INFEASIBLE
  origin: introduced
  message: ess_name is interpolated into a path with no check against the IR event list, so a name containing .. reads a schema outside generated/schema/events and the payload is accepted; the adversary constructed the name and found no caller that reaches it.
- file: crates/mandate-testkit/tests/contract.rs
  line: 253
  category: mutant
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: assert!(message.contains("id")) is vacuous because every message from this call is prefixed mandate.identity.RevokeSession and "identity" contains "id".
- file: crates/mandate-testkit/src/contract.rs
  line: 160
  category: mutant
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: assert_single_emission and assert_payload_sources have no should_panic case, so replacing either panic message with a constant is a mutant the suite does not catch.
- file: .engineering/planning/story/event-validation-harness.md
  line: 23
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: the shipped signatures add an event_name parameter to assert_payload_sources and reorder assert_single_emission relative to the story Scope; the addition is necessary but the deviation is unrecorded.
- file: crates/mandate-testkit/src/contract.rs
  line: 317
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: payload_fields keys on the event name across all outcomes and ignores the outcome, so a command that emits one event from two outcomes will silently take the first mapping once wrong-state outcomes land.
```

Held under attack: both live drifts refused naming the field (`SecurityEpochIncremented {target}` → `context` required; `FederationConnectionDisabled {context, connection_id}` → `id` required and `connection_id` unexpected); `additionalProperties: false` enforced inside `$defs`; nested `pattern` failures carry the instance path; `date-time` and `duration` format assertions live with default features off; integer-as-string refused; names matched exactly; emission counting refuses zero, two, duplicate, wrong name, denied-with-one, unknown command and outcome. Offline cross-check: all 59 payload mappings' targets are declared schema properties, every required property is mapped, 0 mismatches. Note for the gate: `cargo test -p mandate-testkit --locked` without `--no-fail-fast` stops at the first failing target.

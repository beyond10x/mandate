---
format: aep.planning-md/1
id: story:obligations-identity
kind: story
status: implemented
title: Bind mandate-identity's denial clauses to real-path tests
relations:
- decomposes: epic:foundations
- informed_by: initiative:drift-enforcement
- depends_on: story:obligation-registry
- serves: vision:mandate
scope:
- confidence: cited
  path: contracts/obligations/identity.json
- confidence: cited
  path: crates/mandate-identity/tests/obligations.rs
revision: 7
---
## Why

`story:obligation-registry` (wave D second half) authors `contracts/obligations.json`, the clause-level map from every implemented command's external denial clauses to the real-path tests that decide them. The binding for `mandate-identity` is one file this story owns: 3 commands, ~12 clauses; denials as RefusedOutcome (scoper's estimate on `6d812e0`, split of each IR `condition.cause` on comma/`or`; granularity checked against `services/sts/tests/declared_denials.rs:108`). Until it lands, the registry carries `blocked_on: story:obligations-identity` for every unbound clause of this crate and the step stays green.

## Outcome

`crates/mandate-identity/tests/obligations.rs` decides every clause of the crate's implemented commands on the real path — one denial case per clause naming the clause verbatim, one no-state-change case per command — and `contracts/obligations.json` names each; the crate's rows in `contracts/conformance/obligations-report.json` move from `deferred` to `real_covered`.

## Acceptance

`cargo xtask obligations-registry` reports no clause of a `mandate-identity` command as `deferred` on this story, and `cargo test -p mandate-identity --locked --test obligations` is green.

- Result (2026-09-21, at merge): the Outcome above overstated what this story could reach, as it did for every binding unit this half. Of 12 `mandate-identity` clauses the unit leaves **4 real** (`RefreshSession`'s expired/revoked record, its epoch mismatch and its session binding; `RevokeSession`'s tenancy — all handler code over the fold), **2 double** on `mandate_identity::IdentityLog` and **6 re-pointed**: 3 authority/verifier clauses to `decision-blocker:guards`, 2 to `decision-blocker:epoch-atomicity`, 1 to `story:identity-tenant-containment`. Final table `mandate-identity 12 / 4 / 2 / 6` (`cargo run -p xtask -- obligations-registry`, coordinator verification 2026-09-21). The Acceptance — "no clause of a `mandate-identity` command is `deferred` on this story" — is met by re-pointing as well as by binding.
- The unit's substantive finding, from two adversary passes: **`mandate.identity.IncrementSecurityEpoch` decides nothing itself.** `IncrementSecurityEpoch::execute` (`crates/mandate-identity/src/increment.rs:87-100`) delegates to the write port; both refusals it can reach are `return Err(...)` inside the one `impl SecurityEpochWrite for IdentityLog` (`crates/mandate-identity/src/port.rs:911`) — the compare-and-set at `:919-921` and the generation overflow at `:922-924`, three lines apart. The command's `no_state_change` row follows them. `IdentityLog` is the in-memory double of an adapter nobody has written, so the whole command waits on `decision-blocker:epoch-atomicity`.
- Adversary pass 2 ruled (`review-result:wave-d-obligations-identity-adversary-2`): 2 blockers, 2 warnings. F1 moved the overflow clause and, by the coordinator's extension, the `no_state_change` row. F3's blocker was an artefact of the unit tree carrying a base copy of the planning store — the deferral to `story:declared-writers` was right and that story names both the command and the event. F4 replaced re-reading citations with a check: `crates/mandate-identity/tests/obligations.rs` now scrapes every `file:line` span out of its own doc comments, reads the cited lines and refuses both a span that does not hold its phrase and a citation its table does not carry (11 spans, 14 phrases, 0 wrong).
- One row the correction withdrew on its own finding, and the coordinator upheld: `mandate-identity::generation::epoch_overflow_the_maximum_generation_does_not_advance` was rowed against the overflow clause but constructs no `IdentityLog` and survives every mutation of the refusal it was rowed for — it is evidence of a domain-type invariant, not of the command. Withdrawn with nothing added to compensate; `double_only` did not move, because the withdrawal removed volume and not evidence.

---
format: aep.planning-md/1
id: review-result:wijk-k2-draws-adversary-1
kind: review-result
status: active
title: Adversary pass 1 on K2 (sts-refusal-draws-nothing)
relations:
- reviews: story:sts-refusal-draws-nothing
revision: 1
---
unit: story:sts-refusal-draws-nothing, commit d4db4c1 plus the uncommitted test file
verdict: red (strongest verdict returned is INFEASIBLE: 3 red cases, each built on a state nothing in the tree reaches)
cases: executed 217→221, red 3
origin: introduced 2, pre-existing 0, undecided 1
wrote-outside-worktree: ~/.cache/claude-tmp/wijk/k2/scratch/adv1-suite.log
needs-coordinator: no

Cases in services/sts/tests/adversary_draws_nothing_1.rs:
- a_reservation_a_draw_overtook_is_not_signed_into_a_second_credential (:269) red: a draw after the reservation handed out the reserved identity; commit changed nothing and said nothing
- a_counting_allocator_that_only_implements_the_required_methods_draws_on_a_signer_refusal (:338) red
- a_log_that_refuses_after_the_build_as_its_contract_allows_has_drawn (:430) red: left (1, false) right (0, true)
- a_redemption_behind_a_genuinely_stale_version_draws_nothing green

Suite: cargo test -p mandate-sts --locked --no-fail-fast EXIT=101, passed 218, failed 3. clippy clean.

F1 lib.rs:272-280 INFEASIBLE introduced: SequentialAllocator::reserve_credential_id only peeks; a later draw returns the reserved id; commit silently no-ops; trait docs say the reservation is held (lib.rs:197). Reaches: nothing — issue_self_contained_credential holds &mut from reserve to commit.
F2 lib.rs:210-212 INFEASIBLE introduced: the default reserve draws, so a counting allocator overriding neither method draws on a signer refusal; the compiler forces no override. Reaches: nothing — only ChosenServers (tests/adversary_profiles_2.rs:317), which reaches only registration and reference issuance.
F3 store.rs:545-548 INFEASIBLE undecided: the append_built contract places AppendRefused::Unreadable after build, so a conforming log makes redeem_and_consume refuse after drawing 1 secret and 1 identity. Reaches: nothing — InMemoryCodeLog cannot fail to fold a redemption decide accepted; a real kit failing at commit time would.
F4 adversary_obligations_sts_2.rs:262,:376; sts.json:305,:413 CONFIRMED introduced: the no_state_change rows cite ..._has_already_drawn_... cases that now assert the opposite; kept so the story's citation resolves.

Could not break: every decide refusal precedes the draw; ProfileUnadmitted and ExpiryUnbounded precede the reservation; code/reference issuance, key and server registration draw last; a CAS loss draws nothing; mint has no Result/?/expect; the flipped cases are not relaxed; ?Sized→Sized on L breaks no caller.

```findings
- file: services/sts/src/lib.rs
  line: 276
  category: property
  severity: note
  verdict: INFEASIBLE
  origin: introduced
  message: 'SequentialAllocator reserve only peeks: a draw after it returns the reserved id, and commit then silently no-ops, so two credentials could carry one id'
- file: services/sts/src/lib.rs
  line: 210
  category: contract-drift
  severity: note
  verdict: INFEASIBLE
  origin: introduced
  message: the default reserve draws, so a counting allocator that does not override it draws on a signer refusal, and nothing forces the override
- file: services/sts/src/store.rs
  line: 545
  category: contract-drift
  severity: note
  verdict: INFEASIBLE
  origin: undecided
  message: the append_built contract allows an Unreadable refusal after build runs, so redeem_and_consume can refuse having drawn a secret and an identity
- file: contracts/obligations/sts.json
  line: 305
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: the no_state_change rows cite cases named has_already_drawn that now assert that nothing is drawn
```

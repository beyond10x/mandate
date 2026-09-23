---
format: aep.planning-md/1
id: review-result:wm-m2-exchange-adversary-2
kind: review-result
status: active
title: Adversary pass 2 on M2 (federated-token-exchange)
relations:
- reviews: story:federated-token-exchange
revision: 1
---
unit: story:federated-token-exchange (M2), HEAD 736556e plus one untracked test file
verdict: red
cases: executed 182→187, red 5
origin: introduced 5, pre-existing 0, undecided 0
wrote-outside-worktree: ~/.cache/claude-tmp/wm/m2/scratch/{adv2-cp-cases.rs, adv2-red-cp.log, adv2-red-cp-5.log, adv2-suite-cp.log}
needs-coordinator: yes. F1 needs a ruling: either the story's Acceptance changes, or the code does.

Cases in services/control-plane/tests/adversary_exchange_2.rs, all red: the_session_proof_a_login_returns_is_exchanged_as_the_acceptance_states (:436); a_target_this_road_cannot_mint_for_is_not_answered_as_a_scope_the_caller_got_wrong (:493, invalid_scope for ProfileUnadmitted); a_registration_whose_audience_is_spelled_as_a_uuid_is_exchanged_by_that_name (:531); a_denial_for_an_unresolved_name_never_names_a_registration_that_exists (:572); a_target_named_by_its_resource_uri_reaches_the_handler_and_is_exchanged (:609, MalformedField).

Suite: cargo test -p mandate-control-plane --locked --no-fail-fast 187 executed, 182 passed, 5 failed, EXIT=101. clippy clean.

F1 exchange.rs:1 NEEDS-CHANGE introduced: the acceptance and brief exchange a session proof; the implementation admits only an access credential. (The adversary's worktree carries the story as of 871c11b0, before the coordinator amended the Acceptance to option A.)
F2 oauth.rs:449 NEEDS-CHANGE introduced: ProfileUnadmitted maps to invalid_scope for an exchange into a self-contained-profile target, though the scope is inside the subject's (oauth.rs:429 reserves invalid_scope for the requested authority).
F3 decode.rs:765 CONFIRMED introduced: an audience parsing as a UUID is always a registration id.
F4 exchange.rs:139 INFEASIBLE introduced note: seeding accepts a stated nil resource_server_id, which UNRESOLVED_TARGET then names.
F5 decode.rs:769 NEEDS-CHANGE introduced: a resource that is not urn:uuid is refused in the decoder; RFC 8707 URIs cannot name a target and an unknown one records no TokenExchangeDenied.
F6 adapters.rs:3117 CONFIRMED introduced note: allowed and denied share one 1024 ring; unauthenticated refusals evict every allowed record.
F7 exchange.rs:333 CONFIRMED introduced note: all unusable-subject causes share one clause and a None context, so the operator log cannot distinguish them.

Not broken: name resolution within the subject's organization only; disabled and foreign names leak nothing; exact matching on both sides; the cap's comparison is pinned; the arm calls code_for_clause for every clause; ResolutionUnavailable is unreachable.

```findings
- file: services/sts/src/exchange.rs
  line: 1
  category: acceptance
  severity: warning
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'the acceptance and brief exchange a session proof as subject_token, the implementation admits only an access credential and refuses the session proof as SubjectTokenInvalid'
- file: crates/mandate-proto/src/oauth.rs
  line: 449
  category: contract-drift
  severity: warning
  verdict: NEEDS-CHANGE
  origin: introduced
  message: an exchange into a self-contained-profile target is refused ProfileUnadmitted and answered invalid_scope although the requested scope is inside the subject's
- file: crates/mandate-server/src/decode.rs
  line: 765
  category: boundary
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: an audience whose text parses as a UUID is always read as a registration identity, so a registration whose audience is a UUID string is unreachable by its name
- file: services/sts/src/exchange.rs
  line: 139
  category: contract-drift
  severity: note
  verdict: INFEASIBLE
  origin: introduced
  message: operator seeding accepts a stated nil resource_server_id, so UNRESOLVED_TARGET can name a real registration in a denial record only tests read
- file: crates/mandate-server/src/decode.rs
  line: 769
  category: acceptance
  severity: warning
  verdict: NEEDS-CHANGE
  origin: introduced
  message: a resource that is not urn:uuid is refused in the decoder, so RFC 8707 URIs cannot name a target and an unknown target named by URI is refused with no TokenExchangeDenied
- file: services/control-plane/src/adapters.rs
  line: 3117
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: allowed and denied decisions share one 1024 ring, so unauthenticated refusals evict every TokenExchangeAllowed record
- file: services/sts/src/exchange.rs
  line: 333
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: unknown, revoked, expired and source-disabled subjects share one clause and a None context, so the operator stderr line cannot distinguish a revoked-credential replay from garbage
```

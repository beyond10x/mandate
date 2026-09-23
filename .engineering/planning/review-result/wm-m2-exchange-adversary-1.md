---
format: aep.planning-md/1
id: review-result:wm-m2-exchange-adversary-1
kind: review-result
status: active
title: Adversary pass 1 on M2 (federated-token-exchange)
relations:
- reviews: story:federated-token-exchange
revision: 1
---
unit: story:federated-token-exchange (M2), HEAD 5d5c40a5 plus two untracked test files
verdict: red
cases: executed 417→426, red 1
origin: introduced 4, pre-existing 0, undecided 0
wrote-outside-worktree: ~/.cache/claude-tmp/wm/m2/scratch/adv1-mandate-sts.log, adv1-mandate-control-plane.log
needs-coordinator: yes (which way to fix F1)

Cases: control-plane adversary_exchange_1.rs — a_source_unadmitted_refusal_is_answered_with_the_code_clause_codes_declares_for_it (red at :388: left invalid_request, right invalid_grant); a session proof as subject_token refused and recorded with no context (green). sts adversary_exchange_1.rs — chain S→T→V never widens or outlives S (green); re-exchange into the same target refused (green); disabled source/target and another organization's target refused, draw nothing (green); expiry at the exact instant and a fractional time never pass the subject's (green).

Suite: mandate-sts 248 passed; mandate-control-plane 177 passed, 1 failed; clippy clean.

F1 oauth.rs:505 NEEDS-CHANGE introduced warning: CLAUSE_CODES maps SourceUnadmitted to invalid_grant but the exchange arm at serve.rs:764 hard-codes invalid_request; the new ExchangeNotSubjectOnly row is unused too. Reaches: any exchange naming a target that does not list the source.
F2 adapters.rs:3080 CONFIRMED introduced warning: every refused exchange appends to an unbounded Vec only tests read; the endpoint needs no client authentication. Reaches: the shipped binary (main.rs:354,371).
F3 decode.rs:723 CONFIRMED introduced note: actor_token and a textual or non-UUID target are refused in the decoder, so no TokenExchangeDenied is recorded and ExchangeNotSubjectOnly (exchange.rs:267) is unreachable from the wire, though the obligations ledger cites it.
F4 decode.rs:747 INFEASIBLE introduced note: the target must be a registration UUID, not the logical audience name RFC 8693 section 2.1 describes.

Not broken: scope widening direct or chained; another organization's target; disabled source/target; lifetime extension by re-exchange; session proof or code as subject_token; wrong token types, both audience and resource, repeated parameters, client credentials; expiry edges; error codes do not reveal unknown/revoked/expired/disabled; a revoked subject leaves the exchanged credential active by design (original-design.md:2423, workload.yaml:2); introspection honest.

```findings
- file: crates/mandate-proto/src/oauth.rs
  line: 505
  category: contract-drift
  severity: warning
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'CLAUSE_CODES now maps SourceUnadmitted to invalid_grant but the exchange arm at serve.rs:764 hard-codes invalid_request and never consults the table, so the unit''s two new rows describe no wire behaviour'
- file: services/control-plane/src/adapters.rs
  line: 3080
  category: judgement
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: every refused exchange from the unauthenticated token endpoint is appended to an unbounded in-memory Vec that shipped code never reads
- file: crates/mandate-server/src/decode.rs
  line: 723
  category: acceptance
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: actor_token and audience-by-name refusals stop in the decoder, so no TokenExchangeDenied is recorded and the ExchangeNotSubjectOnly handler path cited by the obligations ledger is unreachable from the wire
- file: crates/mandate-server/src/decode.rs
  line: 747
  category: judgement
  severity: note
  verdict: INFEASIBLE
  origin: introduced
  message: the exchange target must be a registration UUID rather than the logical audience name RFC 8693 section 2.1 describes, which standard clients will not send
```

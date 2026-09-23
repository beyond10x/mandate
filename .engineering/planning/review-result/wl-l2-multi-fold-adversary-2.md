---
format: aep.planning-md/1
id: review-result:wl-l2-multi-fold-adversary-2
kind: review-result
status: active
title: Adversary pass 2 on L2 (control-plane-multi-fold-writes)
relations:
- reviews: story:control-plane-multi-fold-writes
revision: 1
---
unit: story:control-plane-multi-fold-writes, working tree af7d4e6 plus one untracked test file
verdict: red
cases: executed 168→170, red 1
origin: introduced 0, pre-existing 0, undecided 1
wrote-outside-worktree: ~/.cache/claude-tmp/wl/l2/scratch/adv2-suite.log
needs-coordinator: no

The correction holds; one new red case outside the story's three sites.

Cases in services/control-plane/tests/adversary_multi_fold_2.rs: a_refused_document_keeps_what_earlier_documents_seeded (green: earlier documents' state survives, RepeatedConnectionId still names a.json, refused b.json leaves nothing); two_documents_stating_one_link_identity_are_refused (red: b.json was admitted and its link is held nowhere; the fold holds only ["p@c0c0..."]).

Suite: cargo test -p mandate-control-plane --locked --no-fail-fast EXIT=101, 169 passed, 1 failed. clippy and fmt clean.

F1 adapters.rs:1011 NEEDS-CHANGE undecided warning: two --connection documents stating one external_principal_id are both admitted; record_link stores insert-if-absent, so the second link is dropped, printed as seeded, and every login through its connection is refused LinkAbsent. main.rs promises a set it cannot serve is refused before the socket; every other stated id has a Repeated* refusal. Reaches: an operator writing the optional link.external_principal_id into two documents; nothing found showing anybody does. Fix: RepeatedExternalPrincipalId in ConnectionSeeding::admit. Outside the story's scope.

Could not break: seeding copy-then-swap (no lost state, no double apply, incumbent unchanged); ClientSeeding swap changes nothing; OpeningSessionIssuer::issue is the last fallible step; the two documented-unreachable sites match record.rs and projection.rs.

```findings
- file: services/control-plane/src/adapters.rs
  line: 1011
  category: contract-drift
  severity: warning
  verdict: NEEDS-CHANGE
  origin: undecided
  message: 'ConnectionSeeding::admit never compares a stated external_principal_id across documents, so a second document using the same one is admitted and printed while the fold drops its link insert-if-absent, and every login through that connection is refused with LinkAbsent'
```

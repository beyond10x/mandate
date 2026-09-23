---
format: aep.planning-md/1
id: story:seeding-repeated-external-principal-id
kind: story
status: draft
title: Two connection documents may state one external principal id
relations:
- decomposes: epic:authentication
- serves: vision:mandate
scope:
- confidence: cited
  path: services/control-plane/src/adapters.rs
- confidence: cited
  path: services/control-plane/tests/adversary_multi_fold_2.rs
revision: 2
---
# Two connection documents may state one external principal id

## Why

Adversary pass 2 on unit L2 of wave L (`review-result:wl-l2-multi-fold-adversary-2`): `services/control-plane/src/adapters.rs` `ConnectionSeeding::admit` (~`:1011`) never compares a stated `link.external_principal_id` across documents. Two `--connection` documents stating one are both admitted; `record_link` in `crates/mandate-federation/src/record.rs` stores links insert-if-absent, so the second link is dropped while the process prints it as seeded, and every login through that connection is refused `LinkAbsent`. Every other stated id (connection, client, resource server, kid) already has a `Repeated*` refusal naming the incumbent file.

What reaches it: an operator writing the optional `link.external_principal_id` into two documents; nothing found showing anybody does.

## Acceptance

Given two connection documents stating one `external_principal_id`, when both are seeded, then the second is refused naming the first file, before the socket is bound; the case `two_documents_stating_one_link_identity_are_refused` in `services/control-plane/tests/adversary_multi_fold_2.rs` is re-pinned to the refusal.

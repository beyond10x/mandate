---
format: aep.planning-md/1
id: story:authorize-flood-eviction
kind: story
status: draft
title: An anonymous authorize flood evicts a waiting browser's sign-in
relations:
- decomposes: epic:authentication
- serves: vision:mandate
scope:
- confidence: cited
  path: services/control-plane/src/adapters.rs
revision: 2
---
# An anonymous authorize flood evicts a waiting browser's sign-in

## Why

Adversary pass 2 on unit M1 of wave M (`review-result:wm-m1-rp-flow-adversary-2`, B): `GET /v1/federation/authorize` is anonymous and every request adds a pending sign-in to one bounded store shared by all connections (`services/control-plane/src/adapters.rs` ~`:1032`); oldest-first eviction lets 4096 requests, sent in under a second, evict a browser waiting at its IdP. The code defers the residual pressure to an ingress rate limit, which nothing in this repository provides or checks.

## Acceptance

Given a burst of anonymous authorize requests, when a browser that started earlier returns within its lifetime, then its sign-in completes; the case `services/control-plane/tests/adversary_rp_flow_2.rs` that pins today's eviction is re-pinned to the completion.

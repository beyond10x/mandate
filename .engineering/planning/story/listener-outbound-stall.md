---
format: aep.planning-md/1
id: story:listener-outbound-stall
kind: story
status: draft
title: A slow external IdP stalls every route on the control-plane listener
relations:
- decomposes: epic:authentication
- serves: vision:mandate
scope:
- confidence: cited
  path: services/control-plane/src/serve.rs
revision: 2
---
# A slow external IdP stalls every route on the control-plane listener

## Why

Adversary pass 1 on unit M1 of wave M (`review-result:wm-m1-rp-flow-adversary-1`, F7): the listener is single-threaded (`services/control-plane/src/serve.rs:183`) and `/v1/federation/authorize` and `/v1/federation/callback` make outbound discovery and token-endpoint calls inline with a 5 s deadline; a failed discovery is not cached. An anonymous authorize-then-callback pair while the IdP is slow holds every other route. Not measured (a timing case would be flaky).

## Acceptance

Given an IdP whose token endpoint answers after its deadline, when a callback is in flight, then another route on the same process answers within its own bound; a case drives the two concurrently.

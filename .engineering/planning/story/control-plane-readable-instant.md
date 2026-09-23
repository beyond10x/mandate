---
format: aep.planning-md/1
id: story:control-plane-readable-instant
kind: story
status: draft
title: The control-plane's renders_readably admits an expiry before year 0
relations:
- decomposes: epic:authentication
- serves: vision:mandate
scope:
- confidence: inferred
  path: services/control-plane/src/adapters.rs
revision: 2
---
# The control-plane's renders_readably admits an expiry before year 0

## Why

Reported by the implementor of unit I3 in wave I (`story:sts-lifetime-bounds`), **not reproduced by the coordinator**: `services/control-plane`'s `instant::renders_readably` checks only where the separators sit, so `-001-12-31T23:00:01Z` passes it, while `mandate-sts`'s `instant::at` now refuses such an expiry (it reads the rendered text back). The two crates disagree on what a readable instant is.

What reaches it: not established.

## Acceptance

Given the timestamp `-001-12-31T23:00:01Z`, when the control-plane checks a lifetime against it, then it is refused as the STS refuses it — a case in `services/control-plane/tests` is red before and green after.

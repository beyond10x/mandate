---
format: aep.planning-md/1
id: story:federation-guard-trailing-dots
kind: story
status: draft
title: The federation guard folds every trailing dot of a host
relations:
- decomposes: epic:authentication
- serves: vision:mandate
scope:
- confidence: cited
  path: crates/mandate-federation/src/verifier_real.rs
revision: 2
---
# The federation guard folds every trailing dot of a host

## Why

Found by **reading only** by the implementor of unit J1 in wave J (`story:control-plane-loopback-fold`), which fixed the class in the control-plane: `crates/mandate-federation/src/verifier_real.rs` `folded` uses `trim_end_matches('.')`, so `localhost..` counts as loopback. Adversary pass 2 on unit I2 (`review-result:wijk-i2-folded-adversary-2`) confirmed multiple trailing dots are admitted as at base. The control-plane guard now strips at most one; the two guards disagree.

What reaches it: an issuer or JWKS destination spelled with two trailing dots; none found in the repository.

## Acceptance

Given `http://localhost..:8080`, when the federation guard decides it, then it answers as the control-plane guard does (refused); a case is red before and green after, and the 12,168-decision sweep's movement is recorded.

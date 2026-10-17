---
format: aep.planning-md/3
id: story:guard-stale-key-set-bound
kind: story
status: draft
title: The token guard bounds how long it keeps a stale JWK Set
relations:
- serves: vision:mandate
- informed_by: story:token-guard
revision: 1
---
# The token guard bounds how long it keeps a stale JWK Set

## Why

The wave 11 security review found that the guard keeps the JWK Set it holds when every refetch fails (`crates/mandate-client/src/verify.rs`, the `JwksSource` contract), so during an issuer outage a key the issuer withdrew keeps verifying past the 15-minute maximum age. Failing closed refuses every token while the issuer is down; the bound is a trade-off for the deployment to choose.

## Acceptance

Given a guard configured with a maximum staleness and a JWK Set source that fails every fetch, when the held set is older than that bound, then a token signed with a key from the held set is refused with a named reason; a case drives the clock past the bound.

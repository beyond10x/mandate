---
format: aep.planning-md/1
id: epic:sts-credentials
kind: epic
status: draft
title: STS and registered credentials
relations:
- serves: vision:mandate
- derived_from: specification:combined
revision: 1
---
# STS and registered credentials

## Deliverables

Audience registry, profiles, signed/reference issuance, verifier persistence, introspection, revocation, constrained OAuth exchange, service principals, asymmetric authentication, JWKS/key rotation and downstream example.

## Exit criteria

A service obtains a downstream credential whose subject/actor context and limits are no broader than the accepted exchange inputs.

## Required observations

Both cores satisfy their contracts before authority-bearing exchange; narrowing and expiry properties pass; actor survives; no universal token forwarding; key rotation without downtime.

## Contract and provenance

`systems/mandate/ess-inputs.yaml`, `docs/architecture/combined.md`, `docs/requirements.md` (all original phases and addendum requirements). Advanced delegation is deferred; other addendum requirements are mandatory.

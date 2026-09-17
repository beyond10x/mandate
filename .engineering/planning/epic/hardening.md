---
format: aep.planning-md/1
id: epic:hardening
kind: epic
status: draft
title: Operational security and resilience
relations:
- serves: vision:mandate
- derived_from: specification:combined
revision: 1
---
# Operational security and resilience

## Deliverables

Organization resets, emergency federation shutdown, key drills, reference/introspection load/cache tests, token theft/exchange-confusion simulations, tenant penetration tests, audit export/analytics, retention/tamper resistance, SLOs, quotas and recovery.

## Exit criteria

An emergency federation shutdown drill invalidates affected renewable access within the declared online revocation bound.

## Required observations

Documented online/offline revocation bounds and cache behavior verified under load and outages; redacted durable audit; incident runbooks exercised; full original production security checklist reviewed.

## Contract and provenance

`systems/mandate/ess-inputs.yaml`, `docs/architecture/combined.md`, `docs/requirements.md` (all original phases and addendum requirements). Advanced delegation is deferred; other addendum requirements are mandatory.

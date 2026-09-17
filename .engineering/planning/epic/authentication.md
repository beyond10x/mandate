---
format: aep.planning-md/1
id: epic:authentication
kind: epic
status: draft
title: Authentication and federation core
relations:
- serves: vision:mandate
- derived_from: specification:combined
revision: 1
---
# Authentication and federation core

## Deliverables

Organization-bound federation, explicit linking, JIT, OIDC discovery/JWKS, sessions, active org, public authorization-code/S256 PKCE, metadata, token validation, security epochs.

## Exit criteria

A user with an existing configured IdP session completes the reviewed public-client flow into one verified Mandate organization context.

## Required observations

Existing IdP SSO works without separate password; exact external keys and fail-closed tenant resolution; PKCE/replay/epoch/issuer tests pass; no upstream token propagation.

## Contract and provenance

`systems/mandate/ess-inputs.yaml`, `docs/architecture/combined.md`, `docs/requirements.md` (all original phases and addendum requirements). Advanced delegation is deferred; other addendum requirements are mandatory.

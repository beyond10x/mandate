---
format: aep.planning-md/1
id: epic:enterprise-directory
kind: epic
status: draft
title: Enterprise directory and identity lifecycle
relations:
- serves: vision:mandate
- derived_from: specification:combined
revision: 1
---
# Enterprise directory and identity lifecycle

## Deliverables

SCIM users/groups/memberships, explicit mapping provenance, deprovisioning, SAML, enterprise administration API/UI and IdP diagnostics.

## Exit criteria

An enterprise deprovisioning operation removes only its contributed authority within the declared propagation bound.

## Required observations

Directory alone grants nothing; manual/overlapping mappings survive; source-specific removal retracts only own authority; access removal within documented bounds; SSO separate from provisioning.

## Contract and provenance

`systems/mandate/ess-inputs.yaml`, `docs/architecture/combined.md`, `docs/requirements.md` (all original phases and addendum requirements). Advanced delegation is deferred; other addendum requirements are mandatory.

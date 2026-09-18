---
format: aep.planning-md/1
id: story:protocol-adapters
kind: story
status: draft
title: Implement product routes and OAuth adapters
relations:
- decomposes: epic:sts-credentials
- serves: vision:mandate
- depends_on: story:canonical-types
- depends_on: story:federation-linking
- depends_on: story:check-api
- depends_on: story:constrained-exchange
- depends_on: story:directory-provenance
- informed_by: initiative:next-ten-waves
- depends_on: story:audit-worker-delivery
scope:
- confidence: cited
  path: crates/mandate-proto
- confidence: cited
  path: crates/mandate-server
revision: 4
---
# Implement product routes and OAuth adapters

## Acceptance

Given a caller supplies spoofed authority selectors, when a product adapter decodes the request, then only credential-validated context reaches the corresponding application command.

## Required observations

Resolve UNMAPPED-GUARDS before exposing routes; trusted adapter constructs context and ignores/rejects spoofed authority selectors. Registration, linking, mapping, OAuth form encoding/errors, token exchange, introspection, revocation, metadata/JWKS comply with their protocols. credential-containment passes.

## Scope

- `crates/mandate-server` — cited planned scope; canonical directory granularity.
- `crates/mandate-proto` — cited planned scope; canonical directory granularity.

## Validation and contract

`task check` and the runtime tests named above. `tests/security/cases.json` is a contract corpus, not runtime evidence. ESS: `systems/mandate/ess-inputs.yaml`. Source: `docs/requirements.md` and combined architecture.

## Integration obligations

The trusted worker RecordAuditEvent ingress is part of this adapter delivery: authenticate the emitter independently of optional event subject/tenant, preserve unknown tenant on invalid-proof denials, and reject forged emitter or client-supplied tenant authority. Expose the completed worker append port through the actual adapter so audit-recovery-conformance can exercise it. Source: docs/architecture/audit-routing.md:3 and systems/mandate/domains/audit.yaml:113.

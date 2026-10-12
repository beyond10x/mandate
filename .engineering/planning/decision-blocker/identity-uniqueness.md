---
format: aep.planning-md/3
id: decision-blocker:identity-uniqueness
kind: decision-blocker
status: open
title: UNMAPPED-UNIQUENESS
relations:
- blocks: story:federation-linking
- blocks: story:credential-profiles
- blocks: story:agent-security
revision: 2
---
Enforce external key uniqueness by organization, immutable configured issuer and external subject; connection/organization agreement; organization-local registered audience uniqueness; and one current ceiling per agent and platform/tenant scope. Enforce these atomically in storage. Issuer is derived from the validated connection. Nominal IDs and plain JSON Schema do not establish composite uniqueness.

Source: `docs/architecture/unmapped.md`, `docs/architecture/ownership.md` and the preserved technical reviews. Clear only with concrete reviewed semantics and verification evidence.

## Ceiling half decided (2026-10-12)

The ceiling key, the current record and the conflict rule are decided in `decision-blocker:identity-uniqueness-ceiling`, which now blocks `story:agent-authority-kernel` in place of this record. The external-principal, audience and exchange-source halves, and runtime ceiling data for `story:agent-security`, stay open here.

---
format: aep.planning-md/1
id: decision-blocker:identity-uniqueness
kind: decision-blocker
status: open
title: UNMAPPED-UNIQUENESS
relations:
- blocks: story:federation-linking
- blocks: story:credential-profiles
- blocks: story:agent-security
- blocks: story:agent-authority-kernel
revision: 1
---
Enforce external key uniqueness by organization, immutable configured issuer and external subject; connection/organization agreement; organization-local registered audience uniqueness; and one current ceiling per agent and platform/tenant scope. Enforce these atomically in storage. Issuer is derived from the validated connection. Nominal IDs and plain JSON Schema do not establish composite uniqueness.

Source: `docs/architecture/unmapped.md`, `docs/architecture/ownership.md` and the preserved technical reviews. Clear only with concrete reviewed semantics and verification evidence.

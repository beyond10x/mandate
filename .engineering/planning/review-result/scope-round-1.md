---
format: aep.planning-md/1
id: review-result:scope-round-1
kind: review-result
status: active
title: scope critic round 1
relations:
- reviews: specification:combined
- reviews: epic:advanced-delegation
- reviews: epic:agents-workloads
- reviews: epic:authentication
- reviews: epic:authorization
- reviews: epic:enterprise-directory
- reviews: epic:foundations
- reviews: epic:hardening
- reviews: epic:scale-interoperability
- reviews: epic:sts-credentials
- reviews: story:advanced-delegation
- reviews: story:agent-security
- reviews: story:audit-client
- reviews: story:canonical-types
- reviews: story:check-api
- reviews: story:constrained-exchange
- reviews: story:credential-profiles
- reviews: story:directory-provenance
- reviews: story:domain-runtime
- reviews: story:federation-linking
- reviews: story:foundation-contracts
- reviews: story:graph-policy
- reviews: story:pkce-sessions
- reviews: story:protocol-adapters
- reviews: story:session-epochs
- reviews: story:tenancy-topology
revision: 1
---
needs-revision

specification:combined — “The CLI is both a product tool and an essential development/debugging surface” is promised, but no epic or story claims its management, check, delegation and audit commands; epic:foundations should retain explicit follow-on CLI work — docs/sources/original-design.md:2796

Read all 34 artifacts using `cat` and `aep plan artifact show`, both source snapshots, combined architecture, requirements mapping, exclusions and graph; ran `artifact kinds`, `relations`, `graph` and `validate` (valid); extracted 51 consolidated promises, traced 50 fully, and found CLI coverage limited to scaffolding and authentication.

Could not establish: none within the coverage perspective; explicit UNMAPPED decisions and deferred advanced functionality were treated as acknowledged omissions.

```findings
- file: docs/sources/original-design.md
  line: 2796
  category: scope
  severity: warning
  verdict: needs-revision
  origin: introduced
  message: “The CLI is both a product tool and an essential development/debugging surface” is promised, but no epic or story claims its management, check, delegation and audit commands; epic:foundations should retain explicit follow-on CLI work
```

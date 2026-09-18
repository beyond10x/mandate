---
format: aep.planning-md/1
id: review-result:ten-waves-acceptance-r2
kind: review-result
status: active
title: Ten-wave acceptance critic, round 2
relations:
- reviews: initiative:next-ten-waves
- reviews: story:canonical-types
- reviews: story:runtime-decision-dossier
- reviews: story:domain-runtime
- reviews: story:federation-linking
- reviews: story:graph-policy
- reviews: story:session-epochs
- reviews: story:tenancy-topology
- reviews: story:check-api
- reviews: story:directory-provenance
- reviews: story:pkce-sessions
- reviews: story:agent-authority-kernel
- reviews: story:audit-client
- reviews: story:audit-worker-delivery
- reviews: story:credential-profiles
- reviews: story:constrained-exchange
- reviews: story:recovery-runbooks
- reviews: story:agent-security
- reviews: story:protocol-adapters
- reviews: story:audit-recovery-conformance
- reviews: story:oauth-integration
- reviews: story:product-cli
- reviews: story:runtime-service-qualification
- reviews: task:runtime-wave-integration
revision: 1
---
needs-revision

story:pkce-sessions — the acceptance names an “expected non-consuming validation result” without specifying which verifier and redirect inputs must produce a validation candidate or a refusal — .engineering/planning/story/pkce-sessions.md:24

Read: 24/24 supplied artifacts in full through `aep plan artifact show`: initiative:next-ten-waves; story:canonical-types; story:runtime-decision-dossier; story:domain-runtime; story:federation-linking; story:graph-policy; story:session-epochs; story:tenancy-topology; story:check-api; story:directory-provenance; story:pkce-sessions; story:agent-authority-kernel; story:audit-client; story:audit-worker-delivery; story:credential-profiles; story:constrained-exchange; story:recovery-runbooks; story:agent-security; story:protocol-adapters; story:audit-recovery-conformance; story:oauth-integration; story:product-cli; story:runtime-service-qualification; task:runtime-wave-integration; also read the revised ten-wave proposal and inspected PKCE contracts, corpus expectations and changes using `rg`, `sed`, `nl` and `git diff`, retaining the charter, rubric, lifecycle and parent-epic context read earlier this session.

The three round-one acceptance findings are resolved. `aep plan artifact validate` exited 0 with findings-block warnings; coordinator retains the exact output locally.

Could not establish: runtime behavior or executable conformance results; implementation remains future conditional work. The existing PKCE corpus describes endpoint redemption, while the revised story owns non-consuming validation.

Out of lane: dependency completeness, parent coverage and shared-surface scheduling were not judged. No other critics’ review records were read; no files were written.

```findings
- file: .engineering/planning/story/pkce-sessions.md
  line: 24
  category: acceptance
  severity: warning
  verdict: needs-revision
  origin: introduced
  message: the acceptance names an “expected non-consuming validation result” without specifying which verifier and redirect inputs must produce a validation candidate or a refusal
```

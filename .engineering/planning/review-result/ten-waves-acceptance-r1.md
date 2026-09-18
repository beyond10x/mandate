---
format: aep.planning-md/1
id: review-result:ten-waves-acceptance-r1
kind: review-result
status: active
title: Ten-wave acceptance critic, round 1
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

story:graph-policy — the acceptance combines revision-bound denial and backend-type containment as independent outcomes instead of naming one conformance result — .engineering/planning/story/graph-policy.md:24

story:audit-recovery-conformance — the acceptance combines exactly-once recovery, tenant isolation and secret redaction as independent outcomes instead of naming one recovery-suite result — .engineering/planning/story/audit-recovery-conformance.md:24

task:runtime-wave-integration — the acceptance says integration surfaces “support each unit brief” without defining a recorded pass/fail result that establishes dispatch readiness — .engineering/planning/task/runtime-wave-integration.md:15

Read: 24/24 supplied artifacts in full through `aep plan artifact show`: initiative:next-ten-waves; story:canonical-types; story:runtime-decision-dossier; story:domain-runtime; story:federation-linking; story:graph-policy; story:session-epochs; story:tenancy-topology; story:check-api; story:directory-provenance; story:pkce-sessions; story:agent-authority-kernel; story:audit-client; story:audit-worker-delivery; story:credential-profiles; story:constrained-exchange; story:recovery-runbooks; story:agent-security; story:protocol-adapters; story:audit-recovery-conformance; story:oauth-integration; story:product-cli; story:runtime-service-qualification; task:runtime-wave-integration; additionally read eight parent epics, repository AGENTS.md, the complete ten-wave proposal, critic charter/rubric, kinds and initiative/story/task lifecycles, and inspected referenced contracts/scaffolds with `rg`, `rg --files` and `git diff`.

aep plan artifact validate exited 0 with four pre-existing reviews lacking findings blocks; coordinator retains the exact output locally.

Could not establish: runtime behavior or executable conformance results; the referenced packages currently contain scaffolds, and future implementation remains conditional. These are not findings against draft thinness.

Out of lane: dependency completeness, parent coverage and shared-surface scheduling were not judged. No other critic reports were read; no files were written.

```findings
- file: .engineering/planning/story/graph-policy.md
  line: 24
  category: acceptance
  severity: warning
  verdict: needs-revision
  origin: pre-existing
  message: the acceptance combines revision-bound denial and backend-type containment as independent outcomes instead of naming one conformance result
- file: .engineering/planning/story/audit-recovery-conformance.md
  line: 24
  category: acceptance
  severity: warning
  verdict: needs-revision
  origin: introduced
  message: the acceptance combines exactly-once recovery, tenant isolation and secret redaction as independent outcomes instead of naming one recovery-suite result
- file: .engineering/planning/task/runtime-wave-integration.md
  line: 15
  category: acceptance
  severity: warning
  verdict: needs-revision
  origin: introduced
  message: the acceptance says integration surfaces “support each unit brief” without defining a recorded pass/fail result that establishes dispatch readiness
```

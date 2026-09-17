---
format: aep.planning-md/1
id: review-result:acceptance-round-1
kind: review-result
status: active
title: acceptance critic round 1
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

story:advanced-delegation — the acceptance combines design approval, separate global-linking/device-flow decisions and chain proofs instead of naming one observable review outcome — .engineering/planning/story/advanced-delegation.md:20
story:agent-security — the acceptance combines ceiling-test results, independent identity authentication and privileged-call enforcement instead of naming one observable acceptance outcome — .engineering/planning/story/agent-security.md:22
story:audit-client — the acceptance combines audit completeness, serialized redaction and client enforcement as three independently passing outcomes — .engineering/planning/story/audit-client.md:24
story:canonical-types — the acceptance combines type realization, exclusion accounting and test execution across multiple statements instead of naming one observable realization outcome — .engineering/planning/story/canonical-types.md:26
story:check-api — the acceptance combines context validation, approval challenges, outage denial and decision metadata as independently passing outcomes — .engineering/planning/story/check-api.md:23
story:constrained-exchange — the acceptance combines upstream acceptance, runtime exchange evidence and authority-preservation requirements across multiple statements instead of naming one observable exchange outcome — .engineering/planning/story/constrained-exchange.md:22
story:credential-profiles — the acceptance combines target registration, credential persistence, introspection authorization and key-rotation verification as independently passing outcomes — .engineering/planning/story/credential-profiles.md:23
story:directory-provenance — the acceptance combines runtime directory results and preservation of another epic's exit criteria as independently passing outcomes — .engineering/planning/story/directory-provenance.md:23
story:domain-runtime — the acceptance combines resolving lifecycle decisions and updating contract artifacts without naming one observable transition that establishes the accepted lifecycle contract — .engineering/planning/story/domain-runtime.md:22
story:federation-linking — the acceptance combines account-linking scenario results and JWKS-cache/key-rollover verification as independently passing outcomes — .engineering/planning/story/federation-linking.md:20
story:foundation-contracts — the acceptance combines contract validation, recorded critic outcomes and binary behavior as three independently passing outcomes — .engineering/planning/story/foundation-contracts.md:25
story:graph-policy — the acceptance combines engine selection, adapter behavior and prevention of backend-type leakage as independently passing outcomes — .engineering/planning/story/graph-policy.md:22
story:pkce-sessions — the acceptance combines endpoint redemption scenarios, session-state checks and absence of embedded CLI secrets as independently passing outcomes — .engineering/planning/story/pkce-sessions.md:23
story:protocol-adapters — the acceptance combines guard resolution, protocol compliance and credential containment across multiple statements instead of naming one observable adapter outcome — .engineering/planning/story/protocol-adapters.md:24
story:session-epochs — the acceptance combines decision resolution, generation invariants and runtime race-test results across multiple statements instead of naming one observable invalidation outcome — .engineering/planning/story/session-epochs.md:21
story:tenancy-topology — the acceptance combines membership creation and resource-registration refusal as independently passing outcomes — .engineering/planning/story/tenancy-topology.md:23
epic:advanced-delegation — the exit criteria combine delegation-chain controls and simulation authority restrictions instead of naming one observable acceptance outcome — .engineering/planning/epic/advanced-delegation.md:20
epic:agents-workloads — the exit criteria combine agent ceilings, identity separation, revocation and sender constraints as independently passing outcomes — .engineering/planning/epic/agents-workloads.md:20
epic:authentication — the exit criteria combine SSO entry, tenant resolution, security tests and upstream-token containment as independently passing outcomes — .engineering/planning/epic/authentication.md:20
epic:authorization — the exit criteria combine live access changes, fail-closed tests, inheritance and audit completeness as independently passing outcomes — .engineering/planning/epic/authorization.md:20
epic:enterprise-directory — the exit criteria combine mapping-removal behavior, propagation bounds and subsystem separation as independently passing outcomes — .engineering/planning/epic/enterprise-directory.md:20
epic:foundations — the exit criteria combine validation, source integrity, publication and handoff preparation as independently passing outcomes — .engineering/planning/epic/foundations.md:21
epic:hardening — the exit criteria combine revocation verification, durable audit, runbook exercises and checklist review as independently passing outcomes — .engineering/planning/epic/hardening.md:20
epic:scale-interoperability — the exit criteria name “at scale” and “safe/testable model upgrades” without defining an observable workload, upgrade transition or passing result — .engineering/planning/epic/scale-interoperability.md:20
epic:sts-credentials — the exit criteria combine core readiness, exchange narrowing, actor preservation and uninterrupted key rotation as independently passing outcomes — .engineering/planning/epic/sts-credentials.md:20

Read: all 34 supplied artifacts through `aep plan artifact show <id>`: architecture-design:foundations; decision-blocker:{backend,epoch,epoch-atomicity,global-trust,guards,lifecycle}; epic:{advanced-delegation,agents-workloads,authentication,authorization,enterprise-directory,foundations,hardening,scale-interoperability,sts-credentials}; specification:combined; story:{advanced-delegation,agent-security,audit-client,canonical-types,check-api,constrained-exchange,credential-profiles,directory-provenance,domain-runtime,federation-linking,foundation-contracts,graph-policy,pkce-sessions,protocol-adapters,session-epochs,tenancy-topology}; vision:mandate; also read the charter/rubric, kind lifecycles, combined architecture, requirement mapping, security corpus, unmapped decisions and relevant preserved-source test/roadmap sections using `cat`, `rg` and `sed`; `aep plan artifact validate` returned `34 artifact(s)` and `valid`.

Could not establish: the snapshot contains no Taskfile or Rust implementation, so named runtime commands, symbols and tests cannot be verified here; the corpus explicitly supplies contract scenarios rather than runtime evidence.
Could not establish: draft vision/specification/design and open decision records do not yet establish completed acceptance evidence; their permitted initial-status thinness does not set this verdict.
Outside this lane: dependency ordering, scope coverage and shared-file ownership are not adjudicated.

```findings
- file: .engineering/planning/story/advanced-delegation.md
  line: 20
  category: acceptance
  severity: blocker
  verdict: needs-revision
  origin: introduced
  message: the acceptance combines design approval, separate global-linking/device-flow decisions and chain proofs instead of naming one observable review outcome
- file: .engineering/planning/story/agent-security.md
  line: 22
  category: acceptance
  severity: blocker
  verdict: needs-revision
  origin: introduced
  message: the acceptance combines ceiling-test results, independent identity authentication and privileged-call enforcement instead of naming one observable acceptance outcome
- file: .engineering/planning/story/audit-client.md
  line: 24
  category: acceptance
  severity: blocker
  verdict: needs-revision
  origin: introduced
  message: the acceptance combines audit completeness, serialized redaction and client enforcement as three independently passing outcomes
- file: .engineering/planning/story/canonical-types.md
  line: 26
  category: acceptance
  severity: blocker
  verdict: needs-revision
  origin: introduced
  message: the acceptance combines type realization, exclusion accounting and test execution across multiple statements instead of naming one observable realization outcome
- file: .engineering/planning/story/check-api.md
  line: 23
  category: acceptance
  severity: blocker
  verdict: needs-revision
  origin: introduced
  message: the acceptance combines context validation, approval challenges, outage denial and decision metadata as independently passing outcomes
- file: .engineering/planning/story/constrained-exchange.md
  line: 22
  category: acceptance
  severity: blocker
  verdict: needs-revision
  origin: introduced
  message: the acceptance combines upstream acceptance, runtime exchange evidence and authority-preservation requirements across multiple statements instead of naming one observable exchange outcome
- file: .engineering/planning/story/credential-profiles.md
  line: 23
  category: acceptance
  severity: blocker
  verdict: needs-revision
  origin: introduced
  message: the acceptance combines target registration, credential persistence, introspection authorization and key-rotation verification as independently passing outcomes
- file: .engineering/planning/story/directory-provenance.md
  line: 23
  category: acceptance
  severity: blocker
  verdict: needs-revision
  origin: introduced
  message: the acceptance combines runtime directory results and preservation of another epic's exit criteria as independently passing outcomes
- file: .engineering/planning/story/domain-runtime.md
  line: 22
  category: acceptance
  severity: blocker
  verdict: needs-revision
  origin: introduced
  message: the acceptance combines resolving lifecycle decisions and updating contract artifacts without naming one observable transition that establishes the accepted lifecycle contract
- file: .engineering/planning/story/federation-linking.md
  line: 20
  category: acceptance
  severity: blocker
  verdict: needs-revision
  origin: introduced
  message: the acceptance combines account-linking scenario results and JWKS-cache/key-rollover verification as independently passing outcomes
- file: .engineering/planning/story/foundation-contracts.md
  line: 25
  category: acceptance
  severity: blocker
  verdict: needs-revision
  origin: introduced
  message: the acceptance combines contract validation, recorded critic outcomes and binary behavior as three independently passing outcomes
- file: .engineering/planning/story/graph-policy.md
  line: 22
  category: acceptance
  severity: blocker
  verdict: needs-revision
  origin: introduced
  message: the acceptance combines engine selection, adapter behavior and prevention of backend-type leakage as independently passing outcomes
- file: .engineering/planning/story/pkce-sessions.md
  line: 23
  category: acceptance
  severity: blocker
  verdict: needs-revision
  origin: introduced
  message: the acceptance combines endpoint redemption scenarios, session-state checks and absence of embedded CLI secrets as independently passing outcomes
- file: .engineering/planning/story/protocol-adapters.md
  line: 24
  category: acceptance
  severity: blocker
  verdict: needs-revision
  origin: introduced
  message: the acceptance combines guard resolution, protocol compliance and credential containment across multiple statements instead of naming one observable adapter outcome
- file: .engineering/planning/story/session-epochs.md
  line: 21
  category: acceptance
  severity: blocker
  verdict: needs-revision
  origin: introduced
  message: the acceptance combines decision resolution, generation invariants and runtime race-test results across multiple statements instead of naming one observable invalidation outcome
- file: .engineering/planning/story/tenancy-topology.md
  line: 23
  category: acceptance
  severity: blocker
  verdict: needs-revision
  origin: introduced
  message: the acceptance combines membership creation and resource-registration refusal as independently passing outcomes
- file: .engineering/planning/epic/advanced-delegation.md
  line: 20
  category: acceptance
  severity: blocker
  verdict: needs-revision
  origin: introduced
  message: the exit criteria combine delegation-chain controls and simulation authority restrictions instead of naming one observable acceptance outcome
- file: .engineering/planning/epic/agents-workloads.md
  line: 20
  category: acceptance
  severity: blocker
  verdict: needs-revision
  origin: introduced
  message: the exit criteria combine agent ceilings, identity separation, revocation and sender constraints as independently passing outcomes
- file: .engineering/planning/epic/authentication.md
  line: 20
  category: acceptance
  severity: blocker
  verdict: needs-revision
  origin: introduced
  message: the exit criteria combine SSO entry, tenant resolution, security tests and upstream-token containment as independently passing outcomes
- file: .engineering/planning/epic/authorization.md
  line: 20
  category: acceptance
  severity: blocker
  verdict: needs-revision
  origin: introduced
  message: the exit criteria combine live access changes, fail-closed tests, inheritance and audit completeness as independently passing outcomes
- file: .engineering/planning/epic/enterprise-directory.md
  line: 20
  category: acceptance
  severity: blocker
  verdict: needs-revision
  origin: introduced
  message: the exit criteria combine mapping-removal behavior, propagation bounds and subsystem separation as independently passing outcomes
- file: .engineering/planning/epic/foundations.md
  line: 21
  category: acceptance
  severity: blocker
  verdict: needs-revision
  origin: introduced
  message: the exit criteria combine validation, source integrity, publication and handoff preparation as independently passing outcomes
- file: .engineering/planning/epic/hardening.md
  line: 20
  category: acceptance
  severity: blocker
  verdict: needs-revision
  origin: introduced
  message: the exit criteria combine revocation verification, durable audit, runbook exercises and checklist review as independently passing outcomes
- file: .engineering/planning/epic/scale-interoperability.md
  line: 20
  category: acceptance
  severity: blocker
  verdict: needs-revision
  origin: introduced
  message: the exit criteria name “at scale” and “safe/testable model upgrades” without defining an observable workload, upgrade transition or passing result
- file: .engineering/planning/epic/sts-credentials.md
  line: 20
  category: acceptance
  severity: blocker
  verdict: needs-revision
  origin: introduced
  message: the exit criteria combine core readiness, exchange narrowing, actor preservation and uninterrupted key rotation as independently passing outcomes
```

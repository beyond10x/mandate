---
format: aep.planning-md/1
id: review-result:contracts-review-1
kind: review-result
status: active
title: 'Contract review 1: ESS systems/mandate against the combined design'
relations:
- reviews: story:foundation-contracts
- reviews: specification:combined
revision: 1
---
needs-revision

story:foundation-contracts — `mandate.graph.Relation.subject` is a required `PrincipalId` and `WriteRelationship` accepts only a `PrincipalId` subject, so a team-subject relation such as `space:staging#operator@team:platform#member` (original §9.1) cannot be written — systems/mandate/domains/graph.yaml:45-48; systems/mandate/domains/graph.yaml:191-192; docs/sources/original-design.md:584-593

story:foundation-contracts — `mandate.graph.Grant` leaves both `principal` and `team` optional, so a grant with no target and a grant with two targets both validate while the design requires one of principal or team — systems/mandate/domains/graph.yaml:93-96; generated/schema/entities/mandate.graph.Grant.schema.json (required lists neither); docs/architecture/combined.md:23

story:foundation-contracts — `mandate.identity.SecurityEpochs` is keyed by `PrincipalId` with one `organization_id`, so a principal in two organizations has one row and the per-organization and per-connection generations have no record of their own — systems/mandate/domains/identity.yaml:114-124; docs/architecture/combined.md:17; docs/sources/architecture-addendum.md:395-401

story:foundation-contracts — `mandate.delegation.AgentCapabilityCeiling` is keyed by the agent `PrincipalId` with one `organization_id`, so the platform ceiling and the tenant ceiling the design intersects cannot both be recorded — systems/mandate/domains/delegation.yaml:83-89; docs/architecture/combined.md:9; docs/sources/original-design.md:3707-3714

story:foundation-contracts — `mandate.core.Decision` carries `revision` but no policy or model version, so a recorded decision is not attributable to the policy revision the vision and design promise, although `Execution.policy_version` shows the type exists — systems/mandate/domains/core.yaml:286-298; systems/mandate/domains/delegation.yaml:129-130; docs/vision.md:5; docs/architecture/combined.md:17

story:foundation-contracts — `mandate.audit.TokenExchangeDenied` requires `subject: PrincipalId` while `mandate.credential.TokenExchangeDenied` carries `context: Optional<VerifiedContext>`, so a denial for an invalid credential has no subject and cannot be recorded under the audit event's type — systems/mandate/domains/audit.yaml:90-99; systems/mandate/domains/credential.yaml:342-349; docs/sources/architecture-addendum.md:906-921

story:foundation-contracts — no command creates `mandate.audit.AuditEvent` and no binding routes any of the 39 domain events into `mandate.audit`, so the durable audit record the design requires has no producer in the contract — systems/mandate/domains/audit.yaml:4-68; systems/mandate/components.yaml:104-115; generated/docs/interactions.md:14-16; docs/architecture/combined.md:59

story:foundation-contracts — the audit domain declares 5 events where addendum §14 lists 20, and the 5 carry only subject, actor, organization and correlation, so requested audience, issued audience, scope, credential class, delegation, execution and result are absent from every audit event — systems/mandate/domains/audit.yaml:69-119; docs/sources/architecture-addendum.md:882-921

story:foundation-contracts — `ResourceServer.allowed_exchange_sources` is `List<Audience>` while audiences are organization-local, so a source audience string registered in another organization matches; addendum §7.1 types the list `Vec<ExchangeSource>` — systems/mandate/domains/credential.yaml:15-16; docs/architecture/combined.md:33; docs/sources/architecture-addendum.md:455

story:foundation-contracts — the (organization, issuer, subject) uniqueness of `ExternalPrincipal` is declared nowhere in the ESS, `issuer` is stored on both `ExternalPrincipal` and its `FederationConnection` and accepted twice by `LinkExternalPrincipal`, so the contract admits an external principal whose issuer differs from its connection's, and no UNMAPPED marker records the gap — systems/mandate/domains/federation.yaml:10-17; systems/mandate/domains/federation.yaml:57-58; systems/mandate/domains/federation.yaml:212-218; docs/architecture/unmapped.md:5-42 (no uniqueness entry); docs/architecture/combined.md:27

story:foundation-contracts — `IncrementSecurityEpoch` declares no `moves` and `SecurityEpochs` is terminal at `Recorded`, so the only epoch command changes nothing in the model while the generated OpenAPI still publishes it as an operation — systems/mandate/domains/identity.yaml:219-237; systems/mandate/domains/identity.yaml:125-130

story:foundation-contracts — `ResourceServer` and `FederationConnection` each encode enabled/disabled twice, as an `enabled: Boolean` field and as an Enabled/Disabled lifecycle, so `enabled: true` in state `Disabled` validates — systems/mandate/domains/credential.yaml:17-30; systems/mandate/domains/federation.yaml:63-76

story:foundation-contracts — every domain's `Denied.reason` is `DecisionReason`, whose variants include `Allowed`, so a refusal carrying reason `Allowed` validates — systems/mandate/domains/core.yaml:177-187; systems/mandate/domains/credential.yaml:351-355

story:foundation-contracts — `CreateDelegation` accepts no `transitive`, `not_before` or `execution_binding` while `Delegation` carries all three, so those fields can never be set by the only creation command — systems/mandate/domains/delegation.yaml:229-240; systems/mandate/domains/delegation.yaml:19-26

story:foundation-contracts — all 33 command `denied` outcomes carry the identical `external:` sentence, so the per-command deny conditions the design states (wrong verifier, plain method, redirect mismatch, replay) live only in the corpus, whose cases cite stories rather than commands — systems/mandate/domains/credential.yaml:97-99 (one of 33); grep -c "Authoritative credential, graph, policy or lifecycle validation fails" systems/mandate/domains/*.yaml; docs/architecture/combined.md:53

story:foundation-contracts — `SigningKey.algorithm`, `AuditEvent.event_type` and `AuditEvent.result` are bare `String` in a system whose crossings page says every type is used only as itself, and the design names an algorithm allowlist — systems/mandate/domains/credential.yaml:69-70; systems/mandate/domains/audit.yaml:15-16; systems/mandate/domains/audit.yaml:33-34; docs/architecture/combined.md:37

Read: all 16 ESS files under `systems/mandate` (2648 lines) with `cat -n`; `aep plan artifact list`, `kinds`, `relations`, `validate`, and `show` on 15 artifacts (vision, specification, architecture-design, epic:foundations, 7 decision-blockers, story:foundation-contracts, story:canonical-types, task:canonical-types-drive, 6 review-results); `docs/architecture/combined.md`, `docs/architecture/unmapped.md`, `docs/requirements.md`, `docs/threat-model/README.md`, 7 ADRs, `docs/vision.md`, `docs/handoff.md`, `docs/verification.md`, `docs/review-provenance.md`; original §9, §11, §48, §49 and addendum §6, §7, §14, §15 by line range; `generated/docs/{interactions,topology,crossings}.md`; 5 generated entity schemas' `required` lists; `tests/security/cases.json` (47 cases, 10 categories); `xtask/src/main.rs`; `components.yaml`; `dependency-boundaries.json`. Ran `ess specify validate --path systems/mandate` (mandate v1, 14 files, valid), `cargo xtask corpus`, `cargo xtask boundaries`, `cargo xtask contracts` (each exit 0), `sha256sum -c docs/sources/SHA256SUMS` (2 OK).

Could not establish: whether ess/4 can declare a uniqueness constraint or an exactly-one-of field pair; the installed ESS skill file names neither and `ess specify --help` lists no such surface, so the Grant and ExternalPrincipal findings may resolve as an UNMAPPED marker rather than a type change.
Could not establish: whether `Optional<ID>` beside `cardinality: one` is ESS's intended spelling for an optional reference; the generated schema omits such fields from `required`, which matches the design's claim, so it is not raised as a finding.
Could not establish: any runtime behaviour; none exists in the scaffold. The full `task check` (fmt, clippy, test, build, deny) was not run in the leased tree; the three contract sub-gates were.
Outside this lane: the 4 validator advisories on prose-only findings blocks are already documented in `docs/review-provenance.md`; plan shape, acceptance wording, coverage and parallel safety were judged by the four earlier critic rounds and are not re-judged here.

```findings
- file: systems/mandate/domains/graph.yaml
  line: 45
  category: contract
  severity: blocker
  verdict: needs-revision
  origin: pre-existing
  message: "`mandate.graph.Relation.subject` is a required `PrincipalId` and `WriteRelationship` accepts only a `PrincipalId` subject, so a team-subject relation such as `space:staging#operator@team:platform#member` (original §9.1) cannot be written"
- file: systems/mandate/domains/graph.yaml
  line: 93
  category: contract
  severity: blocker
  verdict: needs-revision
  origin: pre-existing
  message: "`mandate.graph.Grant` leaves both `principal` and `team` optional, so a grant with no target and a grant with two targets both validate while the design requires one of principal or team"
- file: systems/mandate/domains/identity.yaml
  line: 114
  category: contract
  severity: blocker
  verdict: needs-revision
  origin: pre-existing
  message: "`mandate.identity.SecurityEpochs` is keyed by `PrincipalId` with one `organization_id`, so a principal in two organizations has one row and the per-organization and per-connection generations have no record of their own"
- file: systems/mandate/domains/delegation.yaml
  line: 83
  category: contract
  severity: blocker
  verdict: needs-revision
  origin: pre-existing
  message: "`mandate.delegation.AgentCapabilityCeiling` is keyed by the agent `PrincipalId` with one `organization_id`, so the platform ceiling and the tenant ceiling the design intersects cannot both be recorded"
- file: systems/mandate/domains/core.yaml
  line: 286
  category: contract
  severity: blocker
  verdict: needs-revision
  origin: pre-existing
  message: "`mandate.core.Decision` carries `revision` but no policy or model version, so a recorded decision is not attributable to the policy revision the vision and design promise, although `Execution.policy_version` shows the type exists"
- file: systems/mandate/domains/audit.yaml
  line: 90
  category: contract
  severity: blocker
  verdict: needs-revision
  origin: pre-existing
  message: "`mandate.audit.TokenExchangeDenied` requires `subject: PrincipalId` while `mandate.credential.TokenExchangeDenied` carries `context: Optional<VerifiedContext>`, so a denial for an invalid credential has no subject and cannot be recorded under the audit event's type"
- file: systems/mandate/domains/audit.yaml
  line: 4
  category: contract
  severity: blocker
  verdict: needs-revision
  origin: pre-existing
  message: "no command creates `mandate.audit.AuditEvent` and no binding routes any of the 39 domain events into `mandate.audit`, so the durable audit record the design requires has no producer in the contract"
- file: systems/mandate/domains/audit.yaml
  line: 69
  category: contract
  severity: warning
  verdict: needs-revision
  origin: pre-existing
  message: "the audit domain declares 5 events where addendum §14 lists 20, and the 5 carry only subject, actor, organization and correlation, so requested audience, issued audience, scope, credential class, delegation, execution and result are absent from every audit event"
- file: systems/mandate/domains/credential.yaml
  line: 15
  category: contract
  severity: warning
  verdict: needs-revision
  origin: pre-existing
  message: "`ResourceServer.allowed_exchange_sources` is `List<Audience>` while audiences are organization-local, so a source audience string registered in another organization matches; addendum §7.1 types the list `Vec<ExchangeSource>`"
- file: systems/mandate/domains/federation.yaml
  line: 10
  category: contract
  severity: warning
  verdict: needs-revision
  origin: pre-existing
  message: "the (organization, issuer, subject) uniqueness of `ExternalPrincipal` is declared nowhere in the ESS, `issuer` is stored on both `ExternalPrincipal` and its `FederationConnection` and accepted twice by `LinkExternalPrincipal`, so the contract admits an external principal whose issuer differs from its connection's, and no UNMAPPED marker records the gap"
- file: systems/mandate/domains/identity.yaml
  line: 219
  category: contract
  severity: warning
  verdict: needs-revision
  origin: pre-existing
  message: "`IncrementSecurityEpoch` declares no `moves` and `SecurityEpochs` is terminal at `Recorded`, so the only epoch command changes nothing in the model while the generated OpenAPI still publishes it as an operation"
- file: systems/mandate/domains/credential.yaml
  line: 17
  category: contract
  severity: warning
  verdict: needs-revision
  origin: pre-existing
  message: "`ResourceServer` and `FederationConnection` each encode enabled/disabled twice, as an `enabled: Boolean` field and as an Enabled/Disabled lifecycle, so `enabled: true` in state `Disabled` validates"
- file: systems/mandate/domains/core.yaml
  line: 177
  category: contract
  severity: warning
  verdict: needs-revision
  origin: pre-existing
  message: "every domain's `Denied.reason` is `DecisionReason`, whose variants include `Allowed`, so a refusal carrying reason `Allowed` validates"
- file: systems/mandate/domains/delegation.yaml
  line: 229
  category: contract
  severity: warning
  verdict: needs-revision
  origin: pre-existing
  message: "`CreateDelegation` accepts no `transitive`, `not_before` or `execution_binding` while `Delegation` carries all three, so those fields can never be set by the only creation command"
- file: systems/mandate/domains/credential.yaml
  line: 97
  category: contract
  severity: warning
  verdict: needs-revision
  origin: pre-existing
  message: "all 33 command `denied` outcomes carry the identical `external:` sentence, so the per-command deny conditions the design states (wrong verifier, plain method, redirect mismatch, replay) live only in the corpus, whose cases cite stories rather than commands"
- file: systems/mandate/domains/credential.yaml
  line: 69
  category: contract
  severity: warning
  verdict: needs-revision
  origin: pre-existing
  message: "`SigningKey.algorithm`, `AuditEvent.event_type` and `AuditEvent.result` are bare `String` in a system whose crossings page says every type is used only as itself, and the design names an algorithm allowlist"
```

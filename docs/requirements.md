# Requirement traceability

Sources are preserved byte-for-byte. The addendum wins where it refines the original. Domain names resolve in `systems/mandate/ess-inputs.yaml`. A domain association names contract ownership, not runtime completeness. UNMAPPED obligations are linked in `architecture/unmapped.md`. Source anchors resolve to the preserved numbered section headings.

| Requirement | Source | ESS owner | AEP stage |
|---|---|---|---|
| O-00 | [Original §0](sources/original-design.md#0-executive-summary) — Executive summary | `mandate.core` | `epic:foundations` |
| O-01 | [Original §1](sources/original-design.md#1-product-identity-and-naming) — Product identity and naming | `mandate.core` | `epic:foundations` |
| O-02 | [Original §2](sources/original-design.md#2-architectural-principles) — Architectural principles | `mandate.core` | `epic:foundations` |
| O-03 | [Original §3](sources/original-design.md#3-goals-and-non-goals) — Goals and non-goals | `mandate.core` | `epic:foundations` |
| O-04 | [Original §4](sources/original-design.md#4-canonical-vocabulary) — Canonical vocabulary | `mandate.core` | `epic:foundations` |
| O-05 | [Original §5](sources/original-design.md#5-system-context) — System context | `mandate.core` | `epic:foundations` |
| O-06 | [Original §6](sources/original-design.md#6-trust-boundaries) — Trust boundaries | `mandate.core` | `epic:foundations` |
| O-07 | [Original §7](sources/original-design.md#7-principal-model) — Principal model | `mandate.federation` | `epic:authentication` |
| O-08 | [Original §8](sources/original-design.md#8-tenant-and-resource-model) — Tenant and resource model | `mandate.authorization` | `epic:authorization` |
| O-09 | [Original §9](sources/original-design.md#9-teams-roles-grants-and-rebac) — Teams, roles, grants, and ReBAC | `mandate.authorization` | `epic:authorization` |
| O-10 | [Original §10](sources/original-design.md#10-conditional-policy) — Conditional policy | `mandate.authorization` | `epic:authorization` |
| O-11 | [Original §11](sources/original-design.md#11-authorization-decision-model) — Authorization decision model | `mandate.authorization` | `epic:authorization` |
| O-12 | [Original §12](sources/original-design.md#12-identity-and-federation) — Identity and federation | `mandate.federation` | `epic:authentication` |
| O-13 | [Original §13](sources/original-design.md#13-sessions-and-active-organization-context) — Sessions and active organization context | `mandate.federation` | `epic:authentication` |
| O-14 | [Original §14](sources/original-design.md#14-security-token-service) — Security Token Service | `mandate.credential` | `epic:sts-credentials` |
| O-15 | [Original §15](sources/original-design.md#15-agent-security-architecture) — Agent security architecture | `mandate.delegation` | `epic:agents-workloads` |
| O-16 | [Original §16](sources/original-design.md#16-services-and-workload-identity) — Services and workload identity | `mandate.delegation` | `epic:agents-workloads` |
| O-17 | [Original §17](sources/original-design.md#17-customer-built-external-agents) — Customer-built external agents | `mandate.delegation` | `epic:agents-workloads` |
| O-18 | [Original §18](sources/original-design.md#18-resource-service-integration) — Resource-service integration | `mandate.authorization` | `epic:authorization` |
| O-19 | [Original §19](sources/original-design.md#19-consistency-caching-and-revocation) — Consistency, caching, and revocation | Cross-cutting: `mandate.graph`, `mandate.credential`, `mandate.authorization`; runtime consistency/revocation adapters | `epic:hardening` |
| O-20 | [Original §20](sources/original-design.md#20-audit-model) — Audit model | `mandate.audit` | `epic:hardening` |
| O-21 | [Original §21](sources/original-design.md#21-public-api-surfaces) — Public API surfaces | `mandate.authorization` | `epic:scale-interoperability` |
| O-22 | [Original §22](sources/original-design.md#22-rust-repository-structure) — Rust repository structure | `mandate.core` | `epic:foundations` |
| O-23 | [Original §23](sources/original-design.md#23-rust-crate-responsibilities) — Rust crate responsibilities | `mandate.core` | `epic:foundations` |
| O-24 | [Original §24](sources/original-design.md#24-workspace-dependency-direction) — Workspace dependency direction | `mandate.core` | `epic:foundations` |
| O-25 | [Original §25](sources/original-design.md#25-initial-deployment-topology) — Initial deployment topology | `mandate.core` | `epic:foundations` |
| O-26 | [Original §26](sources/original-design.md#26-storage-model) — Storage model | `mandate.credential` | `epic:sts-credentials` |
| O-27 | [Original §27](sources/original-design.md#27-data-model-invariants) — Data-model invariants | `mandate.core` | `epic:foundations` |
| O-28 | [Original §28](sources/original-design.md#28-token-and-protocol-security) — Token and protocol security | `mandate.federation` | `epic:authentication` |
| O-29 | [Original §29](sources/original-design.md#29-key-management) — Key management | `mandate.credential` | `epic:sts-credentials` |
| O-30 | [Original §30](sources/original-design.md#30-threat-model) — Threat model | Cross-cutting: `docs/threat-model/README.md` and every trust boundary | `epic:hardening` |
| O-31 | [Original §31](sources/original-design.md#31-rust-engineering-guidelines) — Rust engineering guidelines | `mandate.core` | `epic:foundations` |
| O-32 | [Original §32](sources/original-design.md#32-cli) — CLI | `mandate.core` | `epic:foundations` |
| O-33 | [Original §33](sources/original-design.md#33-test-strategy) — Test strategy | Cross-cutting: `tests/security/cases.json`, `xtask`, and owning runtime suites | `epic:hardening` |
| O-34 | [Original §34](sources/original-design.md#34-observability-and-slo-design) — Observability and SLO design | Cross-cutting: service telemetry and SLO adapters (planned) | `epic:hardening` |
| O-35 | [Original §35](sources/original-design.md#35-availability-and-failure-behavior) — Availability and failure behavior | Cross-cutting: all four service boundaries and failure-policy adapters | `epic:hardening` |
| O-36 | [Original §36](sources/original-design.md#36-administrative-security) — Administrative security | Cross-cutting: `mandate.authorization`, `mandate.identity`, `mandate.federation`, `mandate.credential` | `epic:hardening` |
| O-37 | [Original §37](sources/original-design.md#37-schema-and-policy-change-management) — Schema and policy change management | `mandate.authorization` | `epic:scale-interoperability` |
| O-38 | [Original §38](sources/original-design.md#38-enterprise-provisioning-lifecycle) — Enterprise provisioning lifecycle | `mandate.directory` | `epic:enterprise-directory` |
| O-39 | [Original §39](sources/original-design.md#39-example-end-to-end-flows) — Example end-to-end flows | `mandate.core` | `epic:foundations` |
| O-40 | [Original §40](sources/original-design.md#40-roadmap) — Roadmap | `mandate.core` | `epic:foundations` |
| O-41 | [Original §41](sources/original-design.md#41-recommended-adrs) — Recommended ADRs | `mandate.core` | `epic:foundations` |
| O-42 | [Original §42](sources/original-design.md#42-open-design-questions) — Open design questions | `mandate.core` | `epic:foundations` |
| O-43 | [Original §43](sources/original-design.md#43-standards-and-rfc-map) — Standards and RFC map | `mandate.authorization` | `epic:scale-interoperability` |
| O-44 | [Original §44](sources/original-design.md#44-standards-watchlist) — Standards watchlist | `mandate.authorization` | `epic:scale-interoperability` |
| O-45 | [Original §45](sources/original-design.md#45-authorization-implementation-references) — Authorization implementation references | `mandate.authorization` | `epic:scale-interoperability` |
| O-46 | [Original §46](sources/original-design.md#46-example-authorization-schema) — Example authorization schema | `mandate.authorization` | `epic:authorization` |
| O-47 | [Original §47](sources/original-design.md#47-delegation-data-model) — Delegation data model | `mandate.delegation` | `epic:agents-workloads` |
| O-48 | [Original §48](sources/original-design.md#48-agent-capability-data-model) — Agent capability data model | `mandate.delegation` | `epic:agents-workloads` |
| O-49 | [Original §49](sources/original-design.md#49-authorization-formula) — Authorization formula | `mandate.delegation` | `epic:agents-workloads` |
| O-50 | [Original §50](sources/original-design.md#50-design-guidance-for-resource-teams) — Design guidance for resource teams | `mandate.authorization` | `epic:scale-interoperability` |
| O-51 | [Original §51](sources/original-design.md#51-recommended-initial-product-ux) — Recommended initial product UX | `mandate.authorization` | `epic:scale-interoperability` |
| O-52 | [Original §52](sources/original-design.md#52-security-review-checklist-before-first-production-release) — Security review checklist before first production release | Cross-cutting: production release/security checklist; no single ESS domain | `epic:hardening` |
| O-53 | [Original §53](sources/original-design.md#53-final-architectural-stance) — Final architectural stance | `mandate.core` | `epic:foundations` |
| O-54 | [Original §54](sources/original-design.md#54-primary-reference-index) — Primary reference index | `mandate.core` | `epic:foundations` |
| A-01 | [Addendum §1](sources/architecture-addendum.md#1-purpose) — Purpose | `mandate.core` | `epic:foundations` |
| A-02 | [Addendum §2](sources/architecture-addendum.md#2-directory-groups-and-authorization-teams-are-different-concepts) — Directory groups and authorization teams are different concepts | `mandate.directory` | `epic:enterprise-directory` |
| A-03 | [Addendum §3](sources/architecture-addendum.md#3-accesscredential-is-an-abstraction-not-synonymous-with-jwt) — AccessCredential is an abstraction, not synonymous with JWT | `mandate.credential` | `epic:sts-credentials` |
| A-04 | [Addendum §4](sources/architecture-addendum.md#4-external-principal-linking-must-be-explicit) — External principal linking must be explicit | `mandate.federation` | `epic:authentication` |
| A-05 | [Addendum §5](sources/architecture-addendum.md#5-tenant-resolution-must-be-verified-and-fail-closed) — Tenant resolution must be verified and fail closed | `mandate.federation` | `epic:authentication` |
| A-06 | [Addendum §6](sources/architecture-addendum.md#6-epoch-based-invalidation) — Epoch-based invalidation | `mandate.identity` | `epic:authentication` |
| A-07 | [Addendum §7](sources/architecture-addendum.md#7-audience-and-resource-registration) — Audience and resource registration | `mandate.credential` | `epic:sts-credentials` |
| A-08 | [Addendum §8](sources/architecture-addendum.md#8-public-clients-and-cli-authentication) — Public clients and CLI authentication | `mandate.federation` | `epic:authentication` |
| A-09 | [Addendum §9](sources/architecture-addendum.md#9-token-exchange-hardening) — Token exchange hardening | `mandate.credential` | `epic:sts-credentials` |
| A-10 | [Addendum §10](sources/architecture-addendum.md#10-upstream-credential-containment) — Upstream credential containment | `mandate.credential` | `epic:sts-credentials` |
| A-11 | [Addendum §11](sources/architecture-addendum.md#11-authorization-api-implications) — Authorization API implications | `mandate.authorization` | `epic:authorization` |
| A-12 | [Addendum §12](sources/architecture-addendum.md#12-rust-workspace-changes) — Rust workspace changes | `mandate.core` | `epic:foundations` |
| A-13 | [Addendum §13](sources/architecture-addendum.md#13-storage-changes) — Storage changes | `mandate.credential` | `epic:sts-credentials` |
| A-14 | [Addendum §14](sources/architecture-addendum.md#14-audit-requirements) — Audit requirements | `mandate.audit` | `epic:hardening` |
| A-15 | [Addendum §15](sources/architecture-addendum.md#15-security-invariants-added-by-this-document) — Security invariants added by this document | `mandate.core` | `epic:foundations` |
| A-16 | [Addendum §16](sources/architecture-addendum.md#16-test-plan-additions) — Test-plan additions | `mandate.core` | `epic:foundations` |
| A-17 | [Addendum §17](sources/architecture-addendum.md#17-roadmap-changes) — Roadmap changes | `mandate.core` | `epic:foundations` |
| A-18 | [Addendum §18](sources/architecture-addendum.md#18-api-additions) — API additions | `mandate.credential` | `epic:sts-credentials` |
| A-19 | [Addendum §19](sources/architecture-addendum.md#19-operational-guidance) — Operational guidance | `mandate.credential` | `epic:hardening` |
| A-20 | [Addendum §20](sources/architecture-addendum.md#20-rfc-and-standards-references) — RFC and standards references | `mandate.core` | `epic:scale-interoperability` |
| A-21 | [Addendum §21](sources/architecture-addendum.md#21-final-architecture-after-this-addendum) — Final architecture after this addendum | `mandate.core` | `epic:foundations` |

## Original roadmap deliverables

The following mapping preserves every phase deliverable and exit criterion; the combined roadmap changes ordering, not coverage. Authentication and authorization proceed in parallel after shared contracts.

## Phase 0 — Foundations and threat model

Deliverables:

- repository/workspace skeleton;
- canonical IDs and domain vocabulary;
- ADR process;
- formal threat-model document;
- cryptographic/key-management strategy;
- organization isolation invariants;
- API versioning rules;
- dependency/supply-chain policy;
- local dev environment.

Exit criteria:

- security invariants reviewed;
- crate dependency rules enforced;
- no implementation begins without tenant model and subject/actor semantics being stable.

Combined owner: `epic:foundations`.

## Phase 1 — Core multi-tenant authorization

Deliverables:

- principals;
- organizations/memberships;
- teams;
- spaces;
- resource refs;
- relationships;
- grants;
- authorization check API;
- chosen graph backend adapter;
- audit events;
- Rust client;
- example Axum resource service;
- schema/model tests.

Exit criteria:

- org admin can change team membership and resource grants without redeploying a resource service;
- cross-tenant tests fail closed;
- resource inheritance works;
- audit contains every control-plane mutation and decision identifier.

Combined owner: `epic:authorization`.

## Phase 2 — Identity, OIDC, sessions

Deliverables:

- external identity mapping;
- OIDC federation;
- sessions;
- active org context;
- JIT provisioning;
- issuer/JWKS hardening;
- authorization-code + PKCE;
- OAuth metadata;
- Mandate token validation library.

Exit criteria:

- customer user with an existing IdP session can enter Mandate-protected flows without creating a separate password/account login;
- `(issuer, subject)` mapping is canonical;
- resource services trust Mandate tokens rather than customer IdPs.

Combined owner: `epic:authentication`.

## Phase 3 — STS and service identity

Deliverables:

- `mandate-sts`;
- OAuth token endpoint;
- token exchange;
- audience/resource downscoping;
- `act` claim;
- service principals;
- asymmetric client authentication;
- JWKS/key rotation;
- short-lived tokens;
- revocation/introspection strategy;
- downstream service exchange example.

Exit criteria:

- service A can obtain a narrower token for service B while preserving the original subject;
- universal token forwarding is not required;
- signing-key rotation works without downtime.

Combined owner: `epic:sts-credentials`.

## Phase 4 — Agents, delegation, execution security

Deliverables:

- agent principals;
- agent installations/ownership;
- capability ceilings;
- delegation records;
- execution IDs;
- user -> agent token exchange;
- service -> agent delegation;
- org/team persistent agent grants;
- tool-call PEP integration;
- approval challenge flow;
- agent audit/provenance.

Exit criteria:

- an agent can never exceed both the subject and its own ceiling;
- agent actions retain actor + subject;
- revoked delegation blocks new exchanges;
- prompt content cannot independently authorize an action.

Combined owner: `epic:agents-workloads`.

## Phase 5 — Enterprise identity lifecycle

Deliverables:

- SAML;
- SCIM users/groups;
- group-to-team mapping;
- deprovisioning;
- enterprise admin UI/API;
- IdP test/diagnostics;
- tenant audit export.

Exit criteria:

- enterprise tenant can provision/deprovision users and teams;
- access removal propagates within documented consistency bounds;
- SSO and provisioning remain separate subsystems.

Combined owner: `epic:enterprise-directory`.

## Phase 6 — Workload identity and proof-of-possession

Deliverables:

- SPIFFE-compatible workload credential exchange;
- DPoP and/or mTLS sender-constrained tokens;
- workload identity metadata in audit;
- external customer agent federation;
- workload trust-domain policy.

Exit criteria:

- high-value agent/service tokens can be sender constrained;
- workload and application principal identities remain distinct.

Combined owner: `epic:agents-workloads`.

## Phase 7 — Scale and interoperability

Deliverables:

- batch authorization;
- list-resources/list-subjects;
- materialized indexes where needed;
- revision/consistency API;
- AuthZEN adapter;
- policy/schema deployment pipeline;
- multi-region strategy;
- tenant quotas;
- SDK generation;
- performance/load suite.

Exit criteria:

- list/search APIs are authorization-aware at scale;
- authorization model upgrades are safe and testable;
- documented external interoperability surface exists.

Combined owner: `epic:scale-interoperability`.

## Phase 8 — Advanced delegation

Only after the simpler model is well understood:

- structured Rich Authorization Request mappings;
- limited delegation chains;
- transaction/task tokens;
- fine-grained one-shot capability tokens;
- policy simulations;
- "what-if" authorization analysis;
- access review/certification.

---

Combined owner: `epic:advanced-delegation`.

# Combined architecture

Normative precedence: this combined document applies the supplied architecture addendum to the original design; both immutable snapshots and digests are in `../sources/`. `../requirements.md` maps every source section and original roadmap deliverable to the combined work. An explicit `UNMAPPED` item limits executable coverage; it does not waive a requirement.

## Corrections to the original

The sequence in original §39.2 does not authorize delivering Alice's bearer token to an agent. Trusted session infrastructure retains the original user credential and submits the independently authenticated subject and actor proofs to STS. Only the narrowed output reaches the agent. Upstream provider access/refresh secrets remain within a dedicated encrypted secrets boundary, absent from downstream services, prompt context, logs and audit.

The autonomous formula in original §49 also includes the agent capability ceiling whenever the acting principal is an agent. Effective direct agent authority is graph authority intersected with its platform and tenant ceilings, tenant/space, audience/resource and current policy. Delegated agent authority additionally intersects the subject, explicit delegation and requested capabilities. A tenant configuration can narrow, never widen, a platform ceiling.

Approval-required is always `allowed = false`, with a structured challenge. An authentic, scoped, unexpired approval leads to a new check; a prompt or ignored obligation never converts denial into permission.

## Domain and ownership

ESS sources in `systems/mandate` define named identifiers, records, references, command inputs/responses, events and supported transitions. `components.yaml` records four deployment boundaries. Library boundaries are finer: types → model → graph/policy → authz; token depends only on types; identity and federation are separate from authorization. Adapters contain HTTP, concrete databases and graph-backend details. The STS deployment alone owns issuance, introspection/resolution, exchange and revocation; control-plane administration invokes those capabilities. Browser federation establishes sessions; STS redeems codes and issues credentials. Worker handles asynchronous audit/export, cleanup and synchronization orchestration without minting credentials.

Organization is the isolation root. Principals may join multiple organizations; roles are contextual relationships, never a global user field. Every tenant-owned record resolves to exactly one organization. Resource services own existence and business state; Mandate registers only security topology. Registration validates ownership and parent tenancy; unresolved or cross-tenant parents deny, and resources remain inaccessible until topology is admitted. Policy and authorization models are versioned; decisions retain their versions and graph revision.

Relations use `references` when records outlive their links (not cascade ownership); a bare carrying ID makes a one relation required and `Optional<ID>` makes it optional under ESS. Data-retention ownership and unsettled deletion behavior are tracked in UNMAPPED-LIFECYCLE. `Recorded` is the initial observed state of a record under immutable-with-status; every later state is a declared transition moved by exactly one command, and none is destructive. No runtime implementor may infer deletion or reactivation where the contract declares no transition; expiry is read from a record's own timestamp, never moved.

The [ownership map](ownership.md) assigns every ESS domain to the original libraries and explains the shared vocabulary publisher. This document is normative; the AEP architecture record references it instead of maintaining a second copy. Worker scheduling, cleanup and synchronization transport remain UNMAPPED-ORCHESTRATION; the declared worker ingress is the trusted audit append port.

Authorization codes are owned by STS. Public-client authorization invokes its issuance port; STS performs verifier resolution, one-use consumption, credential creation and durable audit outbox commit within one transaction. The consumed code binds registered target, narrowed scope, client, redirect and S256 proof. The internal server-resolved code identifier is not a public OAuth parameter or independent authority.

Graph subjects are a tagged principal-or-team value, so a grant cannot have zero or two targets. Conditional branch references retain exactly-one, non-owning semantics under UNMAPPED-SUBJECT-RELATIONS; ESS cannot express a relation carrier through a union branch. Generation ownership is separately keyed by principal, organization and federation connection. Snapshot handles identify immutable records; no UUID, String or Integer stands in for an unsigned generation value. Exact values and arithmetic remain UNMAPPED-EPOCH.

## Directory and membership provenance

SCIM writes directory groups and directory memberships. Directory membership alone grants nothing. Explicit, audited organization-local DirectoryGroupTeamMapping contributes to TeamMembership through MembershipContribution. A contribution identifies its source mapping, or an explicit manual source with no mapping. Effective membership exists while at least one valid contribution exists. Removing one mapping retracts only that mapping's contributions; manual and overlapping mappings survive. The team is never deleted as a side effect. Mapping, source membership and target team must share an organization. Administrative grants target principals or teams, never directory groups. Filtered/policy-driven mapping and nested-team cycle limits require their own implementation decisions.

## Verified external identity and tenancy

ExternalPrincipal is the canonical linking record. Initial uniqueness is (organization, issuer, subject), using exact configured issuer and opaque subject values. Subject-only keys, email equality and similar hostnames cannot merge accounts. Linking is explicit, collision checked, authorized and audited; global trust/linking is deferred. Unlinking invalidates renewable state through principal generation changes.

FederationConnection binds one organization, issuer, client and tenant-resolution rule. Select registered trust, verify issuer/signature, client audience, redirect, nonce/state/PKCE as applicable, then validate configured tenant claims/binding. Exactly one matching tenant is required before context or a session exists. Zero/multiple matches deny. Query organization selectors are routing hints only; email domains and unverified claims never establish authority.

## Credentials and audiences

CredentialKind distinguishes SelfContained and Reference. CredentialDescriptor carries subject, optional actor, organization, one intended audience, narrowed scope, delegation/execution and expiry. ResourceServer registers an audience, organization scope, enabled state, named profile and allowed exchange sources. Initial registration is organization-local; global audiences require a separate trust decision. Unknown/disabled targets deny issuance and exchange. Audience selection requests a restriction, not authority.

Named profiles choose format, maximum TTL, required online authorization and revocation guarantee. Example profile names are browser-api, agent-high-risk and internal-read-api; sample minute values in source are illustrative, never protocol constants. ImmediateOnline requires current authoritative revocation checks and no stale positive credential cache. BoundedOffline permits validity only until the documented TTL/skew bound; a valid signature alone proves neither current permission nor immediate revocation. Authorization caches separately obey consistency/revision rules.

Opaque credentials use at least 256 random bits. Raw bearer values are returned only at issuance; persistence stores non-reversible verifiers and a safe lookup index. Keyed/collision-resistant verification and constant-time comparison are implementation obligations. Refresh credentials and authorization codes likewise persist verifiers. CredentialSecret and CredentialProof are transient boundary types, never persisted entity fields or audit payloads. Signed credentials validate algorithm allowlist, issuer, audience, timestamps, key identity and sender constraints where required. Cryptographic primitives use reviewed libraries; private keys reside behind a key provider.

## Epoch invalidation

PrincipalEpoch, OrganizationSecurityEpoch and FederationEpoch are distinct monotonically increasing unsigned generations. Relevant sessions and renewable credentials snapshot all applicable generations. Refresh, exchange and profile-designated high-risk operations compare current authoritative values; any mismatch denies. Principal disable/unlink, organization reset and federation change/disable advance the appropriate generation atomically with the security change. Changes in organization A do not invalidate unrelated organization B sessions, except a deliberately global principal reset. Overflow must fail closed, never wrap or reset. ESS 0.25.0 cannot express the required u64/monotonic/atomic semantics: UNMAPPED-EPOCH is blocking for epoch realization. EpochSnapshotRef is only a reference to a future authoritative snapshot, not a numeric substitute. Epochs supplement graph revocation; they never replace it.

## Exchange and authorization

Context is constructed only from validated credentials by a trusted adapter before application decoding. Generated command inputs represent internal contracts, not caller-set trust headers. Product routes must strip external context and produce a validated context; `organization`, `subject`, `actor` and `audience` selectors cannot establish authority.

Exchange validates subject and actor independently and preserves both. Effective authority is the intersection of subject authority, actor ceiling, explicit delegation, requested authority, tenant/space/resource, registered target and current policy. Denies override grants. The output expiry is at most the earliest applicable subject/actor credential, delegation and policy expiry. Explicit future renewable-session rules cannot be inferred to extend it. Existing source credentials must be eligible for the registered exchange target; an empty source list grants none. No cross-organization escalation, staging-to-production widening, wildcard audience or actor removal is allowed. Transitive delegation is initially disabled.

PDP checks principal and context validity, organization/resource ownership, graph authority, policy, applicable ceilings, delegation and current revocation/consistency state. Outages and unknown resources fail closed. Resource services enforce every privileged call including agent tools. Workload identity proves runtime origin; application agent identity and ExecutionId remain separately visible.

## Protocol adapters

Initial public/native/CLI authentication uses authorization-code with S256 PKCE, exact registered redirects, state/nonce and atomic one-use code consumption. No embedded public-client secret is a security control. Missing/wrong verifier, plain, redirect mismatch, expired code and replay deny. Device authorization is deferred.

Product adapters must implement registration, explicit external linking and mapping routes; OAuth authorization/token endpoints, RFC 8693 exchange, RFC 8707 resource indicators, RFC 7662 introspection, revocation, metadata and JWKS; OIDC, later SAML/SCIM, and later AuthZEN. ESS semantic OpenAPI describes commands but does not implement these routes, encodings, errors or authentication middleware. Protocol conformance and metadata remain acceptance obligations in the roadmap.

## Audit, operational security and deferred decisions

Audit is durable security evidence, separate from tracing. It includes linking/unlinking, federation changes, generation increments, mapping changes, registered servers, credential issuance/introspection/revocation and exchange allow/deny. Retain subject/actor, organization, requested/issued target, requested narrowing, credential class, delegation/execution, result and decision correlation. Never record raw credentials, upstream secrets or sensitive prompt bodies. Durability, retention, tamper resistance and export are explicit later gates, not implied by a typed event.

Graph backend, policy implementation, key provider, sender-constraint profile, retention and cache bounds need reviewed decisions before their implementation. PostgreSQL is the initial storage direction, not a chosen authorization engine. Administrative changes require least privilege, tenant scoping, audit and high-risk reauthentication/approval. Operational work includes quotas, latency/error metrics without secrets, key rotation, emergency shutdown, consistency/load tests and disaster drills. See the roadmap for original deliverables retained across scale, interoperability and advanced delegation. The foundation implements none of these runtime guarantees.

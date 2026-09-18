# Unmapped semantics and linked blockers

These are required implementation decisions, not silently implemented behavior. Canonical Rust realization may include only accepted types; excluded semantics remain blocked.

## UNMAPPED-EPOCH

ESS 0.25.0 has no unsigned primitive. On 2026-09-18 the operator decided the generation is an ESS `Integer`, constrained `generation >= 0` and monotonic, declared on PrincipalSecurityEpoch, OrganizationSecurityEpoch and FederationSecurityEpoch as the recorded stand-in for the addendum's u64; widening to an unsigned type when ESS gains one is a compatible change. Increment at the maximum denies rather than wraps. EpochSnapshotRef remains a handle. Arithmetic and the runtime comparison are `story:session-epochs`; the field is declared, not computed. Realization of the three records as Rust types stays excluded from the canonical account.

AEP: `decision-blocker:epoch` blocks `story:session-epochs`.

## UNMAPPED-LIFECYCLE

On 2026-09-18 the operator decided immutable-with-status: nothing is destroyed; every lifecycle change is a new recorded state, and retention is redaction (`docs/adr/0009-event-sourced-persistence.md`). The 34 transitions the contract now declares are each moved by exactly one command; prohibitions are recorded in the contract where a mutation is refused (no execution expiry move, no approval reinstatement, no reactivation of a superseded policy or model, no deletion of an audit event). There is no UpdateFederationConnection: a changed connection is `disable` plus `RegisterFederationConnection`. The concrete audit retention floor is still owed.

AEP: `decision-blocker:lifecycle` blocks `story:domain-runtime`.

## UNMAPPED-GUARDS

ESS command outcomes describe authoritative external validation, not executable cryptographic, graph or policy predicates. Add trusted context adapter, actual validation and negative conformance tests; generated command routes must never be exposed as product endpoints.

AEP: `decision-blocker:guards` blocks `story:protocol-adapters`.

## UNMAPPED-ATOMICITY

Cross-record invalidation, code redemption, mapping contribution reconciliation and audit persistence need transactional behavior not captured by current single-entity transitions. Specify atomic storage boundaries and race tests before runtime acceptance.

AEP: `decision-blocker:epoch-atomicity` blocks `story:session-epochs`, `story:oauth-integration` and `story:directory-provenance`. STS owns code storage, consumption and credential creation; those changes and the audit outbox must commit atomically.

## UNMAPPED-BACKEND

Graph engine and policy engine selections remain open; choose behind adapter ports using tenancy, consistency and load acceptance evidence.

AEP: `decision-blocker:backend` blocks `story:graph-policy`.

## UNMAPPED-GLOBAL

Organization-independent external linking and platform-global resource audiences are deferred. The initial organization-bound records must not be treated as global trust.

AEP: `decision-blocker:global-trust` blocks `story:advanced-delegation`.


## UNMAPPED-DENIAL-AUDIT

ESS 0.25.0 refuses an error outcome that also emits an event. TokenExchangeDenied is typed, but a trusted audit boundary must durably record the denial separately from the rejected domain transaction; no credential/authority mutation is admitted. `decision-blocker:guards` also blocks `story:audit-client` until correlated denial audit and failure behavior are specified and tested.

## UNMAPPED-SUBJECT-RELATIONS

AuthoritySubject is a tagged PrincipalId-or-TeamId union. Relation and Grant require one subject; schemas reject missing, duplicated or unknown variants. The selected principal branch references one Principal; the team branch references one Team's members. These are conditional, non-owning relationships. ESS 0.25 relation carriers require a direct field and cannot select a union branch. Storage must enforce that conditional foreign key and tenant membership before graph admission.

AEP: `decision-blocker:subject-relations` blocks `story:graph-policy`.

## UNMAPPED-UNIQUENESS

Storage must atomically enforce ExternalPrincipal uniqueness by (organization, immutable configured connection issuer, external subject), and consistent organization/connection binding. Issuer is derived from the validated connection rather than duplicated or independently supplied. Changing issuer requires a new connection and explicit linking. Resource-server audiences are unique within an organization; allowed exchange source IDs resolve to registered, enabled records in the same verified organization. Ceilings have one current record per (agent, organization-or-platform); applicable platform and tenant ceilings intersect. Composite uniqueness is not implied by nominal IDs or plain JSON Schema validation.

AEP: `decision-blocker:identity-uniqueness` blocks `story:federation-linking`, `story:credential-profiles` and `story:agent-security`.

## UNMAPPED-ALGORITHM-POLICY

SigningAlgorithm is a nominal name. An explicitly admitted verifier-side algorithm/key policy must reject unconfigured names and token-header algorithm selection. The supplied sources do not settle the initial concrete allowlist, so no algorithm set is invented.

AEP: `decision-blocker:algorithm-policy` blocks `story:credential-profiles` and `story:federation-linking`.

## UNMAPPED-AUDIT-ROUTING and UNMAPPED-AUDIT-VOCABULARY

RecordAuditEvent provides a trusted worker append port and a redacted AuditRecord with subject/actor, optional unknown tenant on invalid-proof denial, source/issued credential identifiers and kinds, audiences/scopes, delegation/execution, decision/policy/model/graph correlation and result. Raw credentials and upstream secrets have no field. Named AuditAction/AuditOutcome are nominal strings; runtime must restrict them to an admitted action/result vocabulary. All domain-event mappings must be validated; the [routing map](audit-routing.md) records each required producer. Durable outbox delivery, deduplication, retention and failure behavior remain required adapter/storage work. No automatic event binding or persistence algorithm is fabricated.

AEP: `decision-blocker:audit-routing` blocks `story:audit-client` and `story:constrained-exchange`.

## UNMAPPED-ORCHESTRATION

The worker accepts the audit append command. Its later job scheduling, synchronization, cleanup, audit export, retry and transport behavior need explicit protocol/lifecycle decisions. Directory records and mutation ports remain control-plane-owned. The [ownership map](ownership.md) separates state ownership from invocation and does not invent worker lifecycle transitions.

AEP: `decision-blocker:worker-orchestration` blocks `story:directory-provenance` and `story:domain-runtime`.

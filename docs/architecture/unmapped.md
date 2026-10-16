# Unmapped semantics and linked blockers

These are required implementation decisions, not silently implemented behavior. Canonical Rust realization may include only accepted types; excluded semantics remain blocked.

## UNMAPPED-EPOCH

ESS has no unsigned primitive (0.25.0 when this was recorded, still none at 0.60.0). On 2026-09-18 the operator decided the generation is an ESS `Integer`, constrained `generation >= 0` and monotonic, declared on PrincipalSecurityEpoch, OrganizationSecurityEpoch and FederationSecurityEpoch as the recorded stand-in for the addendum's u64; widening to an unsigned type when ESS gains one is a compatible change. EpochSnapshotRef remains a handle.

`story:session-epochs` implemented the arithmetic outside the contract: `mandate-identity` realizes the three records and the snapshot, its generation refuses a negative value and refuses to advance past its maximum rather than wrapping, and `IncrementSecurityEpoch` advances one generation through the write port's compare-and-set. What stays open is the contract's half: the snapshot carries no generation, so a session's epochs are bound by the position its snapshot is recorded at (`mandate-identity` `IdentityLog`), not by a declared value.

AEP: `decision-blocker:epoch` blocks `story:epoch-snapshot-generations`.

## UNMAPPED-LIFECYCLE

On 2026-09-18 the operator decided immutable-with-status: nothing is destroyed; every lifecycle change is a new recorded state, and retention is redaction (`docs/adr/0009-event-sourced-persistence.md`). The 34 transitions the contract now declares are each moved by exactly one command; prohibitions are recorded in the contract where a mutation is refused (no execution expiry move, no approval reinstatement, no reactivation of a superseded policy or model, no deletion of an audit event). There is no UpdateFederationConnection: a changed connection is `disable` plus `RegisterFederationConnection`. The concrete audit retention floor is still owed.

AEP: `decision-blocker:lifecycle` blocks `story:audit-worker-delivery` and `story:graph-policy-adapter`.

## UNMAPPED-GUARDS

ESS command outcomes describe authoritative external validation, not executable cryptographic, graph or policy predicates. Add trusted context adapter, actual validation and negative conformance tests; generated command routes must never be exposed as product endpoints.

The 34 obligation clauses deferred on this blocker with no test, and the reason each is deferred, are listed on `decision-blocker:guards` itself. Two stories take them off it: `story:caller-authority-off-guards` the caller-authority clauses, and `story:credential-context-guards` the credential-derived context conditions of `Check`.

AEP: `decision-blocker:guards` blocks `story:protocol-adapters`, `story:audit-client` and `story:credential-context-guards`.

## UNMAPPED-ATOMICITY

Cross-record invalidation, code redemption, mapping contribution reconciliation and audit persistence need transactional behavior not captured by current single-entity transitions. Specify atomic storage boundaries and race tests before runtime acceptance.

The one transaction realized so far is the security-epoch increment, a compare-and-set on the expected stream version over a hand-written log; nothing in this repository runs it over the `eventlog` kit (UNMAPPED-RUNTIME below).

AEP: `decision-blocker:epoch-atomicity` blocks `story:oauth-integration`, `story:directory-provenance` and `story:domain-folds-over-the-kit`. STS owns code storage, consumption and credential creation; those changes and the audit outbox must commit atomically.

## UNMAPPED-BACKEND

Graph engine and policy engine selections remain open; choose behind adapter ports using tenancy, consistency and load acceptance evidence.

AEP: `decision-blocker:backend` blocks `story:graph-policy-adapter`.

## UNMAPPED-GLOBAL

Organization-independent external linking and platform-global resource audiences are deferred. The initial organization-bound records must not be treated as global trust.

AEP: `decision-blocker:global-trust` blocks `story:advanced-delegation`.


## UNMAPPED-DENIAL-AUDIT

ESS 0.25.0 refuses an error outcome that also emits an event. TokenExchangeDenied is typed, but a trusted audit boundary must durably record the denial separately from the rejected domain transaction; no credential/authority mutation is admitted. `decision-blocker:guards` also blocks `story:audit-client` until correlated denial audit and failure behavior are specified and tested.

## UNMAPPED-SUBJECT-RELATIONS

AuthoritySubject is a tagged PrincipalId-or-TeamId union. Relation and Grant require one subject; schemas reject missing, duplicated or unknown variants. The selected principal branch references one Principal; the team branch references one Team's members. These are conditional, non-owning relationships. ESS 0.25 relation carriers require a direct field and cannot select a union branch. Storage must enforce that conditional foreign key and tenant membership before graph admission.

AEP: `decision-blocker:subject-relations` blocks `story:graph-policy-adapter`.

## UNMAPPED-UNIQUENESS

Storage must atomically enforce ExternalPrincipal uniqueness by (organization, immutable configured connection issuer, external subject), and consistent organization/connection binding. Issuer is derived from the validated connection rather than duplicated or independently supplied. Changing issuer requires a new connection and explicit linking. Resource-server audiences are unique within an organization; allowed exchange source IDs resolve to registered, enabled records in the same verified organization. Ceilings have one current record per (agent, organization-or-platform); applicable platform and tenant ceilings intersect. Composite uniqueness is not implied by nominal IDs or plain JSON Schema validation.

The command path is decided: `decision-blocker:identity-uniqueness-ceiling` (2026-10-12) and `decision-blocker:identity-uniqueness` (2026-10-13) are cleared on the enforcement that ships, where a command refuses before it emits and the fold keeps a conflict view, so a race is recorded rather than resolved silently. Two current ceilings on one key are the declared denial `ExchangeCredential` names. Atomic enforcement in storage is still owed.

AEP: `decision-blocker:identity-uniqueness-storage` blocks `story:domain-folds-over-the-kit`.

## UNMAPPED-ALGORITHM-POLICY

SigningAlgorithm is a nominal name. An explicitly admitted verifier-side algorithm/key policy must reject unconfigured names and token-header algorithm selection.

Decided by the operator on 2026-09-18 and cleared: the admitted verifier-side algorithms are RS256 and ES256, and a name outside the list, an empty list, an algorithm selected from a token header and `none` are refused. `mandate-federation` realizes it as `verifier_real::AllowedAlgorithms`, with each connection's configured algorithm checked against it.

AEP: `decision-blocker:algorithm-policy` is cleared and blocks nothing open.

## UNMAPPED-AUDIT-ROUTING and UNMAPPED-AUDIT-VOCABULARY

RecordAuditEvent provides a trusted worker append port and a redacted AuditRecord with subject/actor, optional unknown tenant on invalid-proof denial, source/issued credential identifiers and kinds, audiences/scopes, delegation/execution, decision/policy/model/graph correlation and result. Raw credentials and upstream secrets have no field. Named AuditAction/AuditOutcome are nominal strings; runtime must restrict them to an admitted action/result vocabulary. All domain-event mappings must be validated; the [routing map](audit-routing.md) records each required producer. Durable outbox delivery, deduplication, retention and failure behavior remain required adapter/storage work. No automatic event binding or persistence algorithm is fabricated.

AEP: `decision-blocker:audit-routing` blocks `story:audit-client`, `story:constrained-exchange` and `story:audit-worker-delivery`.

## UNMAPPED-ORCHESTRATION

The worker accepts the audit append command. Its later job scheduling, synchronization, cleanup, audit export, retry and transport behavior need explicit protocol/lifecycle decisions. Directory records and mutation ports remain control-plane-owned. The [ownership map](ownership.md) separates state ownership from invocation and does not invent worker lifecycle transitions.

AEP: `decision-blocker:worker-orchestration` blocks `story:directory-provenance` and `story:audit-worker-delivery`.

## UNMAPPED-RUNTIME

`docs/adr/0009-event-sourced-persistence.md` was accepted on 2026-09-18 and is implemented by nothing.
The `eventlog` kit is pinned in the workspace manifest and named by two crates' manifests; no `.rs`
file in this repository references it. Every fold is hand-written and synchronous, and each substitute
was admitted one wave at a time — `docs/plans/2026-09-19-wave-c-execution.md:24`: *"the in-memory fake
is a test double with the kit's shape, ADR 0009: no second mechanism."*

One admission stands between the ADR and the code, and it has never been taken: the kit's `EventStore`
is an async trait (`eventlog-core/src/lib.rs:59` at `0.3.0`), every `eventlog-sqlite` entry point is
`pub async fn` including `SqliteEventStore::in_memory` (`:118`), and neither `Cargo.toml` nor
`dependency-boundaries.json` admits `tokio`. Recorded as stop condition S1 on 2026-09-18
(`docs/plans/2026-09-18-wave-3-execution.md:13`), deferred to "the next dispatch", and still open four
waves later. A version bump does not resolve it: `0.3.0` is async exactly as `0.2.1` is.

The ADR's own argument for believing a test proves a deployment property is the kit's in-memory
backend — *"The kit's SQLite backend is `:memory:`-capable, which is why a property proved in a test is
proved for the deployment"* — and that is the argument the hand-written doubles do not carry.

AEP: `decision-blocker:async-runtime` blocks `story:domain-folds-over-the-kit`.
`story:eventlog-repin-0-3-0` is the pin, and is hygiene rather than wiring.

# Runtime decision dossier

Eleven open runtime decision blockers, one row each. Every row carries a source-cited decision question, bounded alternatives, a proposed owner, the affected stories read from the planning store, and the exact evidence required to clear it. An independent reviewer should be able to take one row, follow its citations, and hold the decision conversation without reading the rest of this file.

## What this document does not do

It clears nothing. No blocker is moved, no algorithm is selected, no backend is selected, no ESS meaning is changed and no runtime test is claimed here. Every owner and every alternative marked as recommended below is a **proposal** for an authorized owner to accept, amend or reject; recording a proposal is not approval. `decision-blocker:global-trust` remains deferred by decision and is present as a row, not as a resolution.

A decision may remain unanswered and this dossier still be complete. Completeness here means the question, its bounds, its proposed owner, its blast radius and its exit evidence are all written down and checkable. Where a question has a sub-question the permitted sources do not settle, the row says so in place rather than inventing an answer. What cannot remain unanswered is clearance: downstream runtime work cannot start until its own decision is recorded and cleared by an authorized owner.

## How the matrix was derived

The blocker set and the affected-stories column come from `aep plan artifact blocked`, run against the planning store, not from the `AEP:` lines in [unmapped semantics](unmapped.md). The register is a prose companion to the store; the store is authoritative for which stories a blocker holds. The command returned thirteen blocker groups: these eleven runtime rows, plus two Drive execution-tooling blockers recorded as excluded below.

## Where the register disagrees with the store

Four of the eleven rows name fewer stories in `unmapped.md` than the store holds, and one names the same set across two separate sections rather than on its `AEP:` line. The register is not wrong about the semantics in any of these cases; it is behind on edges added after it was written. Nothing in this document is built from those lines.

| Row | Register `AEP:` line | Store adds |
|---|---|---|
| `decision-blocker:lifecycle` | `unmapped.md:15` names `story:domain-runtime` | `story:audit-worker-delivery` |
| `decision-blocker:identity-uniqueness` | `unmapped.md:56` names three stories | `story:agent-authority-kernel` |
| `decision-blocker:audit-routing` | `unmapped.md:68` names two stories | `story:audit-worker-delivery` |
| `decision-blocker:worker-orchestration` | `unmapped.md:74` names two stories | `story:audit-worker-delivery` |
| `decision-blocker:guards` | `unmapped.md:21` names `story:protocol-adapters` only; `story:audit-client` appears at `unmapped.md:44` under UNMAPPED-DENIAL-AUDIT | nothing — the register is complete but split across two sections |

Correcting the register is not this story's change and was not made here.

## Proposed owners are roles, not people

No source this document may cite names an individual for any of these decisions, so every proposed owner below is a role or boundary taken from the [ownership map](ownership.md), citing the line that assigns it — **with two exceptions, which cite no ownership line because none exists**. Row 6's decision is a trust question the ownership map does not assign to any library or deployment, and the key-provider half of row 9 falls outside the map's whole assignment surface — its domain table (`ownership.md:5-18`) and the four cross-domain libraries (`ownership.md:20`) — while `combined.md:67` lists the key provider among the items still needing a reviewed decision, which is not the same as naming its owner. Both exceptions say so in place, marked *no ownership-map owner exists*. The rule is enforced mechanically rather than by this sentence; see *Claims this document makes about itself*. Converting a role to a named person is the coordinator's or the operator's act, not this document's; inventing an owner where the map assigns none would be worse than recording the gap.

## Index

| # | Blocker | Marker | Affected stories (store) |
|---|---|---|---|
| 1 | `decision-blocker:epoch` | UNMAPPED-EPOCH | `story:session-epochs` |
| 2 | `decision-blocker:lifecycle` | UNMAPPED-LIFECYCLE | `story:audit-worker-delivery`, `story:domain-runtime` |
| 3 | `decision-blocker:guards` | UNMAPPED-GUARDS, UNMAPPED-DENIAL-AUDIT | `story:audit-client`, `story:protocol-adapters` |
| 4 | `decision-blocker:epoch-atomicity` | UNMAPPED-ATOMICITY | `story:directory-provenance`, `story:oauth-integration`, `story:session-epochs` |
| 5 | `decision-blocker:backend` | UNMAPPED-BACKEND | `story:graph-policy` |
| 6 | `decision-blocker:global-trust` | UNMAPPED-GLOBAL | `story:advanced-delegation` |
| 7 | `decision-blocker:subject-relations` | UNMAPPED-SUBJECT-RELATIONS | `story:graph-policy` |
| 8 | `decision-blocker:identity-uniqueness` | UNMAPPED-UNIQUENESS | `story:agent-authority-kernel`, `story:agent-security`, `story:credential-profiles`, `story:federation-linking` |
| 9 | `decision-blocker:algorithm-policy` | UNMAPPED-ALGORITHM-POLICY | `story:credential-profiles`, `story:federation-linking` |
| 10 | `decision-blocker:audit-routing` | UNMAPPED-AUDIT-ROUTING, UNMAPPED-AUDIT-VOCABULARY | `story:audit-client`, `story:audit-worker-delivery`, `story:constrained-exchange` |
| 11 | `decision-blocker:worker-orchestration` | UNMAPPED-ORCHESTRATION | `story:audit-worker-delivery`, `story:directory-provenance`, `story:domain-runtime` |

## 1. `decision-blocker:epoch` — epoch representation and arithmetic

**Decision question.** What exact representation carries a security generation value, and what happens when it reaches its maximum? ESS 0.25.0 has no exact unsigned 64-bit generation with monotonic increment, overflow denial and atomic comparison, so `PrincipalSecurityEpoch`, `OrganizationSecurityEpoch` and `FederationSecurityEpoch` declare ownership while their numeric values stay absent (`unmapped.md:7`; `../../systems/mandate/domains/identity.yaml:1`). `EpochSnapshotRef` is an immutable record handle only and is never a generation number (`unmapped.md:7`; `combined.md:47`). The addendum's suggested model is three `u64` fields (`../sources/architecture-addendum.md:417`), and `IncrementSecurityEpoch` already declares a denial when "the exact unsigned generation is at its maximum, or atomic increment cannot commit" (`command-obligations.md:36`) — so the exhaustion behaviour is declared and the representation that would make it checkable is not.

**Bounded alternatives.**

1. Keep the exact unsigned generation outside ESS in the storage schema, with ESS carrying only the record handle until an exact unsigned scalar exists. Extends today's position.
2. Admit the exact unsigned generation into ESS once ESS can express it, with `IncrementSecurityEpoch` the only mutation path.
3. Use an opaque monotonic token compared for equality only. This satisfies the mismatch-rejects invariant (`../sources/architecture-addendum.md:976`) but gives up ordering, which the "monotonically increasing" requirement at `../sources/architecture-addendum.md:393` assumes.

On the exhaustion half, the two bounded options are to deny the increment and require an out-of-band reset procedure (the shape already declared at `command-obligations.md:36`), or to widen the representation before exhaustion is reachable.

Out of bounds, not alternatives: approximating the value with `Integer`, `String` or `UUID` (`unmapped.md:7`); wrapping or resetting on overflow (`combined.md:47`); inventing a lifecycle self-loop to stand in for numeric mutation (`unmapped.md:7`).

**Proposed owner.** The `mandate.identity` contract owner — `mandate-identity` and `mandate-model` in the control plane — with STS as the consuming reviewer, since STS consumes validated session and epoch information rather than owning it (`ownership.md:8`). Whether a representation is expressible at all is an ESS-version question and belongs to the owner of `systems/mandate`.

**Affected stories (store).** `story:session-epochs`.

**Exact evidence required to clear.**

- A recorded representation decision naming the exact type, its bound and the ESS version in which it is expressible, attached to this blocker.
- Cases showing increment is monotonic, and that comparison denies when any applicable dimension mismatches (`combined.md:47`).
- A case showing increment at the maximum denies rather than wraps (`command-obligations.md:36`; `combined.md:47`).
- A case showing an increment in organization A does not invalidate unrelated organization B sessions, except a deliberate global principal reset (`combined.md:47`).
- Atomicity evidence does **not** clear this row; it belongs to row 4. A clearance record showing only that the increment committed atomically leaves this question open.

## 2. `decision-blocker:lifecycle` — lifecycle and retention

**Decision question.** For each recorded entity class, what are the deletion, reactivation, retention, execution-completion and mapping-transaction semantics? Recorded entity lifecycles are immutable snapshots, and the source documents settle none of these (`unmapped.md:13`). `Recorded` is an immutable observed record, not an invented product lifecycle, and no runtime implementor may infer deletion, expiry transitions or reactivation from it (`combined.md:19`). The original design requires a deliberate decision about whether a disabled user remains in historical audit relationships, and states that audit data should not be destroyed merely because an account is deprovisioned (`../sources/original-design.md:3053`). Retention is tenant-specific in the tamper-resistance list (`../sources/original-design.md:1771`). One concrete instance is already parked on this blocker: the federation connection update command and its trust-change semantics (`audit-routing.md:12`).

**Bounded alternatives.**

1. Immutable-with-status: no destructive delete anywhere; every lifecycle change is a new recorded state, plus a generation advance where the change is security-relevant. Closest to the addendum's preference for explicit security-sensitive deletes over broad cascade (`../sources/architecture-addendum.md:867`).
2. Explicit scoped delete commands per record class, each naming its own cascade, with audit retained on an independent schedule (`../sources/original-design.md:3055`).
3. Retention-tiered: domain records follow (1), audit records follow a separate tenant-configurable retention policy (`../sources/original-design.md:1690`, `:1771`).

Out of bounds: inferring any transition from `Recorded` (`combined.md:19`); relying on broad database cascade as the mechanism (`../sources/architecture-addendum.md:869`); destroying audit history as a side effect of deprovisioning (`../sources/original-design.md:3055`).

**Proposed owner.** Joint, and it cannot be split: the control-plane owner of `mandate-model` record lifecycles (`ownership.md:8`, `:9`, `:10`) together with the `mandate-audit` retention owner (`ownership.md:18`). The domain owner cannot decide the audit-retention half alone, because the constraint that audit survives deprovisioning is what bounds the domain answer.

**Affected stories (store).** `story:audit-worker-delivery`, `story:domain-runtime`. The register names only the second (`unmapped.md:15`).

**Exact evidence required to clear.**

- A per-class lifecycle table covering at least: principal and membership disablement, federation connection change and disable, external principal unlink, directory mapping retraction, execution completion, and audit retention — each naming its allowed transitions and whether any is destructive.
- The retention decision, naming who configures it and what the floor is for audit records (`../sources/original-design.md:1771`).
- A case showing a deprovisioned account leaves audit history intact (`../sources/original-design.md:3055`).
- A case showing removal of one mapping retracts only that mapping's contributions, with manual and overlapping mapping contributions surviving and the team not deleted (`combined.md:29`; `command-obligations.md:22`).
- A recorded answer for the federation connection update and trust-change semantics currently parked here (`audit-routing.md:12`).
- This row constrains rows 7 and 10. Clearing it with a retention or deletion answer that contradicts either is not a clearance.

## 3. `decision-blocker:guards` — guards and denial audit

**Decision question.** Two coupled questions on one blocker, because it carries two markers. First: where is the trusted context adapter boundary, and what does it validate before each domain command, given that ESS command outcomes describe authoritative external validation and are not executable cryptographic, graph or policy predicates (`unmapped.md:19`)? Context must be constructed only from validated credentials by a trusted adapter before application decoding, and `organization`, `subject`, `actor` and `audience` selectors cannot establish authority (`combined.md:51`; `command-obligations.md:3`). Second: how is a denial durably recorded when the domain transaction is rejected? ESS 0.25.0 refuses an error outcome that also emits an event, so a trusted audit boundary must record the denial separately from the rejected transaction, admitting no credential or authority mutation (`unmapped.md:44`). Nothing may silently become an allow (`../sources/original-design.md:206`).

**Bounded alternatives.** For the denial-record half:

1. Out-of-band append: the adapter writes the denial through `mandate.audit.RecordAuditEvent` on the rejection path, outside the refused domain transaction. The literal shape the register describes (`unmapped.md:44`).
2. Two-phase: the adapter records an intent before invoking the command and finalizes the outcome after, so allow and deny share one path.
3. Structured transport error plus a later reconciliation job. Bounded but weak: tracing logs are explicitly not a substitute for durable security audit records (`../sources/original-design.md:1680`), so this option only survives if the reconciliation store is itself durable audit.

Out of bounds: an ESS error outcome that also emits an event (`unmapped.md:44`); any credential or authority mutation on the denial path (`unmapped.md:44`); exposing generated command routes as product endpoints (`unmapped.md:19`).

**Proposed owner.** The shared transport and authentication adapter owner, `mandate-server` (`ownership.md:20`), with `mandate-audit` (`ownership.md:18`) co-owning the denial-record half. `ownership.md:20` also states the server adapter does not acquire PDP or token-issuance authority; proposing it as the guard owner does not grant it either.

**Affected stories (store).** `story:audit-client`, `story:protocol-adapters`.

**Exact evidence required to clear.**

- A written adapter contract naming, for every one of the 34 commands in `command-obligations.md:7-40`, which party establishes each declared precondition. A sample is not evidence; the table is the enumeration.
- A negative conformance case per command deny clause (`unmapped.md:19` requires negative conformance tests, and the obligations table is what they are against).
- A case showing a caller-supplied `organization`, `subject`, `actor` or `audience` selector is stripped and cannot establish authority (`combined.md:51`).
- A case showing `TokenExchangeDenied` produces a durable audit record while the domain transaction is rejected and no credential is issued (`unmapped.md:44`; `audit-routing.md:26`).
- Evidence that generated command routes are not reachable as product endpoints (`unmapped.md:19`).

## 4. `decision-blocker:epoch-atomicity` — transaction boundaries

**Decision question.** What are the exact atomic storage boundaries for cross-record invalidation, code redemption, mapping contribution reconciliation and audit persistence, none of which is captured by current single-entity transitions (`unmapped.md:25`)? STS owns code storage, consumption and credential creation, and those changes plus the audit outbox must commit atomically (`unmapped.md:27`). `RedeemAuthorizationCode` consumes the STS-owned code and creates the bounded credential and durable audit outbox in one transaction; a failed or replayed transaction must not issue a credential (`ownership.md:28`; `command-obligations.md:15`). The choice of consistency class for reads after a security-sensitive mutation is part of the same question (`../sources/original-design.md:1617`).

**Bounded alternatives.**

1. One relational transaction per boundary with the audit outbox as a row in the same database — the shape the addendum's table implies by listing `audit_events` alongside the domain tables (`../sources/architecture-addendum.md:851`).
2. A storage-level atomic primitive (compare-and-set on the code record) plus a separately durable audit write, with a reconciliation invariant that detects and repairs a split.
3. Distributed coordination across the STS store and a separate audit store.

Out of bounds: an asynchronous event binding as the one-use redemption mechanism — it would not establish one-use redemption, so none is invented (`ownership.md:30`).

**Proposed owner.** Joint: the STS deployment owner for the credential and code half (`ownership.md:15`, `:24-30`), and the control-plane directory owner for the mapping-contribution half (`ownership.md:10`). One blocker spans three stories owned across two deployments; a decision recorded by one of them alone does not bind the other.

**Affected stories (store).** `story:directory-provenance`, `story:oauth-integration`, `story:session-epochs`.

**Exact evidence required to clear.**

- A named boundary for each transaction listed at `unmapped.md:25`, each with its isolation level and its stated failure mode on partial commit.
- A race case showing concurrent redemption of one code issues at most one credential (`ownership.md:28`; `command-obligations.md:15`).
- A race case showing a concurrent increment and refresh cannot observe a stale generation as valid (`command-obligations.md:37`).
- A race case showing concurrent mapping retraction preserves every other valid manual and mapping contribution (`command-obligations.md:23`).
- A case showing a rolled-back domain transaction leaves no issued credential and no partially written audit record.
- The consistency class chosen for reads after revocation, recorded with the boundary decision (`../sources/original-design.md:1629`, `:1633`).

## 5. `decision-blocker:backend` — graph and policy backend

**Decision question.** Which graph engine and which policy engine are selected behind the `mandate-graph` and `mandate-policy` adapter ports, and on what tenancy, consistency and load acceptance evidence (`unmapped.md:31`; `ownership.md:11`, `:12`)? The original design enumerates the graph candidates and requires they stay behind `mandate-graph` (`../sources/original-design.md:2367`). PostgreSQL being the initial storage direction is explicitly not an authorization-engine selection (`combined.md:67`).

**Bounded alternatives.** Both halves are enumerated by the source, and its own open-questions section splits them exactly as this row does (`../sources/original-design.md:3353`, `:3357`, `:3364`).

The graph half (`../sources/original-design.md:2372-2374`, restated as an open question at `:3359`):

1. SpiceDB.
2. OpenFGA.
3. A PostgreSQL adapter for the initial bounded model.

The policy half (`../sources/original-design.md:3366-3368`):

1. A simple internal condition language.
2. Cedar, which the design carries as its policy-language reference (`../sources/original-design.md:740`).
3. Another engine. The design names Open Policy Agent as its general policy-engine reference (`../sources/original-design.md:742`) without proposing it, so this branch is a real option and not a placeholder.

**This document selects none of these six and recommends none.** The selection is an approval, not a proposal, and it is prohibited here.

The policy half carries one further question the same section asks and this document does not answer: how resource attributes are trusted and distributed (`../sources/original-design.md:3369`). That bears directly on the choice, because authorization-critical attributes must arrive as signed or trusted context, or be materialized into a policy data plane, rather than being fetched from the resource database during a check (`../sources/original-design.md:738`).

Out of bounds: building a globally distributed Zanzibar database before the product requires it (`../sources/original-design.md:259`); reading `combined.md:67` as having already chosen an engine.

**Proposed owner.** The `mandate-graph` and `mandate-policy` owner in the Authorization deployment, where concrete storage remains an adapter (`ownership.md:11`, `:12`).

**Affected stories (store).** `story:graph-policy`.

**Exact evidence required to clear.**

- Tenancy evidence: cross-tenant isolation cases against the candidate, not against the port.
- Consistency evidence: that the candidate's consistency token or revision survives Mandate's own API rather than being discarded (`../sources/original-design.md:1633`), and that it supports the strong/security-sensitive class used after revocation (`../sources/original-design.md:1629`).
- Load acceptance evidence against a stated decision-latency target. The sources name decision latency as a metric to observe (`../sources/original-design.md:2900`) but set no value for it, so the clearance record must state one before the evidence means anything.
- Fail-closed evidence: when the graph cannot produce a trustworthy answer, protected operations deny (`../sources/original-design.md:2967`).
- For the policy half specifically, the recorded answer to resource-attribute trust and distribution (`../sources/original-design.md:3369`, `:738`). An engine selected without it is selected against unknown inputs.
- A recorded selection approved by an authorized owner, naming the approver.

## 6. `decision-blocker:global-trust` — deferred global trust

**Decision question.** When, if ever, are organization-independent external linking and platform-global resource audiences admitted, and what would reopen the deferral? Both are deferred, and the initial organization-bound records must not be treated as global trust (`unmapped.md:37`). Global trust and linking is deferred (`combined.md:33`); initial audience registration is organization-local and global audiences require a separate trust decision (`combined.md:39`).

**This row records a deferral and is not a resolution.** It stays deferred. The alternatives below bound the shape of the deferral, not a choice to be made now.

**Bounded alternatives.**

1. Remain deferred for this milestone. This is the recorded position and the one this document reflects.
2. Reopen with a single trust decision covering both halves — linking and audiences — together.
3. Reopen one half only. Admissible as a distinct option because the two halves are deferred by separate statements (`combined.md:33` for linking, `combined.md:39` for audiences) and nothing ties their timing.

Out of bounds: treating any existing organization-bound record as global (`unmapped.md:37`); widening implicitly through audience registration, since audience selection requests a restriction and not authority (`combined.md:39`).

**Proposed owner.** **No ownership-map owner exists for this row.** The [ownership map](ownership.md) assigns libraries and deployments to ESS domains; a deferral on organization-independent trust is not one of those domains, and no source this document may cite names a platform trust authority as a role or a person. The nearest thing to an owner is the review that carries the question — `story:advanced-delegation`, "Review advanced delegation and global trust options" — but the store records no owner for it, so that is a pointer to where the conversation happens, not an assignment. Identifying the owner is outside what this document can establish.

**Affected stories (store).** `story:advanced-delegation`.

**Exact evidence required to clear.** This row is not expected to clear in this milestone, and its remaining open is not an incompleteness in this dossier. Keeping it deferred requires the negative property that no implementation admits a non-organization-bound link or audience — a check over the graph and credential surfaces, not a document. If it is ever reopened, clearance requires a recorded trust decision stating the boundary, plus cases showing an organization-bound record never satisfies a global audience check.

## 7. `decision-blocker:subject-relations` — conditional subject references

**Decision question.** How does storage enforce the exactly-one, non-owning conditional foreign key for `AuthoritySubject`, and tenant membership, before graph admission? `AuthoritySubject` is a tagged `PrincipalId`-or-`TeamId` union; relation and grant require one subject, and schemas reject missing, duplicated or unknown variants (`unmapped.md:48`; `../../systems/mandate/domains/graph.yaml:1`; `../../systems/mandate/domains/core.yaml:325`). ESS 0.25 relation carriers require a direct field and cannot select a union branch, so the constraint cannot live in the contract (`unmapped.md:48`; `combined.md:25`). `WriteRelationship` already declares the denial when the chosen subject is unresolved or outside tenant membership (`command-obligations.md:34`). Teams are graph subjects and resource services never expand them (`../sources/original-design.md:582`, `:597`).

**Bounded alternatives.**

1. Two nullable identifier columns with a database check constraint enforcing exactly one, each with its own foreign key.
2. One discriminator column plus one identifier column, with the branch-correct referential check enforced by a constraint or trigger rather than by application code alone.
3. Separate tables per branch with a union view over them.

Out of bounds: representing the union as a plain identifier with the branch implied (`combined.md:25`); letting the resource service expand teams (`../sources/original-design.md:597`); treating JSON Schema variant validation as the storage constraint (`unmapped.md:48` requires storage to enforce it).

**Proposed owner.** The `mandate-graph` owner together with the concrete storage adapter owner, since storage remains an adapter under that port (`ownership.md:11`).

**Affected stories (store).** `story:graph-policy`.

**Exact evidence required to clear.**

- A schema statement showing exactly-one is enforced by the storage engine, not only by application code.
- Negative cases: a zero-branch write, a two-branch write and an unknown-variant write are each rejected (`unmapped.md:48`).
- A case showing a subject outside tenant membership is rejected before graph admission (`command-obligations.md:34`; `unmapped.md:48`).
- Evidence the reference is non-owning: removing the referenced principal or team does not silently delete the relation or grant. This answer depends on row 2 — decide lifecycle first, or the two rows will be cleared with contradictory cascade semantics.

## 8. `decision-blocker:identity-uniqueness` — composite uniqueness

**Decision question.** Which composite uniqueness constraints does storage enforce atomically, and on exactly which key columns? Storage must enforce `ExternalPrincipal` uniqueness by (organization, immutable configured connection issuer, external subject) with the issuer derived from the validated connection rather than supplied; resource-server audiences unique within an organization; allowed exchange source identifiers resolving to registered, enabled records in the same verified organization; and one current ceiling record per (agent, organization-or-platform). Composite uniqueness is not implied by nominal IDs or plain JSON Schema validation (`unmapped.md:54`). The addendum names the recommended constraints directly (`../sources/architecture-addendum.md:859-862`). Email equality never authorizes linking, and same email is not same principal (`command-obligations.md:28`; `../sources/architecture-addendum.md:941`; `combined.md:33`).

**Bounded alternatives.**

1. Database unique indexes on the exact composite keys recommended at `../sources/architecture-addendum.md:859-862`, with the issuer column populated from the validated connection rather than from caller input.
2. Application-level uniqueness behind a serialized critical section.
3. Hybrid: unique index for enforcement plus an explicit conflict-detection path that returns the already-declared denial rather than a raw constraint error (`command-obligations.md:28`).

Out of bounds: nominal ID uniqueness or JSON Schema as the enforcement mechanism (`unmapped.md:54`); a subject-only or email-derived key (`combined.md:33`); changing an issuer in place — that requires a new connection and explicit linking (`unmapped.md:54`).

**Unsettled sub-question, stated rather than invented.** The ceiling key is "(agent, organization-or-platform)" (`unmapped.md:54`). How the platform scope is represented in a column whose other values are organization identifiers is not stated in any source this document may cite. This may stay unanswered without the dossier being incomplete. It may not stay unanswered at clearance.

**Proposed owner.** The concrete storage adapter owner, which the map places under the graph port rather than giving it a row of its own (`ownership.md:11`), with `mandate-federation` for the external-principal key (`ownership.md:14`) and `mandate-token` with the credential registry for the audience and exchange-source keys (`ownership.md:15`). The ceiling half belongs to `mandate-authz` and the delegation domain (`ownership.md:16`).

**Affected stories (store).** `story:agent-authority-kernel`, `story:agent-security`, `story:credential-profiles`, `story:federation-linking`. The register names three (`unmapped.md:56`); `story:agent-authority-kernel` is store-only.

**Exact evidence required to clear.**

- The exact constraint definition, or its storage-engine equivalent, for each named key.
- A concurrency case showing two simultaneous links with the same (organization, issuer, subject) produce one record and one declared denial (`command-obligations.md:28`).
- A case showing a changed issuer requires a new connection and explicit linking rather than an in-place update (`unmapped.md:54`).
- A case showing two organizations may register the same audience string and stay isolated — the constraint is unique *within* an organization (`unmapped.md:54`; `../sources/architecture-addendum.md:860`).
- A case showing an allowed exchange source outside the verified organization is unresolved and denies (`command-obligations.md:16`).
- A recorded answer for the ceiling key's platform representation.

## 9. `decision-blocker:algorithm-policy` — verifier-side algorithm and key policy

**Decision question.** What is the verifier-side algorithm and key policy — which algorithm names are admitted, where is the allowlist configured, and how does it rotate? `SigningAlgorithm` is a nominal name, and an explicitly admitted verifier-side policy must reject unconfigured names and token-header algorithm selection; the supplied sources do not settle the initial concrete allowlist, so no algorithm set is invented (`unmapped.md:60`; `../../systems/mandate/domains/credential.yaml:2`). Verification must check an alg allowlist alongside signature, issuer, audience, expiry, not-before, token type, sender constraint and tenant consistency, and algorithms must never be selected solely from untrusted token headers (`../sources/original-design.md:2516-2524`, `:2527`). Signing keys require stable `kid`, overlapping rotation, published JWKS and an emergency revocation procedure (`../sources/original-design.md:2499`).

**Bounded alternatives — the shape of the policy, since no algorithm set may be proposed here.**

1. A single fixed allowlist compiled into the verifier, changed only by release.
2. A deployment-configured allowlist validated at startup, rejecting unknown names and rejecting an empty set.
3. A per-profile allowlist, making the algorithm a field of the named credential profile that already chooses format, maximum TTL, required online authorization and revocation guarantee (`combined.md:41`).

**No admitted algorithm is proposed anywhere in this document, and proposing one is prohibited to it** (`unmapped.md:60`). Exactly one algorithm name appears below — `none`, in the clearance evidence — and it appears solely as something the policy must reject, which is the opposite of admitting it. The shape options above are proposals for an owner to choose among, not a selection.

Out of bounds: selecting the algorithm from the token header (`../sources/original-design.md:2527`); treating a nominal `SigningAlgorithm` value as admitted because it validates against the schema (`unmapped.md:60`).

**Proposed owner.** The allowlist half belongs to the `mandate-token` owner in the STS deployment, which alone issues, resolves, exchanges and revokes credentials (`ownership.md:15`). For the `kid`, rotation and emergency-revocation half, **no ownership-map owner exists**: the map assigns through its domain table (`ownership.md:5-18`) and its four cross-domain libraries (`ownership.md:20`), and key material appears in neither. `combined.md:67` lists the key provider among the items that still need a reviewed decision — which records that the decision is open, not who owns it — and `../sources/original-design.md:2499-2509` states that half's requirements without assigning them to anyone. Naming an owner for it here would be inventing one.

**Affected stories (store).** `story:credential-profiles`, `story:federation-linking`.

**Exact evidence required to clear.**

- A recorded allowlist approved by an authorized owner, naming the approving authority. The list is the decision; this document holds none.
- A case showing an unconfigured algorithm name is rejected at issuance and again at validation.
- A case showing a token whose header names an algorithm outside the policy is rejected regardless of signature validity, and that `none` is rejected (`../sources/original-design.md:2527`).
- A case per item in the verification list at `../sources/original-design.md:2516-2524`, not signature alone.
- Rotation evidence: overlapping `kid` acceptance across a rotation window, and an exercised emergency revocation path (`../sources/original-design.md:2505-2507`).
- Evidence that no production private key appears in source or config (`../sources/original-design.md:2509`).

## 10. `decision-blocker:audit-routing` — audit routing and vocabulary

**Decision question.** Two questions on one blocker, because it carries both markers. First, vocabulary: what is the admitted `AuditAction` and `AuditOutcome` set, and what is the producer-to-record transformation for each category? Named `AuditAction` and `AuditOutcome` are nominal strings and runtime must restrict them to an admitted vocabulary; the complete vocabulary and the transformations must be specified and checked before implementing the boundary, because nominal strings do not enforce it (`unmapped.md:66`; `audit-routing.md:28`; `../../systems/mandate/domains/audit.yaml:3`). Second, delivery: what are the durable outbox delivery, deduplication, retention and failure semantics? These remain required adapter and storage work, and a source notification is not itself proof of durable audit persistence (`unmapped.md:66`; `audit-routing.md:5`). `RecordAuditEvent` already declares the denial when action or result is unadmitted, the payload carries secret material, or durable append validation fails (`command-obligations.md:7`). Durability, retention, tamper resistance and export are explicit later gates, not implied by a typed event (`combined.md:65`).

**Bounded alternatives.** Delivery:

1. Transactional outbox in the producer's own database, drained by the worker — consistent with the single-transaction redemption boundary (`ownership.md:28`) and with `audit_events` sitting among the domain tables (`../sources/architecture-addendum.md:851`).
2. Synchronous append to the worker port on the producer's critical path, failing the domain transaction when the append fails.
3. Broker-backed at-least-once delivery with deduplication on a producer-assigned idempotency key.

Vocabulary:

1. A closed enumeration checked mechanically at the append port and versioned with the contract.
2. An open namespace with a registered-prefix rule and a checked registry.

Out of bounds: tracing logs as the audit record (`../sources/original-design.md:1680`); treating a dedicated audit notification without a source mutation port as delivered audit (`audit-routing.md:5`); accepting arbitrary action or outcome text because the type is a nominal string (`../../systems/mandate/domains/audit.yaml:3`).

**Proposed owner.** The `mandate-audit` owner in the worker deployment for the port, the vocabulary and the delivery policy (`ownership.md:18`), with each producer domain owner accountable for its own rows in the routing table (`audit-routing.md:9-26`). The vocabulary cannot be owned per-producer; the admission check is one list at one boundary.

**Affected stories (store).** `story:audit-client`, `story:audit-worker-delivery`, `story:constrained-exchange`. The register names two (`unmapped.md:68`); `story:audit-worker-delivery` is store-only.

**Exact evidence required to clear.**

- The admitted vocabulary, enumerated, **with a mechanical check that every action and outcome any producer can emit is a member**. A hand-maintained list that only review can extend is not evidence: the check is the deliverable, and a missing entry is its symptom.
- A mapping from each of the 18 categories at `audit-routing.md:9-26` to its producing command and its resulting record fields, with the additional original-design events named at `audit-routing.md:28` either mapped or explicitly recorded as outside the first set.
- Redaction cases: no raw credential and no upstream secret appears in any field, including free-text ones (`audit-routing.md:30`; `../sources/architecture-addendum.md:925`; `command-obligations.md:7`).
- Delivery cases: a duplicated delivery produces exactly one record; an append failure has a stated and tested consequence for the domain transaction (`command-obligations.md:7`).
- A case showing exchange records carry subject, actor, verified organization when known, source and issued credential identifiers and kinds, audiences, scope, delegation, execution, result and decision correlation, and that optional fields are not used to drop known decision evidence (`audit-routing.md:30`).
- The retention and tamper-resistance answers (`combined.md:65`; `../sources/original-design.md:1763`). These overlap row 2; the two rows must not be cleared with contradictory retention answers.

## 11. `decision-blocker:worker-orchestration` — worker orchestration

**Decision question.** What are the worker's job scheduling, synchronization, cleanup, audit export, retry and transport protocols, given that its only declared ingress is the trusted audit append port (`unmapped.md:72`; `ownership.md:34`)? Directory records and mutation ports remain control-plane-owned, and invoking them from a worker does not transfer state ownership; no lifecycle or queue protocol is inferred from the word "worker" (`unmapped.md:72`; `ownership.md:34`; `combined.md:21`). The worker handles asynchronous audit and export, cleanup and synchronization orchestration without minting credentials (`combined.md:15`). The asynchronous work list is enumerated in the original design (`../sources/original-design.md:2324`). One producer is already parked here: the directory group creation producer (`audit-routing.md:15`).

**Bounded alternatives.**

1. A database-backed queue in the existing relational store, polled by the worker. No new infrastructure, and it composes with alternative 1 of row 10.
2. An external broker with explicit delivery semantics.
3. Scheduler-driven periodic batch with no per-item queue, for the items in `../sources/original-design.md:2329-2335` that are genuinely periodic.

These are not mutually exclusive across items; a defensible answer may pick differently per item, provided each item's choice is recorded.

Out of bounds: inferring a lifecycle or queue protocol from the deployment's name (`ownership.md:34`); moving directory state ownership to the worker (`ownership.md:34`; `combined.md:15`); the worker minting credentials (`combined.md:15`).

**Proposed owner.** The worker deployment owner (`ownership.md:18`, `:32-34`), with the control-plane directory owner retaining state ownership for everything the worker invokes (`ownership.md:10`).

**Affected stories (store).** `story:audit-worker-delivery`, `story:directory-provenance`, `story:domain-runtime`. The register names two (`unmapped.md:74`); `story:audit-worker-delivery` is store-only.

**Exact evidence required to clear.**

- A written protocol for each item enumerated at `../sources/original-design.md:2329-2335`, each with its retry policy, its at-least-once or at-most-once guarantee, and its failure destination.
- A case showing the worker holds no directory state ownership: a mutation it triggers still routes through the control-plane command (`ownership.md:34`).
- A case showing the worker mints no credential (`combined.md:15`).
- A retry case showing a redelivered job does not double-apply a membership contribution (`command-obligations.md:24`).
- A recorded producer for `directory_group.created` (`audit-routing.md:15`).
- Row 10's delivery decision constrains this row. A transport answer here that contradicts the audit outbox answer there is not a clearance of either.

## Excluded: execution tooling, not runtime decisions

Two further open `decision-blocker` artifacts exist in the planning store and are **deliberately not rows above**. They block `task:canonical-types-drive`, which is execution tooling for a governed Drive run, not runtime behaviour of the platform. They are recorded here so a reviewer who counts thirteen blockers in the store and eleven rows in this dossier can see that the difference is intentional.

| Blocker | Title | Blocks |
|---|---|---|
| `decision-blocker:drive-verifier` | Mandate property evidence verifier is required before Drive launch | `task:canonical-types-drive` |
| `decision-blocker:drive-map-authority` | Reconcile driver artifact-write prompts with denied planning scope | `task:canonical-types-drive` |

Neither is resolved, argued or given a recommendation here. Wave and Drive have separate lifecycle owners, and Drive must not be launched without a reviewed task and operator-supplied budget and assumed cost; those are the conditions under which these two are answered, by their own owner, elsewhere.

## Claims this document makes about itself

Twice now a universal claim in this document has turned out false — that no source enumerated policy-engine candidates, and that no concrete algorithm was named anywhere — and both times the claim was found by a reader rather than by a check. Prose asserting its own correctness is the least reliable part of any document, so every such claim is listed here with the check that enforces it. The list is verified against the body: a claim whose wording changes, or a check that is dropped, fails the checker. Adding a new universal claim without adding its check is the failure this table exists to prevent.

| id | the claim, verbatim | enforced by |
|---|---|---|
| SC1 | Every row carries a source-cited decision question, bounded alternatives, a proposed owner, the affected stories read from the planning store, and the exact evidence required to clear it. | all five fields present in every row section, and the decision question carrying at least one resolving citation |
| SC2 | Nothing in this document is built from those lines. | affected stories compared against `aep plan artifact blocked`, in every row body and in every index row |
| SC3 | every proposed owner below is a role or boundary taken from the [ownership map](ownership.md), citing the line that assigns it | every owner paragraph cites an `ownership.md` line whose text names the role it claims, or declares *no ownership-map owner exists* |
| SC4 | No admitted algorithm is proposed anywhere in this document | a denylist of concrete algorithm identifiers and family names, matched case-insensitively; `none` is excluded because it appears only as something to reject |
| SC5 | This document selects none of these six and recommends none. | selection phrasing absent from the body. Engine candidate names are not denied: the sources enumerate them, so naming them is quoting. Algorithm names are denied because no source enumerates any, so any name would be invented |
| SC6 | Every row above is open. | every blocker's status read from the store equals `open` |
| SC7 | Two further open `decision-blocker` artifacts exist in the planning store and are **deliberately not rows above**. | both Drive blockers named in the body and absent from the row sections and the index |

Two claims are deliberately *not* in this table because they are judgements, not checkable properties: that an independent reviewer can take one row without reading the rest — seven rows state a dependency on another row, so this is a claim about convenience, not isolation — and that the proposed owners are the right ones.

## Completeness

This dossier is complete when each of the eleven rows above carries its five fields, and no row's clearance evidence has been produced by writing it here. Every row above is open. Nothing in this document constitutes a clearance, an approval, an algorithm selection, a backend selection or a claim that any case listed as clearance evidence has been run — none has.

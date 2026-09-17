# Mandate — Architecture Addendum

**Status:** Normative architecture addendum  
**Applies to:** Mandate design specification  
**Implementation:** Rust multi-crate monorepo  
**Document date:** 2026-09-17

---

## 1. Purpose

This addendum strengthens the Mandate architecture in several areas that should be treated as first-class requirements rather than implementation details:

1. separate directory membership from authorization-bearing teams;
2. support both self-contained and opaque/reference access credentials;
3. make external-principal linking explicit and collision-safe;
4. require cryptographically verified tenant resolution with fail-closed behavior;
5. add generation/epoch invalidation for sessions and credentials;
6. require strict audience/resource registration and downscoping;
7. support public-client and CLI authentication with PKCE;
8. harden token exchange for human, service, workload, and agent delegation;
9. store only non-reversible verifiers for opaque bearer credentials;
10. preserve upstream credential containment at trust boundaries.

These requirements refine the existing architecture without changing its central model:

```text
principal + tenancy + relationships + policy + delegation
                         ↓
                    authorization
                         ↓
                   allow / deny
```

The additions are deliberately compatible with the existing Rust crate and service boundaries.

---

# 2. Directory groups and authorization teams are different concepts

## 2.1 Requirement

Mandate MUST distinguish a synchronized or locally managed **directory group** from an authorization-bearing **team**.

A directory group is organizational information.

A team is an authorization subject that may receive grants.

```text
DirectoryGroup
    = collection / directory state

Team
    = authorization-capable principal collection
```

Directory membership MUST NOT grant resource authority by itself.

This prevents an upstream directory change from silently becoming a privilege change.

## 2.2 Recommended model

```text
External directory group
          │
          │ provisioning / synchronization
          ▼
DirectoryGroup
          │
          │ explicit mapping
          ▼
Team
          │
          │ Grant
          ▼
Resource / Space / Organization
```

Example:

```text
DirectoryGroup: engineering
        ↓ mapped_to
Team: platform-engineering
        ↓ operator
Space: staging
```

The mapping MAY be one-to-one, many-to-one, filtered, manually managed, or policy-driven, but MUST be explicit and auditable.

## 2.3 Suggested domain types

```rust
pub struct DirectoryGroupId(...);
pub struct TeamId(...);

pub struct DirectoryGroup {
    pub id: DirectoryGroupId,
    pub organization_id: OrganizationId,
    pub display_name: String,
    pub source: DirectoryGroupSource,
}

pub struct Team {
    pub id: TeamId,
    pub organization_id: OrganizationId,
    pub display_name: String,
}

pub struct DirectoryGroupTeamMapping {
    pub directory_group_id: DirectoryGroupId,
    pub team_id: TeamId,
    pub created_by: PrincipalId,
    pub created_at: Timestamp,
}
```

The authorization graph SHOULD reference `Team`, not `DirectoryGroup`, for authority-bearing relations.

## 2.4 SCIM behavior

SCIM group synchronization SHOULD populate directory state first:

```text
SCIM Group
    ↓
DirectoryGroup
```

An organization administrator then controls whether that group maps to a Mandate team.

SCIM synchronization MUST NOT implicitly create grants such as:

```text
operator -> production
admin    -> organization
```

without explicit configured mapping semantics.

---

# 3. AccessCredential is an abstraction, not synonymous with JWT

## 3.1 Requirement

Mandate SHOULD support two access-credential families:

```text
AccessCredential
├── SelfContainedToken
│   └── JWT / signed token
└── ReferenceToken
    └── opaque high-entropy value resolved by Mandate
```

The choice SHOULD be made per audience/security profile rather than globally.

## 3.2 Self-contained tokens

Use signed self-contained tokens when:

- local/offline verification is important;
- the target service cannot synchronously call Mandate;
- authorization state embedded in the token is deliberately minimal;
- short expiration is acceptable;
- revocation latency can be bounded by token lifetime plus dynamic authorization checks.

A token MAY carry:

```text
iss
sub
act
org
space
execution_id
delegation_id
aud
jti
iat
nbf
exp
```

It SHOULD NOT carry the entire permission graph.

## 3.3 Opaque/reference tokens

Use reference tokens when:

- immediate centralized revocation matters;
- target services already depend on online authorization;
- credential metadata should remain server-side;
- delegation state changes frequently;
- an audience is particularly security-sensitive;
- credential introspection is desirable.

Example:

```text
API request
    │
    │ Authorization: Bearer <opaque-value>
    ▼
Mandate credential resolver
    │
    ├── subject
    ├── actor
    ├── organization
    ├── audience
    ├── delegation
    ├── execution
    ├── expiry
    └── revocation state
```

Reference-token resolution and authorization MAY be combined into one optimized internal call.

## 3.4 Persist only token verifiers

For opaque bearer credentials, Mandate MUST NOT persist the raw bearer value after issuance.

Recommended pattern:

```text
random 256-bit+ token
        │
        ├── returned once to caller
        │
        └── cryptographic hash/verifier persisted
```

For example:

```rust
struct StoredReferenceCredential {
    id: CredentialId,
    verifier: CredentialVerifier,
    subject: PrincipalId,
    actor: Option<PrincipalId>,
    audience: Audience,
    expires_at: Timestamp,
    revoked_at: Option<Timestamp>,
}
```

Credential lookup implementations SHOULD use a keyed or collision-resistant indexing design that avoids accidentally treating the raw secret as an identifier.

## 3.5 Introspection

Reference-token consumers SHOULD use either:

1. an internal Mandate credential-resolution API; or
2. OAuth 2.0 Token Introspection semantics where interoperability is useful.

Reference:

- RFC 7662 — OAuth 2.0 Token Introspection: https://www.rfc-editor.org/rfc/rfc7662

---

# 4. External principal linking must be explicit

## 4.1 Canonical external key

An external account MUST be identified by a trust-domain-qualified key.

At minimum:

```text
(issuer, subject)
```

Where organization-specific federation creates an additional trust boundary, use:

```text
(organization, issuer, subject)
```

Never treat `subject` alone as globally unique.

## 4.2 Email is an attribute, not an identity key

Mandate MUST NOT automatically merge principals because two accounts have the same email address.

Email MAY be used for:

- display;
- invitations;
- administrator-assisted discovery;
- a verified linking workflow;
- account-recovery policy where explicitly designed.

It MUST NOT independently establish account equivalence.

## 4.3 Explicit linking

External accounts SHOULD link through one of these paths:

- administrator-controlled provisioning;
- authenticated account-link confirmation;
- verified migration mapping;
- configured organization federation rule;
- tightly controlled support/security workflow.

Each link MUST be auditable.

Example domain model:

```rust
pub struct ExternalPrincipal {
    pub organization_id: Option<OrganizationId>,
    pub issuer: Issuer,
    pub subject: ExternalSubject,
    pub principal_id: PrincipalId,
    pub linked_at: Timestamp,
    pub link_method: ExternalLinkMethod,
}
```

A uniqueness constraint SHOULD prevent conflicting mappings for the same trust-domain-qualified external identity.

---

# 5. Tenant resolution must be verified and fail closed

## 5.1 Principle

A B2B tenant boundary is security-sensitive.

Mandate MUST derive tenant context only from cryptographically verified and explicitly configured federation information.

Unsafe fallbacks include:

```text
email domain guessing
hostname similarity
unverified query parameters
arbitrary token claims
user-entered organization names
```

## 5.2 Resolution order

A recommended flow is:

```text
1. select configured federation trust relationship
2. validate issuer
3. validate signature
4. validate audience/client binding
5. validate nonce/state/PKCE as applicable
6. validate configured organization/tenant claim or binding
7. resolve external principal
8. establish Mandate organization context
9. issue session/credential
```

If tenant resolution is ambiguous, Mandate MUST deny issuance rather than guess.

## 5.3 Organization-bound federation configuration

```rust
pub struct FederationConnection {
    pub id: FederationConnectionId,
    pub organization_id: OrganizationId,
    pub issuer: Issuer,
    pub client_id: ClientId,
    pub tenant_resolution: TenantResolutionRule,
    pub enabled: bool,
}
```

Federation connections SHOULD be explicitly registered to an organization instead of discovered through weak heuristics.

---

# 6. Epoch-based invalidation

## 6.1 Motivation

Short token lifetimes are necessary but not sufficient for events such as:

- external-account unlinking;
- federation reconfiguration;
- emergency logout;
- compromised credentials;
- tenant trust changes;
- principal disablement;
- organization security resets.

Mandate SHOULD support monotonically increasing invalidation generations.

## 6.2 Recommended epochs

Start with:

```text
PrincipalEpoch
OrganizationSecurityEpoch
FederationEpoch
```

Optionally add more granular generations only when demonstrated necessary.

For example:

```text
session.principal_epoch = 41
current principal epoch = 42

41 != 42
→ reject session
```

## 6.3 Suggested model

```rust
pub struct SecurityEpochs {
    pub principal: u64,
    pub organization: u64,
    pub federation: u64,
}
```

A session or renewable credential MAY snapshot the relevant epoch values.

Validation compares them with current authoritative values before refresh, exchange, or high-risk operations.

## 6.4 Do not over-encode epochs into every authorization decision

Epochs are primarily a credential/session invalidation tool.

Dynamic resource authorization SHOULD continue to use the authorization graph and policy engine.

Do not replace ReBAC revocation with a global epoch system.

---

# 7. Audience and resource registration

## 7.1 Requirement

Mandate MUST NOT allow callers to mint tokens for arbitrary unregistered audiences.

Every accepted audience/resource server SHOULD have a registered record.

```rust
pub struct ResourceServer {
    pub id: ResourceServerId,
    pub audience: Audience,
    pub organization_scope: ResourceServerScope,
    pub credential_profile: CredentialProfile,
    pub allowed_exchange_sources: Vec<ExchangeSource>,
    pub enabled: bool,
}
```

## 7.2 One credential, one intended target

Prefer narrow target binding:

```text
credential A → deployment-api
credential B → logs-api
credential C → billing-api
```

Avoid broad credentials such as:

```text
aud = *
```

or unnecessarily large audience sets.

## 7.3 Resource Indicators

Where OAuth interoperability applies, Mandate SHOULD support OAuth Resource Indicators.

Reference:

- RFC 8707 — Resource Indicators for OAuth 2.0: https://www.rfc-editor.org/rfc/rfc8707

A token exchange MUST NOT widen the target resource set.

For source target set `S` and requested target `R`:

```text
R ⊆ allowed_targets(S, actor, policy)
```

Failure to satisfy this rule MUST result in denial.

---

# 8. Public clients and CLI authentication

## 8.1 Requirement

Mandate SHOULD provide a first-class authentication flow for CLI, native, desktop, and other public clients that cannot safely retain a client secret.

Authorization Code + PKCE is the preferred baseline.

Reference:

- RFC 7636 — Proof Key for Code Exchange: https://www.rfc-editor.org/rfc/rfc7636
- RFC 8252 — OAuth 2.0 for Native Apps: https://www.rfc-editor.org/rfc/rfc8252
- RFC 9700 — Best Current Practice for OAuth 2.0 Security: https://www.rfc-editor.org/rfc/rfc9700

## 8.2 CLI flow

```text
mandate CLI
    │
    ├── generate verifier + challenge
    ├── open browser
    ▼
Mandate authorization endpoint
    │
    ├── organization federation
    ├── authenticate user
    ├── consent/context if required
    ▼
authorization code
    │
    ▼
CLI + verifier
    │
    ▼
Mandate STS
    │
    ▼
CLI session / refresh capability / access credential
```

The client MUST NOT depend on an embedded static secret for security.

## 8.3 Device Authorization Grant

For terminal-only or constrained environments, Mandate MAY add the Device Authorization Grant.

Reference:

- RFC 8628 — OAuth 2.0 Device Authorization Grant: https://www.rfc-editor.org/rfc/rfc8628

This SHOULD be treated as a separate UX/security profile rather than a replacement for browser-based PKCE where browser access is practical.

---

# 9. Token exchange hardening

## 9.1 STS is the authority-narrowing boundary

The Mandate STS SHALL be responsible for:

```text
credential validation
subject authentication
actor/workload authentication
delegation validation
audience restriction
resource restriction
capability downscoping
tenant/space binding
short-lived issuance
audit correlation
```

## 9.2 Delegated exchange

Conceptually:

```text
subject credential
       +
actor/workload credential
       +
requested target
       +
requested scope/capability
       ↓
Mandate STS
       ↓
short-lived delegated credential
```

The result MUST preserve subject and actor separately.

Reference:

- RFC 8693 — OAuth 2.0 Token Exchange: https://www.rfc-editor.org/rfc/rfc8693

## 9.3 No expansion invariant

For every exchange:

```text
effective authority
  = subject authority
  ∩ actor ceiling
  ∩ explicit delegation
  ∩ requested capability
  ∩ organization boundary
  ∩ space/resource boundary
  ∩ registered audience policy
  ∩ current authorization policy
```

A token exchange MUST NOT:

- create permissions unavailable to the subject;
- exceed the actor's capability ceiling;
- cross an organization boundary without explicit cross-org policy;
- widen from staging to production;
- widen from one audience to arbitrary audiences;
- remove a required actor identity;
- extend beyond the delegation expiry;
- outlive the applicable source credential/policy limit without explicit renewable-session semantics.

## 9.4 Service-to-service exchange

The same mechanism SHOULD cover service delegation:

```text
service:support-platform
        │ delegates subset
        ▼
agent:support-investigator
        │
        ▼
logs-api credential
```

No agent-specific parallel token system is required.

---

# 10. Upstream credential containment

## 10.1 Rule

Mandate MUST NOT propagate an upstream provider's access token or refresh token to downstream Mandate resource services unless an explicit integration requires use of that provider API.

Normal Mandate flow:

```text
external authentication proof
        ↓
Mandate verifies / maps principal
        ↓
Mandate session / credential
        ↓
Mandate-protected resources
```

Not:

```text
external provider token
        ↓
all internal microservices
```

## 10.2 Provider credentials

If Mandate must retain an upstream refresh/access credential for an external API integration, that credential SHOULD be:

- encrypted using a dedicated secrets boundary;
- bound to the relevant connection/principal;
- inaccessible to ordinary resource services;
- excluded from normal logs, audit payloads, and agent context;
- rotated/revoked according to provider capabilities.

This is separate from Mandate access credentials.

---

# 11. Authorization API implications

The authorization interface remains stable.

```rust
pub struct CheckRequest {
    pub subject: PrincipalId,
    pub actor: Option<PrincipalId>,
    pub action: Action,
    pub resource: ResourceRef,
    pub context: AuthorizationContext,
}
```

The new requirements modify how the caller arrives at a trustworthy `subject`, `actor`, organization, audience, and context; they do not require resource services to learn federation or directory semantics.

Resource services SHOULD continue to behave as policy enforcement points:

```text
authenticate Mandate credential
        ↓
construct authorization request
        ↓
Mandate check
        ↓
allow / deny
```

---

# 12. Rust workspace changes

The existing workspace remains appropriate.

Recommended additions/refinements:

```text
crates/
├── mandate-types/
├── mandate-model/
├── mandate-authz/
├── mandate-policy/
├── mandate-graph/
├── mandate-token/
├── mandate-identity/
├── mandate-federation/
├── mandate-provisioning/
├── mandate-audit/
├── mandate-proto/
├── mandate-client/
├── mandate-server/
└── mandate-testkit/
```

## 12.1 `mandate-model`

Add:

```text
DirectoryGroup
DirectoryGroupMembership
DirectoryGroupTeamMapping
ExternalPrincipal
ResourceServer
FederationConnection
SecurityEpochs
CredentialProfile
```

## 12.2 `mandate-token`

Introduce format-neutral primitives:

```rust
pub enum CredentialKind {
    SelfContained,
    Reference,
}

pub struct CredentialDescriptor {
    pub kind: CredentialKind,
    pub subject: PrincipalId,
    pub actor: Option<PrincipalId>,
    pub organization: OrganizationId,
    pub audience: Audience,
    pub delegation_id: Option<DelegationId>,
    pub execution_id: Option<ExecutionId>,
    pub expires_at: Timestamp,
}
```

Keep JWT/JWS/JWK implementation details behind this abstraction where possible.

## 12.3 `mandate-federation`

Add explicit support for:

```text
organization-bound connections
issuer validation
exact external-subject mapping
PKCE
native/CLI flows
strict redirect URI policy
resource indicators
federation generation changes
```

## 12.4 `mandate-provisioning`

SCIM SHOULD write:

```text
users / external principal attributes
directory groups
directory memberships
```

It SHOULD NOT directly create resource grants unless a separately configured mapping policy explicitly requests that behavior.

## 12.5 `mandate-sts`

The STS service becomes the implementation owner for:

```text
reference credential issuance
self-contained token issuance
introspection/resolution
token exchange
audience/resource downscoping
actor preservation
epoch checks
revocation
PKCE token endpoint behavior
```

---

# 13. Storage changes

A relational first implementation could include tables similar to:

```text
principals
organizations
memberships
teams
team_memberships

directory_groups
directory_group_memberships
directory_group_team_mappings

external_principals
federation_connections

resource_servers

reference_credentials
sessions
refresh_credentials

principal_security_epochs
organization_security_epochs
federation_security_epochs

grants
relations
delegations
executions

audit_events
```

## 13.1 Important constraints

Recommended database constraints include:

```text
UNIQUE (organization_id, issuer, external_subject)
UNIQUE (organization_id, audience)
UNIQUE (directory_group_id, team_id)
UNIQUE credential verifier/index
```

Do not place raw opaque bearer credentials in database rows.

## 13.2 Cascading behavior

Security-sensitive deletes SHOULD usually be explicit rather than relying on broad database cascade behavior.

Examples:

- deleting a federation connection increments its security epoch and invalidates affected sessions;
- unlinking an external principal increments the principal epoch;
- disabling a resource server immediately prevents new token issuance;
- deleting a directory group mapping removes derived team membership according to the chosen synchronization semantics but does not delete the team itself unless explicitly requested.

---

# 14. Audit requirements

The audit model SHOULD add dedicated events for:

```text
external_principal.linked
external_principal.unlinked
federation.connection.created
federation.connection.changed
federation.connection.disabled
security_epoch.incremented

directory_group.created
directory_group.membership_changed
directory_group.team_mapping_created
directory_group.team_mapping_removed

resource_server.registered
resource_server.disabled

credential.reference_issued
credential.self_contained_issued
credential.introspected
credential.revoked

token_exchange.allowed
token_exchange.denied
```

A token-exchange event SHOULD record enough information to reconstruct:

```text
subject
actor
organization
source credential class
requested audience
issued audience
requested capability/downscope
delegation
execution
result
policy/decision correlation
```

Secrets and raw bearer tokens MUST NOT appear in audit records.

---

# 15. Security invariants added by this document

The following SHOULD become explicit regression properties.

### Invariant 1 — directory membership is not authority

```text
DirectoryGroup membership
    alone
!= resource permission
```

### Invariant 2 — no identity merge from email

```text
same email
!= same principal
```

### Invariant 3 — ambiguous tenant resolution fails

```text
0 matching configured tenants → deny
>1 matching configured tenants → deny
exact verified tenant         → continue
```

### Invariant 4 — exchange only narrows authority

```text
issued_authority ⊆ allowed(subject, actor, delegation, target)
```

### Invariant 5 — target audience must be registered

```text
unknown audience → no issuance
```

### Invariant 6 — reference-token storage is non-reversible

Database disclosure alone MUST NOT reveal currently usable bearer credentials.

### Invariant 7 — upstream provider credentials stay upstream

Mandate-protected APIs accept Mandate credentials, not arbitrary upstream credentials.

### Invariant 8 — epoch mismatch invalidates renewable security state

```text
credential/session epoch != current epoch
→ reject / force reauthentication
```

### Invariant 9 — actor identity survives delegation

If an actor is required at exchange time, downstream security context MUST NOT collapse the actor into the subject.

### Invariant 10 — target/resource cannot widen across exchange

A credential for one resource server MUST NOT become a wildcard credential through exchange.

---

# 16. Test-plan additions

## 16.1 Directory tests

```text
SCIM group membership alone grants nothing
mapped directory group produces team membership
removing mapping removes derived authority
manual team membership survives unrelated directory changes
```

## 16.2 External-principal tests

```text
same subject under different issuers remains distinct
same email under different issuers remains distinct
explicit link works
ambiguous link fails
unlinked principal invalidates renewable session state
```

## 16.3 Tenant-resolution tests

```text
verified configured tenant succeeds
missing configured tenant fails
ambiguous tenant fails
unverified org claim fails
email-domain fallback is never used
```

## 16.4 Reference-token tests

```text
raw secret is returned only at issuance
raw secret is not persisted
valid verifier resolves correct credential
revoked token fails immediately
audience mismatch fails
expired token fails
```

## 16.5 Exchange tests

```text
subject permission ∩ actor ceiling works
requested authority cannot exceed subject
requested authority cannot exceed actor
requested audience cannot widen
requested organization cannot change
expired delegation fails
revoked actor fails
disabled resource server fails
actor survives into downstream context
```

## 16.6 Epoch tests

```text
principal epoch bump invalidates renewable session
organization epoch bump invalidates affected sessions
federation epoch bump forces federation reauthentication
unrelated organization remains unaffected
```

## 16.7 PKCE tests

```text
S256 succeeds
wrong verifier fails
missing verifier fails for PKCE-required client
plain method rejected unless explicitly supported
code reuse fails
redirect mismatch fails
state/nonce protections remain enforced
```

---

# 17. Roadmap changes

These additions should be incorporated into the implementation roadmap rather than deferred as optional hardening.

## Phase 0 — domain and invariants

Add before broad implementation:

- `DirectoryGroup` vs `Team` semantic split;
- `ExternalPrincipal` canonical key;
- resource-server/audience registry;
- credential-kind abstraction;
- epoch model;
- exchange narrowing invariants;
- audit schemas for link/exchange/invalidation events.

## Phase 1 — authentication and federation foundation

Implement:

- explicit organization federation connections;
- issuer and subject mapping;
- no email-based auto-linking;
- browser authorization-code flow;
- PKCE;
- strict redirect URI validation;
- tenant-resolution fail-closed rules;
- session epoch snapshots.

## Phase 2 — STS and credential system

Implement:

- resource-server registry;
- self-contained credential issuance;
- opaque/reference credential issuance;
- hashed verifier persistence;
- revocation;
- introspection/resolution;
- token exchange;
- audience/resource downscoping;
- actor preservation.

## Phase 3 — directory and enterprise provisioning

Implement:

- SCIM users;
- SCIM directory groups;
- directory group membership;
- explicit group-to-team mapping;
- audit trail for mapping changes.

## Phase 4 — service/workload/agent delegation

Build on the same STS:

- workload authentication;
- service principals;
- agent principals;
- subject + actor token exchange;
- capability ceilings;
- execution IDs;
- delegation expiry/revocation;
- high-risk approval hooks.

## Phase 5 — hardening

Add:

- organization-wide security epoch operations;
- emergency federation shutdown;
- key rotation drills;
- reference-token load testing;
- introspection caching with bounded revocation latency;
- token theft simulations;
- exchange-confusion tests;
- tenant-boundary penetration tests;
- audit export and security analytics.

---

# 18. API additions

## 18.1 Resource-server registration

Conceptual API:

```http
POST /v1/resource-servers
```

```json
{
  "audience": "https://api.example.internal/deployments",
  "credential_profile": "reference",
  "exchange_policy": "downscope-only"
}
```

## 18.2 External-principal link

```http
POST /v1/organizations/{org}/external-principals
```

```json
{
  "issuer": "https://issuer.example.com",
  "subject": "abc123",
  "principal_id": "usr_..."
}
```

## 18.3 Directory group mapping

```http
POST /v1/directory-groups/{group}/team-mappings
```

```json
{
  "team_id": "team_..."
}
```

## 18.4 Token exchange

Interoperable OAuth deployments SHOULD support RFC 8693 semantics at the token endpoint.

Conceptually:

```http
POST /oauth/token
Content-Type: application/x-www-form-urlencoded
```

```text
grant_type=urn:ietf:params:oauth:grant-type:token-exchange
subject_token=...
actor_token=...
resource=...
```

Internal APIs MAY use richer typed requests but MUST preserve the same narrowing semantics.

## 18.5 Introspection

```http
POST /oauth/introspect
```

Responses for active reference credentials SHOULD expose only the security context required by the registered caller.

---

# 19. Operational guidance

## 19.1 Credential profiles

Define named profiles instead of scattering token decisions across services.

Example:

```text
browser-api
    credential: JWT
    ttl: 5m
    online authz: yes

agent-high-risk
    credential: reference
    ttl: 2m
    online authz: yes
    immediate revocation: yes

internal-read-api
    credential: JWT
    ttl: 3m
    workload-bound: yes
```

The exact values are deployment policy, not protocol constants.

## 19.2 Caching

Reference-token resolution MAY be cached, but cache TTL MUST respect the revocation guarantee promised for that credential profile.

Authorization decision caching MUST continue to follow Mandate's existing consistency strategy.

Do not accidentally turn a reference token into a de-facto long-lived locally cached JWT.

## 19.3 Failure behavior

For protected operations:

```text
unknown credential        → deny
unknown issuer            → deny
unknown audience          → deny
ambiguous tenant          → deny
disabled principal        → deny
stale epoch               → deny
unavailable required PDP  → deny
```

Availability exceptions must be explicit, documented, and limited to operations where fail-open behavior has been consciously accepted.

---

# 20. RFC and standards references

The following should be included in the Mandate implementation/reference set.

| Standard | Relevance |
|---|---|
| RFC 6749 — OAuth 2.0 Authorization Framework | OAuth foundation |
| RFC 7636 — PKCE | Public/native/CLI authorization-code protection |
| RFC 8252 — OAuth 2.0 for Native Apps | Native application guidance |
| RFC 8628 — Device Authorization Grant | Optional constrained-device/terminal flow |
| RFC 8693 — OAuth 2.0 Token Exchange | Delegation and STS exchange semantics |
| RFC 8707 — OAuth 2.0 Resource Indicators | Audience/resource-targeted issuance |
| RFC 7009 — OAuth 2.0 Token Revocation | Revocation endpoint semantics |
| RFC 7662 — OAuth 2.0 Token Introspection | Reference-token resolution/interoperability |
| RFC 7519 — JSON Web Token | Self-contained token format |
| RFC 8414 — Authorization Server Metadata | Discovery metadata |
| RFC 9700 — OAuth 2.0 Security Best Current Practice | Current OAuth security BCP |
| OpenID Connect Core 1.0 | Federated authentication |
| RFC 7643 / RFC 7644 — SCIM | Enterprise user/group provisioning |

Links:

- OAuth 2.0 — https://www.rfc-editor.org/rfc/rfc6749
- PKCE — https://www.rfc-editor.org/rfc/rfc7636
- Native Apps — https://www.rfc-editor.org/rfc/rfc8252
- Device Authorization — https://www.rfc-editor.org/rfc/rfc8628
- Token Exchange — https://www.rfc-editor.org/rfc/rfc8693
- Resource Indicators — https://www.rfc-editor.org/rfc/rfc8707
- Token Revocation — https://www.rfc-editor.org/rfc/rfc7009
- Token Introspection — https://www.rfc-editor.org/rfc/rfc7662
- JWT — https://www.rfc-editor.org/rfc/rfc7519
- Authorization Server Metadata — https://www.rfc-editor.org/rfc/rfc8414
- OAuth 2.0 Security BCP — https://www.rfc-editor.org/rfc/rfc9700
- OpenID Connect Core — https://openid.net/specs/openid-connect-core-1_0.html
- SCIM Core Schema — https://www.rfc-editor.org/rfc/rfc7643
- SCIM Protocol — https://www.rfc-editor.org/rfc/rfc7644

---

# 21. Final architecture after this addendum

```text
                           EXTERNAL TRUST

             OIDC / SAML / enterprise federation
                             │
                             ▼
                  ┌─────────────────────┐
                  │ Mandate Federation  │
                  │                     │
                  │ verified tenant     │
                  │ external subject    │
                  │ explicit linking    │
                  └──────────┬──────────┘
                             │
                             ▼
                  ┌─────────────────────┐
                  │ Principal / Session │
                  │                     │
                  │ security epochs     │
                  │ org context         │
                  └──────────┬──────────┘
                             │
                             ▼
                  ┌─────────────────────┐
                  │ Mandate STS         │
                  │                     │
                  │ PKCE                │
                  │ token exchange      │
                  │ reference tokens    │
                  │ signed tokens       │
                  │ audience binding    │
                  │ resource downscope  │
                  │ subject + actor     │
                  └──────────┬──────────┘
                             │
                             ▼
                  ┌─────────────────────┐
                  │ Mandate AuthZ       │
                  │                     │
                  │ ReBAC graph         │
                  │ policy              │
                  │ grants              │
                  │ delegation          │
                  │ agent ceilings      │
                  └──────────┬──────────┘
                             │
         ┌───────────────────┼───────────────────┐
         ▼                   ▼                   ▼
   Deployment API       Database API          Logs API


                  ENTERPRISE DIRECTORY PLANE

                       SCIM / sync
                           │
                           ▼
                    DirectoryGroup
                           │
                    explicit mapping
                           │
                           ▼
                         Team
                           │
                          Grant
                           │
                           ▼
                       Resources
```

The important security properties are now explicit:

```text
external directory state
    ≠ automatic authority

external account similarity
    ≠ automatic principal merge

source credential
    ≠ permission to mint arbitrary target credentials

user authority
    ≠ unrestricted agent authority

valid signature
    ≠ valid tenant / audience / policy

credential issuance
    ≠ authorization decision
```

This addendum should be treated as normative for implementation planning and security review.

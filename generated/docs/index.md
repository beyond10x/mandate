<!--
generated from mandate v1
model digest 4a856239408291b04081d690cb65f638971dd1711f23b1dbb384b26f4f7a5fd1
contract digest e9d6b8cf0a9feccec819fac58f1e8daba79a1a19485b85eeceaa1ee1cfc8add4
do not edit: regenerate with `ess generate`
-->

# mandate v1

Standalone identity, authorization and constrained credential contracts. Runtime enforcement and UNMAPPED semantics are explicit obligations.

## The system as a graph

```mermaid
flowchart TB
    subgraph unit0["mandate-authorization"]
        cmd1["mandate.authorization.Check"]
        cmd24["mandate.graph.RegisterResource"]
        cmd25["mandate.graph.RemoveRelation"]
        cmd26["mandate.graph.RevokeGrant"]
        cmd27["mandate.graph.WriteRelationship"]
        evt6["mandate.authorization.DecisionRecorded"]
        evt30["mandate.graph.GrantRevoked"]
        evt31["mandate.graph.RelationRemoved"]
        evt32["mandate.graph.RelationshipWritten"]
        evt33["mandate.graph.ResourceRegistered"]
    end
    subgraph unit1["mandate-control-plane"]
        cmd11["mandate.delegation.CreateDelegation"]
        cmd12["mandate.delegation.RevokeDelegation"]
        cmd13["mandate.directory.CreateDirectoryGroupTeamMapping"]
        cmd14["mandate.directory.RemoveDirectoryGroupMembership"]
        cmd15["mandate.directory.RemoveDirectoryGroupTeamMapping"]
        cmd16["mandate.directory.RemoveMembershipContribution"]
        cmd17["mandate.directory.SyncDirectoryMembership"]
        cmd18["mandate.federation.AuthenticateFederation"]
        cmd19["mandate.federation.AuthorizePublicClient"]
        cmd20["mandate.federation.DisableFederationConnection"]
        cmd21["mandate.federation.LinkExternalPrincipal"]
        cmd22["mandate.federation.RegisterFederationConnection"]
        cmd23["mandate.federation.UnlinkExternalPrincipal"]
        cmd28["mandate.identity.DisablePrincipal"]
        cmd29["mandate.identity.IncrementSecurityEpoch"]
        cmd30["mandate.identity.RefreshSession"]
        cmd31["mandate.identity.RevokeRefreshCredential"]
        cmd32["mandate.identity.RevokeSession"]
        cmd33["mandate.tenancy.RemoveOrganizationMembership"]
        evt17["mandate.delegation.DelegationCreated"]
        evt18["mandate.delegation.DelegationRevoked"]
        evt19["mandate.directory.DirectoryGroupMembershipChanged"]
        evt20["mandate.directory.DirectoryGroupMembershipRemoved"]
        evt21["mandate.directory.DirectoryGroupTeamMappingCreated"]
        evt22["mandate.directory.DirectoryGroupTeamMappingRemoved"]
        evt23["mandate.directory.MembershipContributionRemoved"]
        evt24["mandate.federation.AuthorizationCodeIssued"]
        evt25["mandate.federation.ExternalPrincipalLinked"]
        evt26["mandate.federation.ExternalPrincipalUnlinked"]
        evt27["mandate.federation.FederationAuthenticated"]
        evt28["mandate.federation.FederationConnectionCreated"]
        evt29["mandate.federation.FederationConnectionDisabled"]
        evt34["mandate.identity.PrincipalDisabled"]
        evt35["mandate.identity.RefreshCredentialRevoked"]
        evt36["mandate.identity.SecurityEpochIncremented"]
        evt37["mandate.identity.SessionRefreshed"]
        evt38["mandate.identity.SessionRevoked"]
        evt39["mandate.tenancy.OrganizationMembershipRemoved"]
    end
    subgraph unit2["mandate-sts"]
        cmd2["mandate.credential.DisableResourceServer"]
        cmd3["mandate.credential.ExchangeCredential"]
        cmd4["mandate.credential.IntrospectCredential"]
        cmd5["mandate.credential.IssueAuthorizationCode"]
        cmd6["mandate.credential.IssueReferenceCredential"]
        cmd7["mandate.credential.IssueSelfContainedCredential"]
        cmd8["mandate.credential.RedeemAuthorizationCode"]
        cmd9["mandate.credential.RegisterResourceServer"]
        cmd10["mandate.credential.RevokeAccessCredential"]
        evt7["mandate.credential.AccessCredentialRevoked"]
        evt8["mandate.credential.AuthorizationCodeIssued"]
        evt9["mandate.credential.AuthorizationCodeRedeemed"]
        evt10["mandate.credential.CredentialIntrospected"]
        evt11["mandate.credential.CredentialReferenceIssued"]
        evt12["mandate.credential.CredentialSelfContainedIssued"]
        evt13["mandate.credential.ResourceServerDisabled"]
        evt14["mandate.credential.ResourceServerRegistered"]
        evt15["mandate.credential.TokenExchangeAllowed"]
        evt16["mandate.credential.TokenExchangeDenied"]
    end
    subgraph unit3["mandate-worker"]
        cmd0["mandate.audit.RecordAuditEvent"]
        evt0["mandate.audit.AuditEventRecorded"]
        evt1["mandate.audit.CredentialRevoked"]
        evt2["mandate.audit.DirectoryGroupCreated"]
        evt3["mandate.audit.ExternalPrincipalUnlinked"]
        evt4["mandate.audit.FederationConnectionChanged"]
        evt5["mandate.audit.TokenExchangeDenied"]
    end
    cmd0 -->|"recorded"| evt0
    cmd1 -->|"accepted"| evt6
    cmd2 -->|"accepted"| evt13
    cmd3 -->|"accepted"| evt15
    cmd4 -->|"accepted"| evt10
    cmd5 -->|"accepted"| evt8
    cmd6 -->|"accepted"| evt11
    cmd7 -->|"accepted"| evt12
    cmd8 -->|"accepted"| evt9
    cmd9 -->|"accepted"| evt14
    cmd10 -->|"accepted"| evt7
    cmd11 -->|"accepted"| evt17
    cmd12 -->|"accepted"| evt18
    cmd13 -->|"accepted"| evt21
    cmd14 -->|"accepted"| evt20
    cmd15 -->|"accepted"| evt22
    cmd16 -->|"accepted"| evt23
    cmd17 -->|"accepted"| evt19
    cmd18 -->|"accepted"| evt27
    cmd19 -->|"accepted"| evt24
    cmd20 -->|"accepted"| evt29
    cmd21 -->|"accepted"| evt25
    cmd22 -->|"accepted"| evt28
    cmd23 -->|"accepted"| evt26
    cmd24 -->|"accepted"| evt33
    cmd25 -->|"accepted"| evt31
    cmd26 -->|"accepted"| evt30
    cmd27 -->|"accepted"| evt32
    cmd28 -->|"accepted"| evt34
    cmd29 -->|"accepted"| evt36
    cmd30 -->|"accepted"| evt37
    cmd31 -->|"accepted"| evt35
    cmd32 -->|"accepted"| evt38
    cmd33 -->|"accepted"| evt39
```

A command is accepted by the component that owns its context, emits the events one of its outcomes declares, and a dashed edge is a binding carrying an event into the next command. Design §9 begins one step earlier, at the actor who invokes the first command, and so does this graph: a solid edge out of an actor is a grant, and an actor drawn with no edge at all may invoke nothing — which is something the model says, not an arrow somebody forgot.

## Bounded contexts

- **[audit](domains/mandate-audit.md)** (`mandate.audit`) — Canonical redacted audit records and the trusted worker append port. UNMAPPED-AUDIT-ROUTING: per-domain event mapping, durable outbox transport, retention and failure policy remain required. Named AuditAction and AuditOutcome do not admit arbitrary values. No types, one entity, no views, one command, six events, one error and no actors.
- **[authorization](domains/mandate-authorization.md)** (`mandate.authorization`) No types, no entities, no views, one command, one event, one error and no actors.
- **[core](domains/mandate-core.md)** (`mandate.core`) 74 types, no entities, no views, no commands, no events, no errors and no actors.
- **[credential](domains/mandate-credential.md)** (`mandate.credential`) No types, four entities, no views, nine commands, 10 events, one error and no actors.
- **[delegation](domains/mandate-delegation.md)** (`mandate.delegation`) No types, five entities, no views, two commands, two events, one error and no actors.
- **[directory](domains/mandate-directory.md)** (`mandate.directory`) No types, five entities, no views, five commands, five events, one error and no actors.
- **[federation](domains/mandate-federation.md)** (`mandate.federation`) No types, three entities, no views, six commands, six events, one error and no actors.
- **[graph](domains/mandate-graph.md)** (`mandate.graph`) — Resource topology, tagged principal-or-team relationship subjects and grants. UNMAPPED-SUBJECT-RELATIONS: ESS cannot select a union branch as a relation carrier. Each chosen principal/team branch references exactly one existing target; conditional foreign-key and tenant membership validation remain required before graph runtime admission. No types, three entities, no views, four commands, four events, one error and no actors.
- **[identity](domains/mandate-identity.md)** (`mandate.identity`) — Principal, session and independent principal/organization/federation generation ownership. UNMAPPED-EPOCH: generation records declare ownership only; exact unsigned current and snapshot values are absent until supported. EpochSnapshotRef is an immutable record handle, not a generation number. Refresh and exchange cannot be implemented without closing this blocker. No types, seven entities, no views, five commands, five events, one error and no actors.
- **[policy](domains/mandate-policy.md)** (`mandate.policy`) No types, two entities, no views, no commands, no events, no errors and no actors.
- **[tenancy](domains/mandate-tenancy.md)** (`mandate.tenancy`) No types, five entities, no views, one command, one event, one error and no actors.
- **[workload](domains/mandate-workload.md)** (`mandate.workload`) No types, one entity, no views, no commands, no events, no errors and no actors.

## Components

A component is a unit of ownership, not a deployment. How many of each runs, and what each needs, is [the topology](topology.md).

**`mandate-authorization`** — Planned deployment boundary; exact domain-to-library responsibilities and required adapter/worker gaps are recorded in docs/architecture/ownership.md. It owns [`mandate.authorization`](domains/mandate-authorization.md), [`mandate.graph`](domains/mandate-graph.md) and [`mandate.policy`](domains/mandate-policy.md). It accepts `mandate.authorization.Check`, `mandate.graph.RegisterResource`, `mandate.graph.RemoveRelation`, `mandate.graph.RevokeGrant` and `mandate.graph.WriteRelationship`. It publishes `mandate.authorization.DecisionRecorded`, `mandate.graph.GrantRevoked`, `mandate.graph.RelationRemoved`, `mandate.graph.RelationshipWritten` and `mandate.graph.ResourceRegistered`.

**`mandate-control-plane`** — Administrative deployment and documentation publisher for the shared mandate.core vocabulary. All four deployments compile those shared library types; core is not a remote control-plane runtime dependency. See docs/architecture/ownership.md. It owns [`mandate.core`](domains/mandate-core.md), [`mandate.delegation`](domains/mandate-delegation.md), [`mandate.directory`](domains/mandate-directory.md), [`mandate.federation`](domains/mandate-federation.md), [`mandate.identity`](domains/mandate-identity.md), [`mandate.tenancy`](domains/mandate-tenancy.md) and [`mandate.workload`](domains/mandate-workload.md). It accepts `mandate.delegation.CreateDelegation`, `mandate.delegation.RevokeDelegation`, `mandate.directory.CreateDirectoryGroupTeamMapping`, `mandate.directory.RemoveDirectoryGroupMembership`, `mandate.directory.RemoveDirectoryGroupTeamMapping`, `mandate.directory.RemoveMembershipContribution`, `mandate.directory.SyncDirectoryMembership`, `mandate.federation.AuthenticateFederation`, `mandate.federation.AuthorizePublicClient`, `mandate.federation.DisableFederationConnection`, `mandate.federation.LinkExternalPrincipal`, `mandate.federation.RegisterFederationConnection`, `mandate.federation.UnlinkExternalPrincipal`, `mandate.identity.DisablePrincipal`, `mandate.identity.IncrementSecurityEpoch`, `mandate.identity.RefreshSession`, `mandate.identity.RevokeRefreshCredential`, `mandate.identity.RevokeSession` and `mandate.tenancy.RemoveOrganizationMembership`. It publishes `mandate.delegation.DelegationCreated`, `mandate.delegation.DelegationRevoked`, `mandate.directory.DirectoryGroupMembershipChanged`, `mandate.directory.DirectoryGroupMembershipRemoved`, `mandate.directory.DirectoryGroupTeamMappingCreated`, `mandate.directory.DirectoryGroupTeamMappingRemoved`, `mandate.directory.MembershipContributionRemoved`, `mandate.federation.AuthorizationCodeIssued`, `mandate.federation.ExternalPrincipalLinked`, `mandate.federation.ExternalPrincipalUnlinked`, `mandate.federation.FederationAuthenticated`, `mandate.federation.FederationConnectionCreated`, `mandate.federation.FederationConnectionDisabled`, `mandate.identity.PrincipalDisabled`, `mandate.identity.RefreshCredentialRevoked`, `mandate.identity.SecurityEpochIncremented`, `mandate.identity.SessionRefreshed`, `mandate.identity.SessionRevoked` and `mandate.tenancy.OrganizationMembershipRemoved`.

**`mandate-sts`** — Planned deployment boundary; exact domain-to-library responsibilities and required adapter/worker gaps are recorded in docs/architecture/ownership.md. It owns [`mandate.credential`](domains/mandate-credential.md). It accepts `mandate.credential.DisableResourceServer`, `mandate.credential.ExchangeCredential`, `mandate.credential.IntrospectCredential`, `mandate.credential.IssueAuthorizationCode`, `mandate.credential.IssueReferenceCredential`, `mandate.credential.IssueSelfContainedCredential`, `mandate.credential.RedeemAuthorizationCode`, `mandate.credential.RegisterResourceServer` and `mandate.credential.RevokeAccessCredential`. It publishes `mandate.credential.AccessCredentialRevoked`, `mandate.credential.AuthorizationCodeIssued`, `mandate.credential.AuthorizationCodeRedeemed`, `mandate.credential.CredentialIntrospected`, `mandate.credential.CredentialReferenceIssued`, `mandate.credential.CredentialSelfContainedIssued`, `mandate.credential.ResourceServerDisabled`, `mandate.credential.ResourceServerRegistered`, `mandate.credential.TokenExchangeAllowed` and `mandate.credential.TokenExchangeDenied`.

**`mandate-worker`** — Planned deployment boundary; exact domain-to-library responsibilities and required adapter/worker gaps are recorded in docs/architecture/ownership.md. It owns [`mandate.audit`](domains/mandate-audit.md). It accepts `mandate.audit.RecordAuditEvent`. It publishes `mandate.audit.AuditEventRecorded`, `mandate.audit.CredentialRevoked`, `mandate.audit.DirectoryGroupCreated`, `mandate.audit.ExternalPrincipalUnlinked`, `mandate.audit.FederationConnectionChanged` and `mandate.audit.TokenExchangeDenied`.

## The other pages

| page | what is on it |
|---|---|
| [audit](domains/mandate-audit.md) | the `mandate.audit` vocabulary: its types, entities, views, commands, events, errors and actors |
| [authorization](domains/mandate-authorization.md) | the `mandate.authorization` vocabulary: its types, entities, views, commands, events, errors and actors |
| [core](domains/mandate-core.md) | the `mandate.core` vocabulary: its types, entities, views, commands, events, errors and actors |
| [credential](domains/mandate-credential.md) | the `mandate.credential` vocabulary: its types, entities, views, commands, events, errors and actors |
| [delegation](domains/mandate-delegation.md) | the `mandate.delegation` vocabulary: its types, entities, views, commands, events, errors and actors |
| [directory](domains/mandate-directory.md) | the `mandate.directory` vocabulary: its types, entities, views, commands, events, errors and actors |
| [federation](domains/mandate-federation.md) | the `mandate.federation` vocabulary: its types, entities, views, commands, events, errors and actors |
| [graph](domains/mandate-graph.md) | the `mandate.graph` vocabulary: its types, entities, views, commands, events, errors and actors |
| [identity](domains/mandate-identity.md) | the `mandate.identity` vocabulary: its types, entities, views, commands, events, errors and actors |
| [policy](domains/mandate-policy.md) | the `mandate.policy` vocabulary: its types, entities, views, commands, events, errors and actors |
| [tenancy](domains/mandate-tenancy.md) | the `mandate.tenancy` vocabulary: its types, entities, views, commands, events, errors and actors |
| [workload](domains/mandate-workload.md) | the `mandate.workload` vocabulary: its types, entities, views, commands, events, errors and actors |
| [Interactions](interactions.md) | every binding, with what it guarantees and what happens when it fails |
| [Type crossings](crossings.md) | every conversion this system permits, and the reason someone gave for it |
| [Topology](topology.md) | what each component needs in order to run |


---

Generated from mandate v1 · model digest `4a856239408291b04081d690cb65f638971dd1711f23b1dbb384b26f4f7a5fd1` · contract digest `e9d6b8cf0a9feccec819fac58f1e8daba79a1a19485b85eeceaa1ee1cfc8add4`. Do not edit this file; change the specification and regenerate it with `ess generate`.

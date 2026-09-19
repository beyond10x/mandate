<!--
generated from mandate v1
model digest 01de9945d788263e9f6df566e556a0cc122f96c94d48538ad2536276eac2bc74
contract digest 6c11d73c4163491aff4557b9039bfea9cff5a87ff4bf652962d8e1f71763c1f0
do not edit: regenerate with `ess generate`
-->

# mandate v1

Standalone identity, authorization and constrained credential contracts. Runtime enforcement and UNMAPPED semantics are explicit obligations.

## The system as a graph

```mermaid
flowchart TB
    subgraph unit0["mandate-authorization"]
        cmd2["mandate.authorization.Check"]
        cmd36["mandate.graph.DeregisterResource"]
        cmd37["mandate.graph.RegisterResource"]
        cmd38["mandate.graph.RemoveRelation"]
        cmd39["mandate.graph.RevokeGrant"]
        cmd40["mandate.graph.WriteRelationship"]
        cmd46["mandate.policy.SupersedeAuthorizationModel"]
        cmd47["mandate.policy.SupersedePolicy"]
        evt7["mandate.authorization.DecisionRecorded"]
        evt46["mandate.graph.GrantRevoked"]
        evt47["mandate.graph.RelationRemoved"]
        evt48["mandate.graph.RelationshipWritten"]
        evt49["mandate.graph.ResourceDeregistered"]
        evt50["mandate.graph.ResourceRegistered"]
        evt59["mandate.policy.AuthorizationModelSuperseded"]
        evt60["mandate.policy.PolicySuperseded"]
    end
    subgraph unit1["mandate-control-plane"]
        cmd14["mandate.delegation.CompleteExecution"]
        cmd15["mandate.delegation.ConsumeApproval"]
        cmd16["mandate.delegation.CreateDelegation"]
        cmd17["mandate.delegation.RetireAgent"]
        cmd18["mandate.delegation.RevokeDelegation"]
        cmd19["mandate.delegation.SupersedeAgentCapabilityCeiling"]
        cmd20["mandate.directory.CompleteSyncJob"]
        cmd21["mandate.directory.CreateDirectoryGroupTeamMapping"]
        cmd22["mandate.directory.FailSyncJob"]
        cmd23["mandate.directory.RemoveDirectoryGroupMembership"]
        cmd24["mandate.directory.RemoveDirectoryGroupTeamMapping"]
        cmd25["mandate.directory.RemoveMembershipContribution"]
        cmd26["mandate.directory.RetireDirectoryGroup"]
        cmd27["mandate.directory.SyncDirectoryMembership"]
        cmd28["mandate.federation.AuthenticateFederation"]
        cmd29["mandate.federation.AuthorizePublicClient"]
        cmd30["mandate.federation.DisableFederationConnection"]
        cmd31["mandate.federation.DisableOAuthClient"]
        cmd32["mandate.federation.LinkExternalPrincipal"]
        cmd33["mandate.federation.ProvisionExternalPrincipal"]
        cmd34["mandate.federation.RegisterFederationConnection"]
        cmd35["mandate.federation.UnlinkExternalPrincipal"]
        cmd41["mandate.identity.DisablePrincipal"]
        cmd42["mandate.identity.IncrementSecurityEpoch"]
        cmd43["mandate.identity.RefreshSession"]
        cmd44["mandate.identity.RevokeRefreshCredential"]
        cmd45["mandate.identity.RevokeSession"]
        cmd48["mandate.tenancy.AddOrganizationMembership"]
        cmd49["mandate.tenancy.AddTeamMembership"]
        cmd50["mandate.tenancy.CloseOrganization"]
        cmd51["mandate.tenancy.CreateOrganization"]
        cmd52["mandate.tenancy.CreateSpace"]
        cmd53["mandate.tenancy.CreateTeam"]
        cmd54["mandate.tenancy.RemoveOrganizationMembership"]
        cmd55["mandate.tenancy.RemoveTeamMembership"]
        cmd56["mandate.tenancy.RetireSpace"]
        cmd57["mandate.tenancy.RetireTeam"]
        cmd58["mandate.workload.RevokeWorkloadIdentity"]
        evt20["mandate.delegation.AgentCapabilityCeilingSuperseded"]
        evt21["mandate.delegation.AgentRetired"]
        evt22["mandate.delegation.ApprovalConsumed"]
        evt23["mandate.delegation.DelegationCreated"]
        evt24["mandate.delegation.DelegationRevoked"]
        evt25["mandate.delegation.ExecutionCompleted"]
        evt26["mandate.directory.DirectoryGroupMembershipChanged"]
        evt27["mandate.directory.DirectoryGroupMembershipRecorded"]
        evt28["mandate.directory.DirectoryGroupMembershipRemoved"]
        evt29["mandate.directory.DirectoryGroupRecorded"]
        evt30["mandate.directory.DirectoryGroupRetired"]
        evt31["mandate.directory.DirectoryGroupTeamMappingCreated"]
        evt32["mandate.directory.DirectoryGroupTeamMappingRemoved"]
        evt33["mandate.directory.MembershipContributionRecorded"]
        evt34["mandate.directory.MembershipContributionRemoved"]
        evt35["mandate.directory.SyncJobCompleted"]
        evt36["mandate.directory.SyncJobFailed"]
        evt37["mandate.directory.SyncJobRecorded"]
        evt38["mandate.federation.AuthorizationCodeIssued"]
        evt39["mandate.federation.ExternalPrincipalLinked"]
        evt40["mandate.federation.ExternalPrincipalProvisioned"]
        evt41["mandate.federation.ExternalPrincipalUnlinked"]
        evt42["mandate.federation.FederationAuthenticated"]
        evt43["mandate.federation.FederationConnectionCreated"]
        evt44["mandate.federation.FederationConnectionDisabled"]
        evt45["mandate.federation.OAuthClientDisabled"]
        evt51["mandate.identity.EpochSnapshotRecorded"]
        evt52["mandate.identity.PrincipalDisabled"]
        evt53["mandate.identity.RefreshCredentialRevoked"]
        evt54["mandate.identity.SecurityEpochIncremented"]
        evt55["mandate.identity.SecurityEpochRecorded"]
        evt56["mandate.identity.SessionOpened"]
        evt57["mandate.identity.SessionRefreshed"]
        evt58["mandate.identity.SessionRevoked"]
        evt61["mandate.tenancy.OrganizationClosed"]
        evt62["mandate.tenancy.OrganizationCreated"]
        evt63["mandate.tenancy.OrganizationMembershipAdded"]
        evt64["mandate.tenancy.OrganizationMembershipRemoved"]
        evt65["mandate.tenancy.SpaceCreated"]
        evt66["mandate.tenancy.SpaceRetired"]
        evt67["mandate.tenancy.TeamCreated"]
        evt68["mandate.tenancy.TeamMembershipAdded"]
        evt69["mandate.tenancy.TeamMembershipRemoved"]
        evt70["mandate.tenancy.TeamRetired"]
        evt71["mandate.workload.WorkloadIdentityRevoked"]
    end
    subgraph unit2["mandate-sts"]
        cmd3["mandate.credential.DisableResourceServer"]
        cmd4["mandate.credential.ExchangeCredential"]
        cmd5["mandate.credential.IntrospectCredential"]
        cmd6["mandate.credential.IssueAuthorizationCode"]
        cmd7["mandate.credential.IssueReferenceCredential"]
        cmd8["mandate.credential.IssueSelfContainedCredential"]
        cmd9["mandate.credential.RedeemAuthorizationCode"]
        cmd10["mandate.credential.RegisterResourceServer"]
        cmd11["mandate.credential.RetireSigningKey"]
        cmd12["mandate.credential.RevokeAccessCredential"]
        cmd13["mandate.credential.RevokeSigningKey"]
        evt8["mandate.credential.AccessCredentialRevoked"]
        evt9["mandate.credential.AuthorizationCodeIssued"]
        evt10["mandate.credential.AuthorizationCodeRedeemed"]
        evt11["mandate.credential.CredentialIntrospected"]
        evt12["mandate.credential.CredentialReferenceIssued"]
        evt13["mandate.credential.CredentialSelfContainedIssued"]
        evt14["mandate.credential.ResourceServerDisabled"]
        evt15["mandate.credential.ResourceServerRegistered"]
        evt16["mandate.credential.SigningKeyRetired"]
        evt17["mandate.credential.SigningKeyRevoked"]
        evt18["mandate.credential.TokenExchangeAllowed"]
        evt19["mandate.credential.TokenExchangeDenied"]
    end
    subgraph unit3["mandate-worker"]
        cmd0["mandate.audit.RecordAuditEvent"]
        cmd1["mandate.audit.RedactAuditEvent"]
        evt0["mandate.audit.AuditEventRecorded"]
        evt1["mandate.audit.AuditEventRedacted"]
        evt2["mandate.audit.CredentialRevoked"]
        evt3["mandate.audit.DirectoryGroupCreated"]
        evt4["mandate.audit.ExternalPrincipalUnlinked"]
        evt5["mandate.audit.FederationConnectionChanged"]
        evt6["mandate.audit.TokenExchangeDenied"]
    end
    cmd0 -->|"recorded"| evt0
    cmd1 -->|"accepted"| evt1
    cmd2 -->|"accepted"| evt7
    cmd3 -->|"accepted"| evt14
    cmd4 -->|"accepted"| evt18
    cmd5 -->|"accepted"| evt11
    cmd6 -->|"accepted"| evt9
    cmd7 -->|"accepted"| evt12
    cmd8 -->|"accepted"| evt13
    cmd9 -->|"accepted"| evt10
    cmd10 -->|"accepted"| evt15
    cmd11 -->|"accepted"| evt16
    cmd12 -->|"accepted"| evt8
    cmd13 -->|"accepted"| evt17
    cmd14 -->|"accepted"| evt25
    cmd15 -->|"accepted"| evt22
    cmd16 -->|"accepted"| evt23
    cmd17 -->|"accepted"| evt21
    cmd18 -->|"accepted"| evt24
    cmd19 -->|"accepted"| evt20
    cmd20 -->|"accepted"| evt35
    cmd21 -->|"accepted"| evt31
    cmd22 -->|"accepted"| evt36
    cmd23 -->|"accepted"| evt28
    cmd24 -->|"accepted"| evt32
    cmd25 -->|"accepted"| evt34
    cmd26 -->|"accepted"| evt30
    cmd27 -->|"accepted"| evt26
    cmd28 -->|"accepted"| evt42
    cmd29 -->|"accepted"| evt38
    cmd30 -->|"accepted"| evt44
    cmd31 -->|"accepted"| evt45
    cmd32 -->|"accepted"| evt39
    cmd33 -->|"accepted"| evt40
    cmd34 -->|"accepted"| evt43
    cmd35 -->|"accepted"| evt41
    cmd36 -->|"accepted"| evt49
    cmd37 -->|"accepted"| evt50
    cmd38 -->|"accepted"| evt47
    cmd39 -->|"accepted"| evt46
    cmd40 -->|"accepted"| evt48
    cmd41 -->|"accepted"| evt52
    cmd42 -->|"accepted"| evt54
    cmd43 -->|"accepted"| evt57
    cmd44 -->|"accepted"| evt53
    cmd45 -->|"accepted"| evt58
    cmd46 -->|"accepted"| evt59
    cmd47 -->|"accepted"| evt60
    cmd48 -->|"accepted"| evt63
    cmd49 -->|"accepted"| evt68
    cmd50 -->|"accepted"| evt61
    cmd51 -->|"accepted"| evt62
    cmd52 -->|"accepted"| evt65
    cmd53 -->|"accepted"| evt67
    cmd54 -->|"accepted"| evt64
    cmd55 -->|"accepted"| evt69
    cmd56 -->|"accepted"| evt66
    cmd57 -->|"accepted"| evt70
    cmd58 -->|"accepted"| evt71
```

A command is accepted by the component that owns its context, emits the events one of its outcomes declares, and a dashed edge is a binding carrying an event into the next command. Design §9 begins one step earlier, at the actor who invokes the first command, and so does this graph: a solid edge out of an actor is a grant, and an actor drawn with no edge at all may invoke nothing — which is something the model says, not an arrow somebody forgot.

## Bounded contexts

- **[audit](domains/mandate-audit.md)** (`mandate.audit`) — Canonical redacted audit records and the trusted worker append port. UNMAPPED-AUDIT-ROUTING: per-domain event mapping, durable outbox transport, the concrete retention floor and failure policy remain required; retention itself is redaction, never deletion. Named AuditAction and AuditOutcome do not admit arbitrary values. No types, one entity, no views, two commands, seven events, one error and no actors.
- **[authorization](domains/mandate-authorization.md)** (`mandate.authorization`) No types, no entities, no views, one command, one event, one error and no actors.
- **[core](domains/mandate-core.md)** (`mandate.core`) 74 types, no entities, no views, no commands, no events, no errors and no actors.
- **[credential](domains/mandate-credential.md)** (`mandate.credential`) No types, four entities, no views, 11 commands, 12 events, one error and no actors.
- **[delegation](domains/mandate-delegation.md)** (`mandate.delegation`) No types, five entities, no views, six commands, six events, one error and no actors.
- **[directory](domains/mandate-directory.md)** (`mandate.directory`) No types, five entities, no views, eight commands, 12 events, one error and no actors.
- **[federation](domains/mandate-federation.md)** (`mandate.federation`) No types, three entities, no views, eight commands, eight events, one error and no actors.
- **[graph](domains/mandate-graph.md)** (`mandate.graph`) — Resource topology, tagged principal-or-team relationship subjects and grants. UNMAPPED-SUBJECT-RELATIONS: ESS cannot select a union branch as a relation carrier. Each chosen principal/team branch references exactly one existing target; conditional foreign-key and tenant membership validation remain required before graph runtime admission. No types, three entities, no views, five commands, five events, one error and no actors.
- **[identity](domains/mandate-identity.md)** (`mandate.identity`) — Principal, session and independent principal/organization/federation generation ownership. UNMAPPED-EPOCH: each generation record declares one non-negative Integer generation, the recorded stand-in for the addendum's u64; monotonic increment, denial at the maximum and per-dimension snapshot values are absent until supported. EpochSnapshotRef is an immutable record handle, not a generation number. Refresh and exchange cannot be implemented without closing this blocker. No types, seven entities, no views, five commands, eight events, one error and no actors.
- **[policy](domains/mandate-policy.md)** (`mandate.policy`) No types, two entities, no views, two commands, two events, one error and no actors.
- **[tenancy](domains/mandate-tenancy.md)** (`mandate.tenancy`) No types, five entities, no views, 10 commands, 10 events, one error and no actors.
- **[workload](domains/mandate-workload.md)** (`mandate.workload`) No types, one entity, no views, one command, one event, one error and no actors.

## Components

A component is a unit of ownership, not a deployment. How many of each runs, and what each needs, is [the topology](topology.md).

**`mandate-authorization`** — Planned deployment boundary; exact domain-to-library responsibilities and required adapter/worker gaps are recorded in docs/architecture/ownership.md. It owns [`mandate.authorization`](domains/mandate-authorization.md), [`mandate.graph`](domains/mandate-graph.md) and [`mandate.policy`](domains/mandate-policy.md). It accepts `mandate.authorization.Check`, `mandate.graph.DeregisterResource`, `mandate.graph.RegisterResource`, `mandate.graph.RemoveRelation`, `mandate.graph.RevokeGrant`, `mandate.graph.WriteRelationship`, `mandate.policy.SupersedeAuthorizationModel` and `mandate.policy.SupersedePolicy`. It publishes `mandate.authorization.DecisionRecorded`, `mandate.graph.GrantRevoked`, `mandate.graph.RelationRemoved`, `mandate.graph.RelationshipWritten`, `mandate.graph.ResourceDeregistered`, `mandate.graph.ResourceRegistered`, `mandate.policy.AuthorizationModelSuperseded` and `mandate.policy.PolicySuperseded`.

**`mandate-control-plane`** — Administrative deployment and documentation publisher for the shared mandate.core vocabulary. All four deployments compile those shared library types; core is not a remote control-plane runtime dependency. See docs/architecture/ownership.md. It owns [`mandate.core`](domains/mandate-core.md), [`mandate.delegation`](domains/mandate-delegation.md), [`mandate.directory`](domains/mandate-directory.md), [`mandate.federation`](domains/mandate-federation.md), [`mandate.identity`](domains/mandate-identity.md), [`mandate.tenancy`](domains/mandate-tenancy.md) and [`mandate.workload`](domains/mandate-workload.md). It accepts `mandate.delegation.CompleteExecution`, `mandate.delegation.ConsumeApproval`, `mandate.delegation.CreateDelegation`, `mandate.delegation.RetireAgent`, `mandate.delegation.RevokeDelegation`, `mandate.delegation.SupersedeAgentCapabilityCeiling`, `mandate.directory.CompleteSyncJob`, `mandate.directory.CreateDirectoryGroupTeamMapping`, `mandate.directory.FailSyncJob`, `mandate.directory.RemoveDirectoryGroupMembership`, `mandate.directory.RemoveDirectoryGroupTeamMapping`, `mandate.directory.RemoveMembershipContribution`, `mandate.directory.RetireDirectoryGroup`, `mandate.directory.SyncDirectoryMembership`, `mandate.federation.AuthenticateFederation`, `mandate.federation.AuthorizePublicClient`, `mandate.federation.DisableFederationConnection`, `mandate.federation.DisableOAuthClient`, `mandate.federation.LinkExternalPrincipal`, `mandate.federation.ProvisionExternalPrincipal`, `mandate.federation.RegisterFederationConnection`, `mandate.federation.UnlinkExternalPrincipal`, `mandate.identity.DisablePrincipal`, `mandate.identity.IncrementSecurityEpoch`, `mandate.identity.RefreshSession`, `mandate.identity.RevokeRefreshCredential`, `mandate.identity.RevokeSession`, `mandate.tenancy.AddOrganizationMembership`, `mandate.tenancy.AddTeamMembership`, `mandate.tenancy.CloseOrganization`, `mandate.tenancy.CreateOrganization`, `mandate.tenancy.CreateSpace`, `mandate.tenancy.CreateTeam`, `mandate.tenancy.RemoveOrganizationMembership`, `mandate.tenancy.RemoveTeamMembership`, `mandate.tenancy.RetireSpace`, `mandate.tenancy.RetireTeam` and `mandate.workload.RevokeWorkloadIdentity`. It publishes `mandate.delegation.AgentCapabilityCeilingSuperseded`, `mandate.delegation.AgentRetired`, `mandate.delegation.ApprovalConsumed`, `mandate.delegation.DelegationCreated`, `mandate.delegation.DelegationRevoked`, `mandate.delegation.ExecutionCompleted`, `mandate.directory.DirectoryGroupMembershipChanged`, `mandate.directory.DirectoryGroupMembershipRecorded`, `mandate.directory.DirectoryGroupMembershipRemoved`, `mandate.directory.DirectoryGroupRecorded`, `mandate.directory.DirectoryGroupRetired`, `mandate.directory.DirectoryGroupTeamMappingCreated`, `mandate.directory.DirectoryGroupTeamMappingRemoved`, `mandate.directory.MembershipContributionRecorded`, `mandate.directory.MembershipContributionRemoved`, `mandate.directory.SyncJobCompleted`, `mandate.directory.SyncJobFailed`, `mandate.directory.SyncJobRecorded`, `mandate.federation.AuthorizationCodeIssued`, `mandate.federation.ExternalPrincipalLinked`, `mandate.federation.ExternalPrincipalProvisioned`, `mandate.federation.ExternalPrincipalUnlinked`, `mandate.federation.FederationAuthenticated`, `mandate.federation.FederationConnectionCreated`, `mandate.federation.FederationConnectionDisabled`, `mandate.federation.OAuthClientDisabled`, `mandate.identity.EpochSnapshotRecorded`, `mandate.identity.PrincipalDisabled`, `mandate.identity.RefreshCredentialRevoked`, `mandate.identity.SecurityEpochIncremented`, `mandate.identity.SecurityEpochRecorded`, `mandate.identity.SessionOpened`, `mandate.identity.SessionRefreshed`, `mandate.identity.SessionRevoked`, `mandate.tenancy.OrganizationClosed`, `mandate.tenancy.OrganizationCreated`, `mandate.tenancy.OrganizationMembershipAdded`, `mandate.tenancy.OrganizationMembershipRemoved`, `mandate.tenancy.SpaceCreated`, `mandate.tenancy.SpaceRetired`, `mandate.tenancy.TeamCreated`, `mandate.tenancy.TeamMembershipAdded`, `mandate.tenancy.TeamMembershipRemoved`, `mandate.tenancy.TeamRetired` and `mandate.workload.WorkloadIdentityRevoked`.

**`mandate-sts`** — Planned deployment boundary; exact domain-to-library responsibilities and required adapter/worker gaps are recorded in docs/architecture/ownership.md. It owns [`mandate.credential`](domains/mandate-credential.md). It accepts `mandate.credential.DisableResourceServer`, `mandate.credential.ExchangeCredential`, `mandate.credential.IntrospectCredential`, `mandate.credential.IssueAuthorizationCode`, `mandate.credential.IssueReferenceCredential`, `mandate.credential.IssueSelfContainedCredential`, `mandate.credential.RedeemAuthorizationCode`, `mandate.credential.RegisterResourceServer`, `mandate.credential.RetireSigningKey`, `mandate.credential.RevokeAccessCredential` and `mandate.credential.RevokeSigningKey`. It publishes `mandate.credential.AccessCredentialRevoked`, `mandate.credential.AuthorizationCodeIssued`, `mandate.credential.AuthorizationCodeRedeemed`, `mandate.credential.CredentialIntrospected`, `mandate.credential.CredentialReferenceIssued`, `mandate.credential.CredentialSelfContainedIssued`, `mandate.credential.ResourceServerDisabled`, `mandate.credential.ResourceServerRegistered`, `mandate.credential.SigningKeyRetired`, `mandate.credential.SigningKeyRevoked`, `mandate.credential.TokenExchangeAllowed` and `mandate.credential.TokenExchangeDenied`.

**`mandate-worker`** — Planned deployment boundary; exact domain-to-library responsibilities and required adapter/worker gaps are recorded in docs/architecture/ownership.md. It owns [`mandate.audit`](domains/mandate-audit.md). It accepts `mandate.audit.RecordAuditEvent` and `mandate.audit.RedactAuditEvent`. It publishes `mandate.audit.AuditEventRecorded`, `mandate.audit.AuditEventRedacted`, `mandate.audit.CredentialRevoked`, `mandate.audit.DirectoryGroupCreated`, `mandate.audit.ExternalPrincipalUnlinked`, `mandate.audit.FederationConnectionChanged` and `mandate.audit.TokenExchangeDenied`.

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

Generated from mandate v1 · model digest `01de9945d788263e9f6df566e556a0cc122f96c94d48538ad2536276eac2bc74` · contract digest `6c11d73c4163491aff4557b9039bfea9cff5a87ff4bf652962d8e1f71763c1f0`. Do not edit this file; change the specification and regenerate it with `ess generate`.

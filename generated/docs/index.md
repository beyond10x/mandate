<!--
generated from mandate v1
model digest ded0d31021cab1a87f5b67d362eff74ee517472819b7625f254db142448cfa5a
contract digest ae7959e6b5cff007097186f617a36d2f55d6f7325a57f55ecbbccacc7b9e2a50
do not edit: regenerate with `ess generate`
-->

# mandate v1

Standalone identity, authorization and constrained credential contracts. Runtime enforcement and UNMAPPED semantics are explicit obligations.

## The system as a graph

```mermaid
flowchart TB
    subgraph unit0["mandate-authorization"]
        cmd2["mandate.authorization.Check"]
        cmd3["mandate.authorization.CheckWithApproval"]
        cmd39["mandate.graph.DeregisterResource"]
        cmd40["mandate.graph.RegisterResource"]
        cmd41["mandate.graph.RemoveRelation"]
        cmd42["mandate.graph.RevokeGrant"]
        cmd43["mandate.graph.WriteRelationship"]
        cmd49["mandate.policy.SupersedeAuthorizationModel"]
        cmd50["mandate.policy.SupersedePolicy"]
        evt7["mandate.authorization.ApprovedDecisionRecorded"]
        evt8["mandate.authorization.DecisionRecorded"]
        evt50["mandate.graph.GrantRevoked"]
        evt51["mandate.graph.RelationRemoved"]
        evt52["mandate.graph.RelationshipWritten"]
        evt53["mandate.graph.ResourceDeregistered"]
        evt54["mandate.graph.ResourceRegistered"]
        evt63["mandate.policy.AuthorizationModelSuperseded"]
        evt64["mandate.policy.PolicySuperseded"]
    end
    subgraph unit1["mandate-control-plane"]
        cmd16["mandate.delegation.CompleteExecution"]
        cmd17["mandate.delegation.ConsumeApproval"]
        cmd18["mandate.delegation.CreateDelegation"]
        cmd19["mandate.delegation.RetireAgent"]
        cmd20["mandate.delegation.RevokeDelegation"]
        cmd21["mandate.delegation.SupersedeAgentCapabilityCeiling"]
        cmd22["mandate.directory.CompleteSyncJob"]
        cmd23["mandate.directory.CreateDirectoryGroupTeamMapping"]
        cmd24["mandate.directory.FailSyncJob"]
        cmd25["mandate.directory.RemoveDirectoryGroupMembership"]
        cmd26["mandate.directory.RemoveDirectoryGroupTeamMapping"]
        cmd27["mandate.directory.RemoveMembershipContribution"]
        cmd28["mandate.directory.RetireDirectoryGroup"]
        cmd29["mandate.directory.SyncDirectoryMembership"]
        cmd30["mandate.federation.AuthenticateFederation"]
        cmd31["mandate.federation.AuthorizePublicClient"]
        cmd32["mandate.federation.DisableFederationConnection"]
        cmd33["mandate.federation.DisableOAuthClient"]
        cmd34["mandate.federation.LinkExternalPrincipal"]
        cmd35["mandate.federation.ProvisionExternalPrincipal"]
        cmd36["mandate.federation.RegisterFederationConnection"]
        cmd37["mandate.federation.RegisterOAuthClient"]
        cmd38["mandate.federation.UnlinkExternalPrincipal"]
        cmd44["mandate.identity.DisablePrincipal"]
        cmd45["mandate.identity.IncrementSecurityEpoch"]
        cmd46["mandate.identity.RefreshSession"]
        cmd47["mandate.identity.RevokeRefreshCredential"]
        cmd48["mandate.identity.RevokeSession"]
        cmd51["mandate.tenancy.AddOrganizationMembership"]
        cmd52["mandate.tenancy.AddTeamMembership"]
        cmd53["mandate.tenancy.CloseOrganization"]
        cmd54["mandate.tenancy.CreateOrganization"]
        cmd55["mandate.tenancy.CreateSpace"]
        cmd56["mandate.tenancy.CreateTeam"]
        cmd57["mandate.tenancy.RemoveOrganizationMembership"]
        cmd58["mandate.tenancy.RemoveTeamMembership"]
        cmd59["mandate.tenancy.RetireSpace"]
        cmd60["mandate.tenancy.RetireTeam"]
        cmd61["mandate.workload.AuthenticateWorkload"]
        cmd62["mandate.workload.RevokeWorkloadIdentity"]
        evt22["mandate.delegation.AgentCapabilityCeilingSuperseded"]
        evt23["mandate.delegation.AgentRetired"]
        evt24["mandate.delegation.ApprovalConsumed"]
        evt25["mandate.delegation.DelegationCreated"]
        evt26["mandate.delegation.DelegationRevoked"]
        evt27["mandate.delegation.ExecutionCompleted"]
        evt28["mandate.directory.DirectoryGroupMembershipChanged"]
        evt29["mandate.directory.DirectoryGroupMembershipRecorded"]
        evt30["mandate.directory.DirectoryGroupMembershipRemoved"]
        evt31["mandate.directory.DirectoryGroupRecorded"]
        evt32["mandate.directory.DirectoryGroupRetired"]
        evt33["mandate.directory.DirectoryGroupTeamMappingCreated"]
        evt34["mandate.directory.DirectoryGroupTeamMappingRemoved"]
        evt35["mandate.directory.MembershipContributionRecorded"]
        evt36["mandate.directory.MembershipContributionRemoved"]
        evt37["mandate.directory.SyncJobCompleted"]
        evt38["mandate.directory.SyncJobFailed"]
        evt39["mandate.directory.SyncJobRecorded"]
        evt40["mandate.federation.AuthorizationCodeIssued"]
        evt41["mandate.federation.ExternalPrincipalLinked"]
        evt42["mandate.federation.ExternalPrincipalProvisioned"]
        evt43["mandate.federation.ExternalPrincipalUnlinked"]
        evt44["mandate.federation.ExternalProfileObserved"]
        evt45["mandate.federation.FederationAuthenticated"]
        evt46["mandate.federation.FederationConnectionCreated"]
        evt47["mandate.federation.FederationConnectionDisabled"]
        evt48["mandate.federation.OAuthClientDisabled"]
        evt49["mandate.federation.OAuthClientRegistered"]
        evt55["mandate.identity.EpochSnapshotRecorded"]
        evt56["mandate.identity.PrincipalDisabled"]
        evt57["mandate.identity.RefreshCredentialRevoked"]
        evt58["mandate.identity.SecurityEpochIncremented"]
        evt59["mandate.identity.SecurityEpochRecorded"]
        evt60["mandate.identity.SessionOpened"]
        evt61["mandate.identity.SessionRefreshed"]
        evt62["mandate.identity.SessionRevoked"]
        evt65["mandate.tenancy.OrganizationClosed"]
        evt66["mandate.tenancy.OrganizationCreated"]
        evt67["mandate.tenancy.OrganizationMembershipAdded"]
        evt68["mandate.tenancy.OrganizationMembershipRemoved"]
        evt69["mandate.tenancy.SpaceCreated"]
        evt70["mandate.tenancy.SpaceRetired"]
        evt71["mandate.tenancy.TeamCreated"]
        evt72["mandate.tenancy.TeamMembershipAdded"]
        evt73["mandate.tenancy.TeamMembershipRemoved"]
        evt74["mandate.tenancy.TeamRetired"]
        evt75["mandate.workload.WorkloadAuthenticated"]
        evt76["mandate.workload.WorkloadIdentityRevoked"]
    end
    subgraph unit2["mandate-sts"]
        cmd4["mandate.credential.DisableResourceServer"]
        cmd5["mandate.credential.ExchangeCredential"]
        cmd6["mandate.credential.IntrospectCredential"]
        cmd7["mandate.credential.IssueAuthorizationCode"]
        cmd8["mandate.credential.IssueReferenceCredential"]
        cmd9["mandate.credential.IssueSelfContainedCredential"]
        cmd10["mandate.credential.RedeemAuthorizationCode"]
        cmd11["mandate.credential.RegisterResourceServer"]
        cmd12["mandate.credential.RegisterSigningKey"]
        cmd13["mandate.credential.RetireSigningKey"]
        cmd14["mandate.credential.RevokeAccessCredential"]
        cmd15["mandate.credential.RevokeSigningKey"]
        evt9["mandate.credential.AccessCredentialRevoked"]
        evt10["mandate.credential.AuthorizationCodeIssued"]
        evt11["mandate.credential.AuthorizationCodeRedeemed"]
        evt12["mandate.credential.CredentialIntrospected"]
        evt13["mandate.credential.CredentialReferenceIssued"]
        evt14["mandate.credential.CredentialSelfContainedIssued"]
        evt15["mandate.credential.ResourceServerDisabled"]
        evt16["mandate.credential.ResourceServerRegistered"]
        evt17["mandate.credential.SigningKeyRegistered"]
        evt18["mandate.credential.SigningKeyRetired"]
        evt19["mandate.credential.SigningKeyRevoked"]
        evt20["mandate.credential.TokenExchangeAllowed"]
        evt21["mandate.credential.TokenExchangeDenied"]
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
    cmd2 -->|"accepted"| evt8
    cmd3 -->|"accepted"| evt7
    cmd4 -->|"accepted"| evt15
    cmd5 -->|"accepted"| evt20
    cmd6 -->|"accepted"| evt12
    cmd7 -->|"accepted"| evt10
    cmd8 -->|"accepted"| evt13
    cmd9 -->|"accepted"| evt14
    cmd10 -->|"accepted"| evt11
    cmd11 -->|"accepted"| evt16
    cmd12 -->|"accepted"| evt17
    cmd13 -->|"accepted"| evt18
    cmd14 -->|"accepted"| evt9
    cmd15 -->|"accepted"| evt19
    cmd16 -->|"accepted"| evt27
    cmd17 -->|"accepted"| evt24
    cmd18 -->|"accepted"| evt25
    cmd19 -->|"accepted"| evt23
    cmd20 -->|"accepted"| evt26
    cmd21 -->|"accepted"| evt22
    cmd22 -->|"accepted"| evt37
    cmd23 -->|"accepted"| evt33
    cmd24 -->|"accepted"| evt38
    cmd25 -->|"accepted"| evt30
    cmd26 -->|"accepted"| evt34
    cmd27 -->|"accepted"| evt36
    cmd28 -->|"accepted"| evt32
    cmd29 -->|"accepted"| evt28
    cmd30 -->|"accepted"| evt45
    cmd30 -->|"accepted"| evt44
    cmd31 -->|"accepted"| evt40
    cmd32 -->|"accepted"| evt47
    cmd33 -->|"accepted"| evt48
    cmd34 -->|"accepted"| evt41
    cmd35 -->|"accepted"| evt42
    cmd36 -->|"accepted"| evt46
    cmd37 -->|"accepted"| evt49
    cmd38 -->|"accepted"| evt43
    cmd39 -->|"accepted"| evt53
    cmd40 -->|"accepted"| evt54
    cmd41 -->|"accepted"| evt51
    cmd42 -->|"accepted"| evt50
    cmd43 -->|"accepted"| evt52
    cmd44 -->|"accepted"| evt56
    cmd45 -->|"accepted"| evt58
    cmd46 -->|"accepted"| evt61
    cmd47 -->|"accepted"| evt57
    cmd48 -->|"accepted"| evt62
    cmd49 -->|"accepted"| evt63
    cmd50 -->|"accepted"| evt64
    cmd51 -->|"accepted"| evt67
    cmd52 -->|"accepted"| evt72
    cmd53 -->|"accepted"| evt65
    cmd54 -->|"accepted"| evt66
    cmd55 -->|"accepted"| evt69
    cmd56 -->|"accepted"| evt71
    cmd57 -->|"accepted"| evt68
    cmd58 -->|"accepted"| evt73
    cmd59 -->|"accepted"| evt70
    cmd60 -->|"accepted"| evt74
    cmd61 -->|"accepted"| evt75
    cmd62 -->|"accepted"| evt76
```

A command is accepted by the component that owns its context, emits the events one of its outcomes declares, and a dashed edge is a binding carrying an event into the next command. Design §9 begins one step earlier, at the actor who invokes the first command, and so does this graph: a solid edge out of an actor is a grant, and an actor drawn with no edge at all may invoke nothing — which is something the model says, not an arrow somebody forgot.

## Bounded contexts

- **[audit](domains/mandate-audit.md)** (`mandate.audit`) — Canonical redacted audit records and the trusted worker append port. UNMAPPED-AUDIT-ROUTING: per-domain event mapping, durable outbox transport, the concrete retention floor and failure policy remain required; retention itself is redaction, never deletion. Named AuditAction and AuditOutcome do not admit arbitrary values. No types, one entity, no views, two commands, seven events, one error and no actors.
- **[authorization](domains/mandate-authorization.md)** (`mandate.authorization`) No types, no entities, no views, two commands, two events, one error and no actors.
- **[core](domains/mandate-core.md)** (`mandate.core`) 77 types, no entities, no views, no commands, no events, no errors and no actors.
- **[credential](domains/mandate-credential.md)** (`mandate.credential`) No types, four entities, no views, 12 commands, 13 events, one error and no actors.
- **[delegation](domains/mandate-delegation.md)** (`mandate.delegation`) No types, five entities, no views, six commands, six events, one error and no actors.
- **[directory](domains/mandate-directory.md)** (`mandate.directory`) No types, five entities, no views, eight commands, 12 events, one error and no actors.
- **[federation](domains/mandate-federation.md)** (`mandate.federation`) No types, three entities, no views, nine commands, 10 events, one error and no actors.
- **[graph](domains/mandate-graph.md)** (`mandate.graph`) — Resource topology, tagged principal-or-team relationship subjects and grants. UNMAPPED-SUBJECT-RELATIONS: ESS cannot select a union branch as a relation carrier. Each chosen principal/team branch references exactly one existing target; conditional foreign-key and tenant membership validation remain required before graph runtime admission. No types, three entities, no views, five commands, five events, one error and no actors.
- **[identity](domains/mandate-identity.md)** (`mandate.identity`) — Principal, session and independent principal/organization/federation generation ownership. UNMAPPED-EPOCH: each generation record declares one non-negative Integer generation, the recorded stand-in for the addendum's u64; monotonic increment, denial at the maximum and per-dimension snapshot values are absent until supported. EpochSnapshotRef is an immutable record handle, not a generation number. Refresh and exchange cannot be implemented without closing this blocker. No types, seven entities, no views, five commands, eight events, one error and no actors.
- **[policy](domains/mandate-policy.md)** (`mandate.policy`) No types, two entities, no views, two commands, two events, one error and no actors.
- **[tenancy](domains/mandate-tenancy.md)** (`mandate.tenancy`) No types, five entities, no views, 10 commands, 10 events, one error and no actors.
- **[workload](domains/mandate-workload.md)** (`mandate.workload`) No types, one entity, no views, two commands, two events, one error and no actors.

## Components

A component is a unit of ownership, not a deployment. How many of each runs, and what each needs, is [the topology](topology.md).

**`mandate-authorization`** — Planned deployment boundary; exact domain-to-library responsibilities and required adapter/worker gaps are recorded in docs/architecture/ownership.md. It owns [`mandate.authorization`](domains/mandate-authorization.md), [`mandate.graph`](domains/mandate-graph.md) and [`mandate.policy`](domains/mandate-policy.md). It accepts `mandate.authorization.Check`, `mandate.authorization.CheckWithApproval`, `mandate.graph.DeregisterResource`, `mandate.graph.RegisterResource`, `mandate.graph.RemoveRelation`, `mandate.graph.RevokeGrant`, `mandate.graph.WriteRelationship`, `mandate.policy.SupersedeAuthorizationModel` and `mandate.policy.SupersedePolicy`. It publishes `mandate.authorization.ApprovedDecisionRecorded`, `mandate.authorization.DecisionRecorded`, `mandate.graph.GrantRevoked`, `mandate.graph.RelationRemoved`, `mandate.graph.RelationshipWritten`, `mandate.graph.ResourceDeregistered`, `mandate.graph.ResourceRegistered`, `mandate.policy.AuthorizationModelSuperseded` and `mandate.policy.PolicySuperseded`.

**`mandate-control-plane`** — Administrative deployment and documentation publisher for the shared mandate.core vocabulary. All four deployments compile those shared library types; core is not a remote control-plane runtime dependency. See docs/architecture/ownership.md. It owns [`mandate.core`](domains/mandate-core.md), [`mandate.delegation`](domains/mandate-delegation.md), [`mandate.directory`](domains/mandate-directory.md), [`mandate.federation`](domains/mandate-federation.md), [`mandate.identity`](domains/mandate-identity.md), [`mandate.tenancy`](domains/mandate-tenancy.md) and [`mandate.workload`](domains/mandate-workload.md). It accepts `mandate.delegation.CompleteExecution`, `mandate.delegation.ConsumeApproval`, `mandate.delegation.CreateDelegation`, `mandate.delegation.RetireAgent`, `mandate.delegation.RevokeDelegation`, `mandate.delegation.SupersedeAgentCapabilityCeiling`, `mandate.directory.CompleteSyncJob`, `mandate.directory.CreateDirectoryGroupTeamMapping`, `mandate.directory.FailSyncJob`, `mandate.directory.RemoveDirectoryGroupMembership`, `mandate.directory.RemoveDirectoryGroupTeamMapping`, `mandate.directory.RemoveMembershipContribution`, `mandate.directory.RetireDirectoryGroup`, `mandate.directory.SyncDirectoryMembership`, `mandate.federation.AuthenticateFederation`, `mandate.federation.AuthorizePublicClient`, `mandate.federation.DisableFederationConnection`, `mandate.federation.DisableOAuthClient`, `mandate.federation.LinkExternalPrincipal`, `mandate.federation.ProvisionExternalPrincipal`, `mandate.federation.RegisterFederationConnection`, `mandate.federation.RegisterOAuthClient`, `mandate.federation.UnlinkExternalPrincipal`, `mandate.identity.DisablePrincipal`, `mandate.identity.IncrementSecurityEpoch`, `mandate.identity.RefreshSession`, `mandate.identity.RevokeRefreshCredential`, `mandate.identity.RevokeSession`, `mandate.tenancy.AddOrganizationMembership`, `mandate.tenancy.AddTeamMembership`, `mandate.tenancy.CloseOrganization`, `mandate.tenancy.CreateOrganization`, `mandate.tenancy.CreateSpace`, `mandate.tenancy.CreateTeam`, `mandate.tenancy.RemoveOrganizationMembership`, `mandate.tenancy.RemoveTeamMembership`, `mandate.tenancy.RetireSpace`, `mandate.tenancy.RetireTeam`, `mandate.workload.AuthenticateWorkload` and `mandate.workload.RevokeWorkloadIdentity`. It publishes `mandate.delegation.AgentCapabilityCeilingSuperseded`, `mandate.delegation.AgentRetired`, `mandate.delegation.ApprovalConsumed`, `mandate.delegation.DelegationCreated`, `mandate.delegation.DelegationRevoked`, `mandate.delegation.ExecutionCompleted`, `mandate.directory.DirectoryGroupMembershipChanged`, `mandate.directory.DirectoryGroupMembershipRecorded`, `mandate.directory.DirectoryGroupMembershipRemoved`, `mandate.directory.DirectoryGroupRecorded`, `mandate.directory.DirectoryGroupRetired`, `mandate.directory.DirectoryGroupTeamMappingCreated`, `mandate.directory.DirectoryGroupTeamMappingRemoved`, `mandate.directory.MembershipContributionRecorded`, `mandate.directory.MembershipContributionRemoved`, `mandate.directory.SyncJobCompleted`, `mandate.directory.SyncJobFailed`, `mandate.directory.SyncJobRecorded`, `mandate.federation.AuthorizationCodeIssued`, `mandate.federation.ExternalPrincipalLinked`, `mandate.federation.ExternalPrincipalProvisioned`, `mandate.federation.ExternalPrincipalUnlinked`, `mandate.federation.ExternalProfileObserved`, `mandate.federation.FederationAuthenticated`, `mandate.federation.FederationConnectionCreated`, `mandate.federation.FederationConnectionDisabled`, `mandate.federation.OAuthClientDisabled`, `mandate.federation.OAuthClientRegistered`, `mandate.identity.EpochSnapshotRecorded`, `mandate.identity.PrincipalDisabled`, `mandate.identity.RefreshCredentialRevoked`, `mandate.identity.SecurityEpochIncremented`, `mandate.identity.SecurityEpochRecorded`, `mandate.identity.SessionOpened`, `mandate.identity.SessionRefreshed`, `mandate.identity.SessionRevoked`, `mandate.tenancy.OrganizationClosed`, `mandate.tenancy.OrganizationCreated`, `mandate.tenancy.OrganizationMembershipAdded`, `mandate.tenancy.OrganizationMembershipRemoved`, `mandate.tenancy.SpaceCreated`, `mandate.tenancy.SpaceRetired`, `mandate.tenancy.TeamCreated`, `mandate.tenancy.TeamMembershipAdded`, `mandate.tenancy.TeamMembershipRemoved`, `mandate.tenancy.TeamRetired`, `mandate.workload.WorkloadAuthenticated` and `mandate.workload.WorkloadIdentityRevoked`.

**`mandate-sts`** — Planned deployment boundary; exact domain-to-library responsibilities and required adapter/worker gaps are recorded in docs/architecture/ownership.md. It owns [`mandate.credential`](domains/mandate-credential.md). It accepts `mandate.credential.DisableResourceServer`, `mandate.credential.ExchangeCredential`, `mandate.credential.IntrospectCredential`, `mandate.credential.IssueAuthorizationCode`, `mandate.credential.IssueReferenceCredential`, `mandate.credential.IssueSelfContainedCredential`, `mandate.credential.RedeemAuthorizationCode`, `mandate.credential.RegisterResourceServer`, `mandate.credential.RegisterSigningKey`, `mandate.credential.RetireSigningKey`, `mandate.credential.RevokeAccessCredential` and `mandate.credential.RevokeSigningKey`. It publishes `mandate.credential.AccessCredentialRevoked`, `mandate.credential.AuthorizationCodeIssued`, `mandate.credential.AuthorizationCodeRedeemed`, `mandate.credential.CredentialIntrospected`, `mandate.credential.CredentialReferenceIssued`, `mandate.credential.CredentialSelfContainedIssued`, `mandate.credential.ResourceServerDisabled`, `mandate.credential.ResourceServerRegistered`, `mandate.credential.SigningKeyRegistered`, `mandate.credential.SigningKeyRetired`, `mandate.credential.SigningKeyRevoked`, `mandate.credential.TokenExchangeAllowed` and `mandate.credential.TokenExchangeDenied`.

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

Generated from mandate v1 · model digest `ded0d31021cab1a87f5b67d362eff74ee517472819b7625f254db142448cfa5a` · contract digest `ae7959e6b5cff007097186f617a36d2f55d6f7325a57f55ecbbccacc7b9e2a50`. Do not edit this file; change the specification and regenerate it with `ess generate`.

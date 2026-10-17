<!--
generated from mandate v1
model digest f5ac6bee950cad438d353c48a341683c9f73db710c6918a82fec4620d7806ea6
contract digest d89a65303b5e7f9c23896d4c74b861c7330eaa694d9cf4eea8b32f6832cfed16
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
        cmd51["mandate.policy.SupersedeAuthorizationModel"]
        cmd52["mandate.policy.SupersedePolicy"]
        evt7["mandate.authorization.ApprovedDecisionRecorded"]
        evt8["mandate.authorization.DecisionRecorded"]
        evt51["mandate.graph.GrantRevoked"]
        evt52["mandate.graph.RelationRemoved"]
        evt53["mandate.graph.RelationshipWritten"]
        evt54["mandate.graph.ResourceDeregistered"]
        evt55["mandate.graph.ResourceRegistered"]
        evt68["mandate.policy.AuthorizationModelSuperseded"]
        evt69["mandate.policy.PolicySuperseded"]
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
        cmd45["mandate.identity.DisablePrincipal"]
        cmd46["mandate.identity.IncrementSecurityEpoch"]
        cmd47["mandate.identity.RefreshSession"]
        cmd48["mandate.identity.RevokeRefreshCredential"]
        cmd49["mandate.identity.RevokeSession"]
        cmd50["mandate.identity.RotateRefreshCredential"]
        cmd53["mandate.tenancy.AddOrganizationMembership"]
        cmd54["mandate.tenancy.AddTeamMembership"]
        cmd55["mandate.tenancy.CloseOrganization"]
        cmd56["mandate.tenancy.CreateOrganization"]
        cmd57["mandate.tenancy.CreateSpace"]
        cmd58["mandate.tenancy.CreateTeam"]
        cmd59["mandate.tenancy.RemoveOrganizationMembership"]
        cmd60["mandate.tenancy.RemoveTeamMembership"]
        cmd61["mandate.tenancy.RetireSpace"]
        cmd62["mandate.tenancy.RetireTeam"]
        cmd63["mandate.workload.AuthenticateWorkload"]
        cmd64["mandate.workload.RevokeWorkloadIdentity"]
        evt23["mandate.delegation.AgentCapabilityCeilingSuperseded"]
        evt24["mandate.delegation.AgentRetired"]
        evt25["mandate.delegation.ApprovalConsumed"]
        evt26["mandate.delegation.DelegationCreated"]
        evt27["mandate.delegation.DelegationRevoked"]
        evt28["mandate.delegation.ExecutionCompleted"]
        evt29["mandate.directory.DirectoryGroupMembershipChanged"]
        evt30["mandate.directory.DirectoryGroupMembershipRecorded"]
        evt31["mandate.directory.DirectoryGroupMembershipRemoved"]
        evt32["mandate.directory.DirectoryGroupRecorded"]
        evt33["mandate.directory.DirectoryGroupRetired"]
        evt34["mandate.directory.DirectoryGroupTeamMappingCreated"]
        evt35["mandate.directory.DirectoryGroupTeamMappingRemoved"]
        evt36["mandate.directory.MembershipContributionRecorded"]
        evt37["mandate.directory.MembershipContributionRemoved"]
        evt38["mandate.directory.SyncJobCompleted"]
        evt39["mandate.directory.SyncJobFailed"]
        evt40["mandate.directory.SyncJobRecorded"]
        evt41["mandate.federation.AuthorizationCodeIssued"]
        evt42["mandate.federation.ExternalPrincipalLinked"]
        evt43["mandate.federation.ExternalPrincipalProvisioned"]
        evt44["mandate.federation.ExternalPrincipalUnlinked"]
        evt45["mandate.federation.ExternalProfileObserved"]
        evt46["mandate.federation.FederationAuthenticated"]
        evt47["mandate.federation.FederationConnectionCreated"]
        evt48["mandate.federation.FederationConnectionDisabled"]
        evt49["mandate.federation.OAuthClientDisabled"]
        evt50["mandate.federation.OAuthClientRegistered"]
        evt57["mandate.identity.EpochSnapshotRecorded"]
        evt58["mandate.identity.PrincipalDisabled"]
        evt59["mandate.identity.RefreshCredentialIssued"]
        evt60["mandate.identity.RefreshCredentialRevoked"]
        evt61["mandate.identity.RefreshCredentialRotated"]
        evt62["mandate.identity.RefreshFamilyRevoked"]
        evt63["mandate.identity.SecurityEpochIncremented"]
        evt64["mandate.identity.SecurityEpochRecorded"]
        evt65["mandate.identity.SessionOpened"]
        evt66["mandate.identity.SessionRefreshed"]
        evt67["mandate.identity.SessionRevoked"]
        evt70["mandate.tenancy.OrganizationClosed"]
        evt71["mandate.tenancy.OrganizationCreated"]
        evt72["mandate.tenancy.OrganizationMembershipAdded"]
        evt73["mandate.tenancy.OrganizationMembershipRemoved"]
        evt74["mandate.tenancy.SpaceCreated"]
        evt75["mandate.tenancy.SpaceRetired"]
        evt76["mandate.tenancy.TeamCreated"]
        evt77["mandate.tenancy.TeamMembershipAdded"]
        evt78["mandate.tenancy.TeamMembershipRemoved"]
        evt79["mandate.tenancy.TeamRetired"]
        evt80["mandate.workload.WorkloadAuthenticated"]
        evt81["mandate.workload.WorkloadIdentityRevoked"]
    end
    subgraph unit2["mandate-guard"]
        cmd44["mandate.guard.AdmitRequest"]
        evt56["mandate.guard.RequestAdmitted"]
    end
    subgraph unit3["mandate-sts"]
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
        evt15["mandate.credential.IdentityTokenIssued"]
        evt16["mandate.credential.ResourceServerDisabled"]
        evt17["mandate.credential.ResourceServerRegistered"]
        evt18["mandate.credential.SigningKeyRegistered"]
        evt19["mandate.credential.SigningKeyRetired"]
        evt20["mandate.credential.SigningKeyRevoked"]
        evt21["mandate.credential.TokenExchangeAllowed"]
        evt22["mandate.credential.TokenExchangeDenied"]
    end
    subgraph unit4["mandate-worker"]
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
    cmd4 -->|"accepted"| evt16
    cmd5 -->|"accepted"| evt21
    cmd6 -->|"accepted"| evt12
    cmd7 -->|"accepted"| evt10
    cmd8 -->|"accepted"| evt13
    cmd9 -->|"accepted"| evt14
    cmd10 -->|"accepted-with-identity-token"| evt11
    cmd10 -->|"accepted-with-identity-token"| evt15
    cmd10 -->|"accepted"| evt11
    cmd11 -->|"accepted"| evt17
    cmd12 -->|"accepted"| evt18
    cmd13 -->|"accepted"| evt19
    cmd14 -->|"accepted"| evt9
    cmd15 -->|"accepted"| evt20
    cmd16 -->|"accepted"| evt28
    cmd17 -->|"accepted"| evt25
    cmd18 -->|"accepted"| evt26
    cmd19 -->|"accepted"| evt24
    cmd20 -->|"accepted"| evt27
    cmd21 -->|"accepted"| evt23
    cmd22 -->|"accepted"| evt38
    cmd23 -->|"accepted"| evt34
    cmd24 -->|"accepted"| evt39
    cmd25 -->|"accepted"| evt31
    cmd26 -->|"accepted"| evt35
    cmd27 -->|"accepted"| evt37
    cmd28 -->|"accepted"| evt33
    cmd29 -->|"accepted"| evt29
    cmd30 -->|"accepted"| evt46
    cmd30 -->|"accepted"| evt45
    cmd31 -->|"accepted"| evt41
    cmd32 -->|"accepted"| evt48
    cmd33 -->|"accepted"| evt49
    cmd34 -->|"accepted"| evt42
    cmd35 -->|"accepted"| evt43
    cmd36 -->|"accepted"| evt47
    cmd37 -->|"accepted"| evt50
    cmd38 -->|"accepted"| evt44
    cmd39 -->|"accepted"| evt54
    cmd40 -->|"accepted"| evt55
    cmd41 -->|"accepted"| evt52
    cmd42 -->|"accepted"| evt51
    cmd43 -->|"accepted"| evt53
    cmd44 -->|"accepted"| evt56
    cmd45 -->|"accepted"| evt58
    cmd46 -->|"accepted"| evt63
    cmd47 -->|"accepted"| evt66
    cmd48 -->|"accepted"| evt60
    cmd49 -->|"accepted"| evt67
    cmd50 -->|"rotated"| evt61
    cmd50 -->|"grace-sibling"| evt61
    cmd50 -->|"reuse-detected"| evt62
    cmd51 -->|"accepted"| evt68
    cmd52 -->|"accepted"| evt69
    cmd53 -->|"accepted"| evt72
    cmd54 -->|"accepted"| evt77
    cmd55 -->|"accepted"| evt70
    cmd56 -->|"accepted"| evt71
    cmd57 -->|"accepted"| evt74
    cmd58 -->|"accepted"| evt76
    cmd59 -->|"accepted"| evt73
    cmd60 -->|"accepted"| evt78
    cmd61 -->|"accepted"| evt75
    cmd62 -->|"accepted"| evt79
    cmd63 -->|"accepted"| evt80
    cmd64 -->|"accepted"| evt81
```

A command is accepted by the component that owns its context, emits the events one of its outcomes declares, and a dashed edge is a binding carrying an event into the next command. Design §9 begins one step earlier, at the actor who invokes the first command, and so does this graph: a solid edge out of an actor is a grant, and an actor drawn with no edge at all may invoke nothing — which is something the model says, not an arrow somebody forgot.

## Bounded contexts

- **[audit](domains/mandate-audit.md)** (`mandate.audit`) — Canonical redacted audit records and the trusted worker append port. UNMAPPED-AUDIT-ROUTING: per-domain event mapping, durable outbox transport, the concrete retention floor and failure policy remain required; retention itself is redaction, never deletion. Named AuditAction and AuditOutcome do not admit arbitrary values. No types, one entity, no views, two commands, seven events, one error and no actors.
- **[authorization](domains/mandate-authorization.md)** (`mandate.authorization`) No types, no entities, no views, two commands, two events, one error and no actors.
- **[core](domains/mandate-core.md)** (`mandate.core`) 77 types, no entities, no views, no commands, no events, no errors and no actors.
- **[credential](domains/mandate-credential.md)** (`mandate.credential`) Three types, four entities, no views, 12 commands, 14 events, one error and no actors.
- **[delegation](domains/mandate-delegation.md)** (`mandate.delegation`) No types, five entities, no views, six commands, six events, one error and no actors.
- **[directory](domains/mandate-directory.md)** (`mandate.directory`) No types, five entities, no views, eight commands, 12 events, one error and no actors.
- **[federation](domains/mandate-federation.md)** (`mandate.federation`) No types, three entities, no views, nine commands, 10 events, one error and no actors.
- **[graph](domains/mandate-graph.md)** (`mandate.graph`) — Resource topology, tagged principal-or-team relationship subjects and grants. UNMAPPED-SUBJECT-RELATIONS: ESS cannot select a union branch as a relation carrier. Each chosen principal/team branch references exactly one existing target; conditional foreign-key and tenant membership validation remain required before graph runtime admission. No types, three entities, no views, five commands, five events, one error and no actors.
- **[guard](domains/mandate-guard.md)** (`mandate.guard`) Seven types, no entities, no views, one command, one event, one error and no actors.
- **[identity](domains/mandate-identity.md)** (`mandate.identity`) — Principal, session and independent principal/organization/federation generation ownership. UNMAPPED-EPOCH: each generation record declares one non-negative Integer generation, the recorded stand-in for the addendum's u64; monotonic increment, denial at the maximum and per-dimension snapshot values are absent until supported. EpochSnapshotRef is an immutable record handle, not a generation number. Refresh and exchange cannot be implemented without closing this blocker. One type, seven entities, no views, six commands, 11 events, one error and no actors.
- **[policy](domains/mandate-policy.md)** (`mandate.policy`) No types, two entities, no views, two commands, two events, one error and no actors.
- **[tenancy](domains/mandate-tenancy.md)** (`mandate.tenancy`) No types, five entities, no views, 10 commands, 10 events, one error and no actors.
- **[workload](domains/mandate-workload.md)** (`mandate.workload`) No types, one entity, no views, two commands, two events, one error and no actors.

## Components

A component is a unit of ownership, not a deployment. How many of each runs, and what each needs, is [the topology](topology.md).

**`mandate-authorization`** — Planned deployment boundary; exact domain-to-library responsibilities and required adapter/worker gaps are recorded in docs/architecture/ownership.md. It owns [`mandate.authorization`](domains/mandate-authorization.md), [`mandate.graph`](domains/mandate-graph.md) and [`mandate.policy`](domains/mandate-policy.md). It accepts `mandate.authorization.Check`, `mandate.authorization.CheckWithApproval`, `mandate.graph.DeregisterResource`, `mandate.graph.RegisterResource`, `mandate.graph.RemoveRelation`, `mandate.graph.RevokeGrant`, `mandate.graph.WriteRelationship`, `mandate.policy.SupersedeAuthorizationModel` and `mandate.policy.SupersedePolicy`. It publishes `mandate.authorization.ApprovedDecisionRecorded`, `mandate.authorization.DecisionRecorded`, `mandate.graph.GrantRevoked`, `mandate.graph.RelationRemoved`, `mandate.graph.RelationshipWritten`, `mandate.graph.ResourceDeregistered`, `mandate.graph.ResourceRegistered`, `mandate.policy.AuthorizationModelSuperseded` and `mandate.policy.PolicySuperseded`.

**`mandate-control-plane`** — Administrative deployment and documentation publisher for the shared mandate.core vocabulary. All four deployments compile those shared library types; core is not a remote control-plane runtime dependency. See docs/architecture/ownership.md. It owns [`mandate.core`](domains/mandate-core.md), [`mandate.delegation`](domains/mandate-delegation.md), [`mandate.directory`](domains/mandate-directory.md), [`mandate.federation`](domains/mandate-federation.md), [`mandate.identity`](domains/mandate-identity.md), [`mandate.tenancy`](domains/mandate-tenancy.md) and [`mandate.workload`](domains/mandate-workload.md). It accepts `mandate.delegation.CompleteExecution`, `mandate.delegation.ConsumeApproval`, `mandate.delegation.CreateDelegation`, `mandate.delegation.RetireAgent`, `mandate.delegation.RevokeDelegation`, `mandate.delegation.SupersedeAgentCapabilityCeiling`, `mandate.directory.CompleteSyncJob`, `mandate.directory.CreateDirectoryGroupTeamMapping`, `mandate.directory.FailSyncJob`, `mandate.directory.RemoveDirectoryGroupMembership`, `mandate.directory.RemoveDirectoryGroupTeamMapping`, `mandate.directory.RemoveMembershipContribution`, `mandate.directory.RetireDirectoryGroup`, `mandate.directory.SyncDirectoryMembership`, `mandate.federation.AuthenticateFederation`, `mandate.federation.AuthorizePublicClient`, `mandate.federation.DisableFederationConnection`, `mandate.federation.DisableOAuthClient`, `mandate.federation.LinkExternalPrincipal`, `mandate.federation.ProvisionExternalPrincipal`, `mandate.federation.RegisterFederationConnection`, `mandate.federation.RegisterOAuthClient`, `mandate.federation.UnlinkExternalPrincipal`, `mandate.identity.DisablePrincipal`, `mandate.identity.IncrementSecurityEpoch`, `mandate.identity.RefreshSession`, `mandate.identity.RevokeRefreshCredential`, `mandate.identity.RevokeSession`, `mandate.identity.RotateRefreshCredential`, `mandate.tenancy.AddOrganizationMembership`, `mandate.tenancy.AddTeamMembership`, `mandate.tenancy.CloseOrganization`, `mandate.tenancy.CreateOrganization`, `mandate.tenancy.CreateSpace`, `mandate.tenancy.CreateTeam`, `mandate.tenancy.RemoveOrganizationMembership`, `mandate.tenancy.RemoveTeamMembership`, `mandate.tenancy.RetireSpace`, `mandate.tenancy.RetireTeam`, `mandate.workload.AuthenticateWorkload` and `mandate.workload.RevokeWorkloadIdentity`. It publishes `mandate.delegation.AgentCapabilityCeilingSuperseded`, `mandate.delegation.AgentRetired`, `mandate.delegation.ApprovalConsumed`, `mandate.delegation.DelegationCreated`, `mandate.delegation.DelegationRevoked`, `mandate.delegation.ExecutionCompleted`, `mandate.directory.DirectoryGroupMembershipChanged`, `mandate.directory.DirectoryGroupMembershipRecorded`, `mandate.directory.DirectoryGroupMembershipRemoved`, `mandate.directory.DirectoryGroupRecorded`, `mandate.directory.DirectoryGroupRetired`, `mandate.directory.DirectoryGroupTeamMappingCreated`, `mandate.directory.DirectoryGroupTeamMappingRemoved`, `mandate.directory.MembershipContributionRecorded`, `mandate.directory.MembershipContributionRemoved`, `mandate.directory.SyncJobCompleted`, `mandate.directory.SyncJobFailed`, `mandate.directory.SyncJobRecorded`, `mandate.federation.AuthorizationCodeIssued`, `mandate.federation.ExternalPrincipalLinked`, `mandate.federation.ExternalPrincipalProvisioned`, `mandate.federation.ExternalPrincipalUnlinked`, `mandate.federation.ExternalProfileObserved`, `mandate.federation.FederationAuthenticated`, `mandate.federation.FederationConnectionCreated`, `mandate.federation.FederationConnectionDisabled`, `mandate.federation.OAuthClientDisabled`, `mandate.federation.OAuthClientRegistered`, `mandate.identity.EpochSnapshotRecorded`, `mandate.identity.PrincipalDisabled`, `mandate.identity.RefreshCredentialIssued`, `mandate.identity.RefreshCredentialRevoked`, `mandate.identity.RefreshCredentialRotated`, `mandate.identity.RefreshFamilyRevoked`, `mandate.identity.SecurityEpochIncremented`, `mandate.identity.SecurityEpochRecorded`, `mandate.identity.SessionOpened`, `mandate.identity.SessionRefreshed`, `mandate.identity.SessionRevoked`, `mandate.tenancy.OrganizationClosed`, `mandate.tenancy.OrganizationCreated`, `mandate.tenancy.OrganizationMembershipAdded`, `mandate.tenancy.OrganizationMembershipRemoved`, `mandate.tenancy.SpaceCreated`, `mandate.tenancy.SpaceRetired`, `mandate.tenancy.TeamCreated`, `mandate.tenancy.TeamMembershipAdded`, `mandate.tenancy.TeamMembershipRemoved`, `mandate.tenancy.TeamRetired`, `mandate.workload.WorkloadAuthenticated` and `mandate.workload.WorkloadIdentityRevoked`.

**`mandate-guard`** — The token guard of docs/adr/0013-token-guard.md. Today the library alone, verify in crates/mandate-client; the sidecar binary and its chart are planned under story:token-guard. It owns [`mandate.guard`](domains/mandate-guard.md). It accepts `mandate.guard.AdmitRequest`. It publishes `mandate.guard.RequestAdmitted`.

**`mandate-sts`** — Planned deployment boundary; exact domain-to-library responsibilities and required adapter/worker gaps are recorded in docs/architecture/ownership.md. It owns [`mandate.credential`](domains/mandate-credential.md). It accepts `mandate.credential.DisableResourceServer`, `mandate.credential.ExchangeCredential`, `mandate.credential.IntrospectCredential`, `mandate.credential.IssueAuthorizationCode`, `mandate.credential.IssueReferenceCredential`, `mandate.credential.IssueSelfContainedCredential`, `mandate.credential.RedeemAuthorizationCode`, `mandate.credential.RegisterResourceServer`, `mandate.credential.RegisterSigningKey`, `mandate.credential.RetireSigningKey`, `mandate.credential.RevokeAccessCredential` and `mandate.credential.RevokeSigningKey`. It publishes `mandate.credential.AccessCredentialRevoked`, `mandate.credential.AuthorizationCodeIssued`, `mandate.credential.AuthorizationCodeRedeemed`, `mandate.credential.CredentialIntrospected`, `mandate.credential.CredentialReferenceIssued`, `mandate.credential.CredentialSelfContainedIssued`, `mandate.credential.IdentityTokenIssued`, `mandate.credential.ResourceServerDisabled`, `mandate.credential.ResourceServerRegistered`, `mandate.credential.SigningKeyRegistered`, `mandate.credential.SigningKeyRetired`, `mandate.credential.SigningKeyRevoked`, `mandate.credential.TokenExchangeAllowed` and `mandate.credential.TokenExchangeDenied`.

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
| [guard](domains/mandate-guard.md) | the `mandate.guard` vocabulary: its types, entities, views, commands, events, errors and actors |
| [identity](domains/mandate-identity.md) | the `mandate.identity` vocabulary: its types, entities, views, commands, events, errors and actors |
| [policy](domains/mandate-policy.md) | the `mandate.policy` vocabulary: its types, entities, views, commands, events, errors and actors |
| [tenancy](domains/mandate-tenancy.md) | the `mandate.tenancy` vocabulary: its types, entities, views, commands, events, errors and actors |
| [workload](domains/mandate-workload.md) | the `mandate.workload` vocabulary: its types, entities, views, commands, events, errors and actors |
| [Interactions](interactions.md) | every binding, with what it guarantees and what happens when it fails |
| [Type crossings](crossings.md) | every conversion this system permits, and the reason someone gave for it |
| [Topology](topology.md) | what each component needs in order to run |


---

Generated from mandate v1 · model digest `f5ac6bee950cad438d353c48a341683c9f73db710c6918a82fec4620d7806ea6` · contract digest `d89a65303b5e7f9c23896d4c74b861c7330eaa694d9cf4eea8b32f6832cfed16`. Do not edit this file; change the specification and regenerate it with `ess generate`.

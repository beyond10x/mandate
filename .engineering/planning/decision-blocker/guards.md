---
format: aep.planning-md/3
id: decision-blocker:guards
kind: decision-blocker
status: open
title: UNMAPPED-GUARDS
relations:
- blocks: story:protocol-adapters
- blocks: story:audit-client
- blocks: story:credential-context-guards
revision: 2
---
ESS command outcomes describe authoritative external validation, not executable cryptographic, graph or policy predicates. Add trusted context adapter, actual validation and negative conformance tests; generated command routes must never be exposed as product endpoints.

Source: `docs/architecture/unmapped.md`. Clear only with reviewed concrete semantics and evidence.

## Deferred clauses

The 34 clauses of `contracts/obligations/*.json` that name this blocker in `blocked_on` and are bound to no test, as of 2026-10-15 (audit G-28; seven more name it and carry a test). Each is quoted verbatim from its command's declared cause.

**Caller authority (20).** The command's decider takes a `VerifiedContext` and decides the record's own guards; whether that caller holds the administrative authority the clause names is a `mandate.authorization.Check` question, and no composition asks it before dispatching the command — the served composition routes only the login and OAuth commands, and none of these. Deciding it needs the trusted context adapter this blocker names. `story:caller-authority-off-guards` takes these off this blocker.

- `model.json` `mandate.tenancy.AddOrganizationMembership`: "Caller lacks membership-administration authority"
- `model.json` `mandate.tenancy.AddOrganizationMembership`: "the caller lacks platform organization-administration authority"
- `model.json` `mandate.tenancy.AddTeamMembership`: "Caller lacks team-administration authority"
- `model.json` `mandate.tenancy.CloseOrganization`: "Caller lacks platform organization-administration authority"
- `model.json` `mandate.tenancy.CreateOrganization`: "Caller lacks platform organization-administration authority"
- `model.json` `mandate.tenancy.CreateSpace`: "Caller lacks space-administration authority"
- `model.json` `mandate.tenancy.CreateTeam`: "Caller lacks team-administration authority"
- `model.json` `mandate.tenancy.RemoveOrganizationMembership`: "Caller lacks membership-administration authority"
- `model.json` `mandate.tenancy.RemoveTeamMembership`: "Caller lacks team-administration authority"
- `model.json` `mandate.tenancy.RetireSpace`: "Caller lacks space-administration authority"
- `model.json` `mandate.tenancy.RetireTeam`: "Caller lacks team-administration authority"
- `model.json` `mandate.workload.RevokeWorkloadIdentity`: "Caller lacks workload-identity administration authority"
- `identity.json` `mandate.identity.IncrementSecurityEpoch`: "Caller lacks authority for the explicitly selected principal/organization/federation target"
- `identity.json` `mandate.identity.RevokeSession`: "Caller lacks authority over this session"
- `sts.json` `mandate.credential.DisableResourceServer`: "Caller lacks resource-server administration authority"
- `sts.json` `mandate.credential.RegisterResourceServer`: "Caller lacks resource-server administration authority"
- `sts.json` `mandate.credential.RegisterSigningKey`: "Caller lacks platform signing-key administration authority"
- `sts.json` `mandate.credential.RetireSigningKey`: "Caller lacks platform signing-key administration authority"
- `sts.json` `mandate.credential.RevokeSigningKey`: "Caller lacks platform signing-key administration authority"
- `sts.json` `mandate.credential.RevokeAccessCredential`: "Caller lacks credential-revocation authority"

**Credential-derived context (10).** The decider receives a context, session or proof that was verified before it is reached; no credential, refresh verifier or session proof arrives for it to validate again. The validation is the trusted context adapter's, which this blocker names. `story:credential-context-guards` takes the five `Check` conditions off this blocker.

- `authz.json` `mandate.authorization.Check`: "Credential-derived context is invalid"
- `authz.json` `mandate.authorization.Check`: "revoked"
- `authz.json` `mandate.authorization.Check`: "expired"
- `authz.json` `mandate.authorization.Check`: "stale"
- `authz.json` `mandate.authorization.Check`: "credential authority is unavailable"
- `identity.json` `mandate.identity.RefreshSession`: "Refresh verifier is absent/incorrect" (`refresh_session` presumes the refresh proof was verified by the credential domain before it is reached)
- `sts.json` `mandate.credential.IntrospectCredential`: "principal/connection/epoch validation fails"
- `sts.json` `mandate.credential.IssueAuthorizationCode`: "Trusted control-plane caller/session context"
- `sts.json` `mandate.credential.IssueReferenceCredential`: "Validated context is expired/revoked/stale"
- `sts.json` `mandate.credential.IssueSelfContainedCredential`: "Validated context is expired/revoked/stale"

**Admission predicates (3).** The contract declares no admitted display-name vocabulary; whether a name is admitted is external validation ESS does not express, and none is invented.

- `model.json` `mandate.tenancy.CreateOrganization`: "the requested display name is not admitted"
- `model.json` `mandate.tenancy.CreateSpace`: "the display name is not admitted in the verified organization"
- `model.json` `mandate.tenancy.CreateTeam`: "the display name is not admitted in the verified organization"

**Delegator authority (1).**

- `authz.json` `mandate.delegation.CreateDelegation`: "requested scope/expiry exceeds source/delegation/policy limits" — the delegator's own authority is the graph's and is not read by `decide_create_delegation`; policy and the agent ceilings are read under sibling clauses (`crates/mandate-authz/src/command.rs`, "Every denial clause this module does not realize").

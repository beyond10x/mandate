---
format: aep.planning-md/3
id: story:unknown-instance-non-disclosing
kind: story
status: draft
title: The unknown-instance scenarios expect the refusal that does not disclose existence
relations:
- decomposes: epic:foundations
- serves: vision:mandate
revision: 1
---
# The unknown-instance scenarios expect the refusal that does not disclose existence

## Why

Under `ess/24` a command may declare `unknown_instance:`, and the synthesized `<Command>/outcome/unknown-instance` scenario then expects that outcome by name. ESS 0.59.0 admits the declaration only on an outcome of its own (`ESS-COMMAND-004` refuses it on `denied`). Mandate answers an identity no record carries exactly like a record the caller may not see, so a caller cannot probe which records exist: an unknown authorization code refuses like a wrong proof (`services/sts/src/redemption.rs`), tenancy and graph refuse "no such record" and "not yours" alike (`crates/mandate-model/tests`, `a_record_in_another_organization_refuses_exactly_as_an_unrecorded_one_does`), and an unknown session refuses like another organization's (`crates/mandate-identity/src/session.rs`, `revoke_session`). A separate outcome would disclose existence. Measured in wave 6 on `ess/24`: with a distinct outcome, 7 credential and federation commands also fail their passing `/outcome/denied` scenario, because the synthesized scenario can force the refusal only through an empty read.

So the 15 commands keep their synthesized `wrong-state` scenario, which fails as before: credential (`DisableResourceServer`, `RedeemAuthorizationCode`, `RetireSigningKey`, `RevokeAccessCredential`, `RevokeSigningKey`), federation (`DisableFederationConnection`, `DisableOAuthClient`, `UnlinkExternalPrincipal`), graph (`DeregisterResource`), identity (`RevokeSession`), tenancy (`CloseOrganization`, `RemoveOrganizationMembership`, `RemoveTeamMembership`, `RetireSpace`, `RetireTeam`).

## Outcome

When ESS lets a command declare that an unknown identity is answered by an existing refusal outcome, each of the 15 commands declares it with the outcome its handler already gives, and no handler changes its answer.

## Acceptance

`cargo xtask conform` reports the 15 scenarios above `passed` with no handler answering an unknown identity differently from a record the caller may not see; the non-disclosure tests named above still pass.

## Waits on

An ESS release that admits the declaration (requested of ESS on 2026-10-13).

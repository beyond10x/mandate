//! `establish_entity`: the upstream-owned records a scenario may arrange, and the refusal
//! for every other one.
//!
//! Ruling 4 of the wave D enforcement track is what this module is: the authored PKCE
//! scenarios need a live `mandate.identity.Session`, and no scenario file can mint one
//! through the real verifier because the session a federated login opens is the one thing
//! the login *produces*. The records here are exactly the ones `identity.yaml` and
//! `federation.yaml` declare an **adapter** writer for — an event no command of this
//! contract emits — plus the authorization code the reuse scenario redeems twice. Every
//! other entity answers `Unsupported`, which is what the trait requires of a target that
//! cannot validate and establish a state.
//!
//! # Nothing here invents a record, and the prerequisites are recorded
//!
//! Each arm folds the declared seeding event, built from the request's own fields through
//! the same `Deserialize` the declared field types carry, into the same log a command would
//! append to. Where a fold refuses to read a seeding event without an earlier one —
//! `IdentityLog` refuses a session whose epoch snapshot is not yet recorded, and the
//! federation fold reads an external key's organization off the connection — the
//! prerequisite is seeded first and written to `injections.json` as
//! `established-prerequisite`, because a reader who sees a scenario pass must be able to
//! see what was standing behind it.

use ess_conformance::target::{EntitySetupRequest, TargetError};
use mandate_federation::record::{ConnectionState, FederationEvent};
use mandate_identity::{
    EpochSnapshotRecorded, Generation, IdentityEvent, SecurityEpochRecorded, SessionOpened,
};
use mandate_model::TenantResolutionRule;
use mandate_sts::store::AuthorizationCodeEvent;
use mandate_token::CredentialDescriptor;
use mandate_types::{
    Audience, ClientId, CredentialKind, EpochSnapshotRef, ExternalLinkMethod, ExternalPrincipalId,
    ExternalSubject, FederationConnectionId, Issuer, OrganizationId, PrincipalId,
    SecurityEpochTarget, SessionId, Timestamp, VerifiedContext,
};

use crate::Live;
use crate::node;

/// Establish the record the request names, in the state it names.
///
/// # Errors
///
/// Returns [`TargetError::Unsupported`] for an entity no adapter writer of this contract
/// creates, and [`TargetError::Unavailable`] when a declared field is not one the
/// contract's schema admits or a fold refuses the seeding event.
pub fn establish(live: &mut Live, request: &EntitySetupRequest) -> Result<(), TargetError> {
    let entity = request.entity.to_string();
    let state = request.state.to_string();
    match entity.as_str() {
        "mandate.identity.Session" => session(live, request, &state),
        "mandate.identity.SecurityEpochSnapshot" => snapshot(live, request),
        "mandate.identity.PrincipalSecurityEpoch"
        | "mandate.identity.OrganizationSecurityEpoch"
        | "mandate.identity.FederationSecurityEpoch" => generation(live, request),
        "mandate.federation.ExternalPrincipal" => external_principal(live, request, &state),
        "mandate.credential.AuthorizationCode" => authorization_code(live, request, &state),
        other => {
            live.ledger.block(
                &live.scenario,
                other,
                "entity-without-adapter-writer",
                "story:declared-writers",
            );
            Err(TargetError::unsupported(
                format!("establishing `{other}`"),
                "this contract declares no adapter writer for that record, so establishing \
                 one would be inventing history; owner story:declared-writers",
            ))
        }
    }
}

/// `mandate.identity.Session`, through the adapter-declared `SessionOpened`.
fn session(live: &mut Live, request: &EntitySetupRequest, state: &str) -> Result<(), TargetError> {
    if state != "Active" {
        return Err(TargetError::unsupported(
            format!("establishing a `mandate.identity.Session` in `{state}`"),
            "`Revoked` is terminal and is reached by the declared `revoke` move alone; a \
             session established there would be history no command wrote",
        ));
    }
    let id: SessionId = identity(request)?;
    let opened = SessionOpened {
        id,
        principal_id: field(request, "principal_id")?,
        organization_id: field(request, "organization_id")?,
        connection_id: optional(request, "connection_id")?,
        epochs: field(request, "epochs")?,
        expires_at: field(request, "expires_at")?,
    };
    // The log refuses an opening whose snapshot is not recorded, and a snapshot whose
    // dimensions have no generation. Both are the adapter's to write and neither is a
    // command, so they are seeded here and recorded.
    seed_snapshot(
        live,
        opened.epochs,
        opened.principal_id,
        opened.organization_id,
        opened.connection_id,
    );
    live.ledger.inject(
        &live.scenario.clone(),
        "mandate.identity.Session",
        "mandate_identity::IdentityLog",
        "established-prerequisite",
    );
    record(live, IdentityEvent::SessionOpened(opened))
}

/// `mandate.identity.SecurityEpochSnapshot`, through `EpochSnapshotRecorded`.
fn snapshot(live: &mut Live, request: &EntitySetupRequest) -> Result<(), TargetError> {
    let id: EpochSnapshotRef = identity(request)?;
    let principal_id: PrincipalId = field(request, "principal_id")?;
    let organization_id: OrganizationId = field(request, "organization_id")?;
    let connection_id: Option<FederationConnectionId> = optional(request, "connection_id")?;
    seed_snapshot(live, id, principal_id, organization_id, connection_id);
    Ok(())
}

/// One of the three generation records, through `SecurityEpochRecorded`.
fn generation(live: &mut Live, request: &EntitySetupRequest) -> Result<(), TargetError> {
    let target: SecurityEpochTarget = identity(request)?;
    let value: i64 = field(request, "generation")?;
    let generation = Generation::new(value).ok_or_else(|| {
        TargetError::unavailable(
            "establishing a generation",
            "the contract constrains `generation` non-negative",
        )
    })?;
    record(
        live,
        IdentityEvent::SecurityEpochRecorded(SecurityEpochRecorded { target, generation }),
    )
}

/// `mandate.federation.ExternalPrincipal`, through the link event the domain declares.
///
/// The fold reads the external key's organization off the **connection**, so a link whose
/// connection is not in the projection cannot be read at all. The connection is therefore
/// seeded first when it is absent, bound to the organization the record states, and
/// recorded as a prerequisite.
fn external_principal(
    live: &mut Live,
    request: &EntitySetupRequest,
    state: &str,
) -> Result<(), TargetError> {
    let id: ExternalPrincipalId = identity(request)?;
    let organization_id: OrganizationId = field(request, "organization_id")?;
    let connection_id: FederationConnectionId = field(request, "connection_id")?;
    let subject: ExternalSubject = field(request, "subject")?;
    let principal_id: PrincipalId = field(request, "principal_id")?;
    let link_method: ExternalLinkMethod = field(request, "link_method")?;
    let linked_at: Timestamp = field(request, "linked_at")?;
    seed_connection(live, connection_id, organization_id)?;
    let seeded = context(organization_id, principal_id);
    live.append_federation(FederationEvent::ExternalPrincipalLinked {
        context: seeded,
        connection_id,
        principal_id,
        external_principal_id: id,
        subject,
        link_method,
        linked_at,
    })?;
    match state {
        "Linked" => Ok(()),
        "Unlinked" => live.append_federation(FederationEvent::ExternalPrincipalUnlinked {
            context: context(organization_id, principal_id),
            id,
        }),
        other => Err(TargetError::unsupported(
            format!("establishing a `mandate.federation.ExternalPrincipal` in `{other}`"),
            "the record declares `Linked` and `Unlinked` and no other state",
        )),
    }
}

/// `mandate.credential.AuthorizationCode`, through the STS code log.
///
/// The `Consumed` state is the one the authored reuse scenario needs: a code that was issued
/// and redeemed, so a second redemption is the declared `wrong-state`. Both events are the
/// STS's own, appended to the same log `redeem_and_consume` appends to, through the same
/// `AuthorizationCodeLog::append` compare-and-set — so a state this establishes is a state
/// the real write path could have produced.
///
/// # What the redemption carries that the record does not
///
/// `mandate.credential.AuthorizationCode` declares nine fields and a state, and
/// `AuthorizationCodeRedeemed` declares a whole `mandate_token::CredentialDescriptor` beside
/// them: the credential the redemption *issues*, which is a different record with a
/// different identity. A scenario establishing a consumed code says nothing about it. So the
/// descriptor is taken from the request when a scenario supplies one and otherwise derived
/// from what the code record itself carries — its `scope`, its `expires_at`, and the
/// organization and subject of the context this module seeds — and the derivation is written
/// to `injections.json` as `established-prerequisite`. A reader who sees a `Consumed` code
/// can see that the credential half of its history is fixture data and not an observation.
fn authorization_code(
    live: &mut Live,
    request: &EntitySetupRequest,
    state: &str,
) -> Result<(), TargetError> {
    let code_id: mandate_types::AuthorizationCodeId = identity(request)?;
    let organization =
        field(request, "organization_id").unwrap_or_else(|_: TargetError| live.mint.organization());
    let subject = live.mint.principal();
    let seeded = context(organization, subject);
    let target: mandate_types::ResourceServerId = field(request, "target")?;
    let scope: mandate_types::AuthorityScope = field(request, "scope")?;
    let expires_at: Timestamp = field(request, "expires_at")?;
    let issued = AuthorizationCodeEvent::AuthorizationCodeIssued {
        context: seeded.clone(),
        code_id,
        client_id: field(request, "client_id")?,
        session_id: field(request, "session_id")?,
        verifier: field(request, "verifier")?,
        challenge: field(request, "challenge")?,
        method: field(request, "method")?,
        redirect_uri: field(request, "redirect_uri")?,
        expires_at: expires_at.clone(),
        target,
        scope: scope.clone(),
    };
    live.append_code(issued)?;
    match state {
        "Issued" => Ok(()),
        "Consumed" => {
            let descriptor = optional(request, "descriptor")?.unwrap_or(CredentialDescriptor {
                kind: CredentialKind::Reference,
                subject,
                actor: None,
                organization,
                audience: Audience::new(crate::AUDIENCE.to_owned()),
                scope,
                delegation: None,
                execution: None,
                expires_at: expires_at.clone(),
            });
            live.ledger.inject(
                &live.scenario.clone(),
                "mandate.credential.AuthorizationCode",
                "mandate_sts::store::AuthorizationCodeLog",
                "established-prerequisite",
            );
            let credential_id = live.mint.credential();
            live.append_code(AuthorizationCodeEvent::AuthorizationCodeRedeemed {
                context: seeded,
                code_id,
                credential_id,
                reference_verifier: None,
                epochs: None,
                issued_at: Timestamp::new(crate::FIXED_INSTANT),
                descriptor,
                target,
            })
        }
        other => Err(TargetError::unsupported(
            format!("establishing a `mandate.credential.AuthorizationCode` in `{other}`"),
            "the record declares `Issued` and `Consumed` and no other state",
        )),
    }
}

/// Seed the snapshot a session refers to, and the generation of every dimension it names.
///
/// Each append goes through `IdentityLog::try_record`, whose guards refuse a rewrite, so
/// seeding a snapshot the log already holds writes nothing rather than resetting it.
fn seed_snapshot(
    live: &mut Live,
    id: EpochSnapshotRef,
    principal_id: PrincipalId,
    organization_id: OrganizationId,
    connection_id: Option<FederationConnectionId>,
) {
    let mut targets = vec![
        SecurityEpochTarget::Principal(principal_id),
        SecurityEpochTarget::Organization(organization_id),
    ];
    if let Some(connection) = connection_id {
        targets.push(SecurityEpochTarget::Federation(connection));
    }
    for target in targets {
        let _ = live
            .identity
            .try_record(IdentityEvent::SecurityEpochRecorded(
                SecurityEpochRecorded {
                    target,
                    generation: Generation::ZERO,
                },
            ));
    }
    let _ = live
        .identity
        .try_record(IdentityEvent::EpochSnapshotRecorded(
            EpochSnapshotRecorded {
                id,
                principal_id,
                organization_id,
                connection_id,
            },
        ));
}

/// Seed the connection an external key resolves through, when the fold has none.
fn seed_connection(
    live: &mut Live,
    id: FederationConnectionId,
    organization_id: OrganizationId,
) -> Result<(), TargetError> {
    if mandate_federation::ConnectionStore::connection(&live.federation, &id)
        .is_some_and(|held| held.state == ConnectionState::Enabled)
    {
        return Ok(());
    }
    live.ledger.inject(
        &live.scenario.clone(),
        "mandate.federation.ExternalPrincipal",
        "mandate_federation::ConnectionStore",
        "established-prerequisite",
    );
    let seeded = context(organization_id, live.mint.principal());
    live.append_federation(FederationEvent::FederationConnectionCreated {
        context: seeded,
        connection_id: id,
        issuer: Issuer::new(format!("https://established.invalid/{id}")),
        client_id: ClientId::new(format!("established-{id}")),
        tenant_resolution: TenantResolutionRule {
            configured_organization: organization_id,
            verified_claim_name: None,
            verified_claim_value: None,
        },
        jit_provisioning: false,
    })
}

/// Append one identity event, refusing what the log refuses.
fn record(live: &mut Live, event: IdentityEvent) -> Result<(), TargetError> {
    live.identity.try_record(event).map_err(|denial| {
        TargetError::unavailable("establishing identity state", denial.to_string())
    })
}

/// The literal identity the request names, as the record's own identity type.
fn identity<T: serde::de::DeserializeOwned>(
    request: &EntitySetupRequest,
) -> Result<T, TargetError> {
    let value = node::to_json(&request.identity)?;
    serde_json::from_value(value).map_err(|error| {
        TargetError::unavailable(
            format!("reading the identity of `{}`", request.entity),
            error.to_string(),
        )
    })
}

/// One declared field of the record, as the declared field's own Rust type.
fn field<T: serde::de::DeserializeOwned>(
    request: &EntitySetupRequest,
    name: &str,
) -> Result<T, TargetError> {
    node::field(&request.fields, name)
}

/// One declared optional field of the record.
fn optional<T: serde::de::DeserializeOwned>(
    request: &EntitySetupRequest,
    name: &str,
) -> Result<Option<T>, TargetError> {
    node::optional(&request.fields, name)
}

/// The verified context a seeding event carries.
///
/// No declared field of any record here is a `mandate.core.VerifiedContext`, and every
/// seeding event declares one, so the target states it: the organization the record itself
/// names and a subject minted from a counter. It reaches no projection — both folds read
/// the record's own fields and the connection for the key — and it is written to
/// `injections.json` with the rest.
fn context(organization: OrganizationId, subject: PrincipalId) -> VerifiedContext {
    VerifiedContext {
        subject,
        actor: None,
        organization,
        audience: mandate_types::Audience::new(crate::AUDIENCE.to_owned()),
        credential: mandate_types::CredentialId::new(mandate_types::Uuid::from_bytes([0xcd; 16])),
        delegation: None,
        execution: None,
        correlation: mandate_types::CorrelationId::new(crate::CORRELATION.to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::establish;
    use crate::{Live, external::Ledger};
    use ess_conformance::scenario::ScenarioId;
    use ess_conformance::target::{EntitySetupRequest, ScenarioContext};
    use ess_primitives::ids::CorrelationId;
    use ess_primitives::node::Node;
    use std::collections::BTreeMap;

    fn live() -> Live {
        Live::open(
            &ScenarioContext::new(
                ScenarioId::parse("mandate.identity.RevokeSession/outcome/accepted")
                    .expect("an identity"),
                CorrelationId::new("c").expect("a correlation"),
            ),
            Ledger::opened(),
        )
    }

    fn request(
        entity: &str,
        identity: &str,
        state: &str,
        fields: &[(&str, Node)],
    ) -> EntitySetupRequest {
        EntitySetupRequest {
            entity: entity.parse().expect("an entity"),
            identity: Node::Text(identity.to_owned()),
            fields: fields
                .iter()
                .map(|(name, value)| ((*name).to_owned(), value.clone()))
                .collect(),
            state: state.parse().expect("a state"),
            correlation: CorrelationId::new("c").expect("a correlation"),
        }
    }

    fn text(value: &str) -> Node {
        Node::Text(value.to_owned())
    }

    const SESSION: &str = "10000000-0000-4000-8000-000000000001";
    const PRINCIPAL: &str = "20000000-0000-4000-8000-000000000002";
    const ORGANIZATION: &str = "30000000-0000-4000-8000-000000000003";
    const CONNECTION: &str = "40000000-0000-4000-8000-000000000004";
    const SNAPSHOT: &str = "50000000-0000-4000-8000-000000000005";
    const EXTERNAL: &str = "60000000-0000-4000-8000-000000000006";

    /// A session established through `SessionOpened` is a session the real read port
    /// resolves, in the declared initial state.
    ///
    /// Ruling 4 of the wave D enforcement track is what this decides: the authored PKCE
    /// scenarios need a live session, and a target that acknowledged the setup without the
    /// fold materializing one would make every step after it assert nothing.
    #[test]
    fn a_session_is_established_and_the_read_port_resolves_it() {
        let mut live = live();
        establish(
            &mut live,
            &request(
                "mandate.identity.Session",
                SESSION,
                "Active",
                &[
                    ("principal_id", text(PRINCIPAL)),
                    ("organization_id", text(ORGANIZATION)),
                    ("connection_id", text(CONNECTION)),
                    ("epochs", text(SNAPSHOT)),
                    ("expires_at", text("2030-01-01T00:00:00Z")),
                ],
            ),
        )
        .expect("a session is established");
        let id = mandate_types::SessionId::parse(SESSION).expect("an identity");
        let session = mandate_identity::IdentityRead::resolve(&live.identity, &id)
            .expect("the fold materialized the session");
        assert!(
            session.is_active(),
            "the session was not established Active"
        );
        assert_eq!(session.principal().to_string(), PRINCIPAL);
        assert_eq!(session.organization().to_string(), ORGANIZATION);
    }

    /// The terminal state is not establishable: reaching it is the declared `revoke` move.
    #[test]
    fn a_revoked_session_is_refused_rather_than_invented() {
        let mut live = live();
        let error = establish(
            &mut live,
            &request(
                "mandate.identity.Session",
                SESSION,
                "Revoked",
                &[
                    ("principal_id", text(PRINCIPAL)),
                    ("organization_id", text(ORGANIZATION)),
                    ("epochs", text(SNAPSHOT)),
                    ("expires_at", text("2030-01-01T00:00:00Z")),
                ],
            ),
        )
        .expect_err("a terminal state was established");
        assert!(error.is_unsupported(), "{error}");
    }

    /// An external principal is established so that the link path's principal read answers.
    ///
    /// The coordinator's addendum names this: `PrincipalStore::organization_of` is answered
    /// from the federation link projection, and `mandate.identity.Principal` carries no
    /// organization, so seeding the principal alone leaves `link_external_principal`
    /// refusing at `PrincipalMismatch`.
    #[test]
    fn an_external_principal_is_established_and_the_principal_read_answers() {
        let mut live = live();
        establish(
            &mut live,
            &request(
                "mandate.federation.ExternalPrincipal",
                EXTERNAL,
                "Linked",
                &[
                    ("organization_id", text(ORGANIZATION)),
                    ("connection_id", text(CONNECTION)),
                    ("subject", text("external-subject")),
                    ("principal_id", text(PRINCIPAL)),
                    ("link_method", text("Administrator")),
                    ("linked_at", text("2026-01-01T00:00:00Z")),
                ],
            ),
        )
        .expect("an external principal is established");
        let principal = mandate_types::PrincipalId::parse(PRINCIPAL).expect("an identity");
        assert_eq!(
            mandate_federation::PrincipalStore::organization_of(&live.federation, &principal)
                .map(|held| held.to_string()),
            Some(ORGANIZATION.to_owned()),
            "the link projection does not answer the principal's organization"
        );
        let record = mandate_federation::ExternalPrincipalStore::external_principal(
            &live.federation,
            &mandate_types::ExternalPrincipalId::parse(EXTERNAL).expect("an identity"),
        )
        .expect("the fold materialized the link");
        assert_eq!(record.state, mandate_federation::record::LinkState::Linked);
    }

    /// An authorization code is established in both declared states.
    ///
    /// `Consumed` is what the authored `pkce-reuse` scenario needs: a code already redeemed,
    /// so a second redemption is the contract's `wrong-state` rather than a first success.
    /// Both events go through `AuthorizationCodeLog::append`'s compare-and-set, so the state
    /// this establishes is one the real write path could have produced — which is the
    /// difference between arranging a fixture and asserting one.
    ///
    /// The case previously recorded that `Consumed` was refused, because
    /// `AuthorizationCodeRedeemed` declares a `mandate_token::CredentialDescriptor` and
    /// `mandate-token` was not on this crate's dependency line. The coordinator landed that
    /// admission; the assertion moves with the fact rather than the fact being left
    /// unasserted.
    #[test]
    fn an_authorization_code_is_established_in_both_declared_states() {
        let mut live = live();
        let fields = [
            ("client_id", text("70000000-0000-4000-8000-000000000007")),
            ("session_id", text(SESSION)),
            ("verifier", text("dmVyaWZpZXI=")),
            (
                "challenge",
                text("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"),
            ),
            ("method", text("S256")),
            ("redirect_uri", text("https://client.example/callback")),
            ("expires_at", text("2030-01-01T00:00:00Z")),
            ("target", text("80000000-0000-4000-8000-000000000008")),
            ("organization_id", text(ORGANIZATION)),
            (
                "scope",
                Node::Map(BTreeMap::from([
                    ("actions".to_owned(), Node::Seq(Vec::new())),
                    ("resources".to_owned(), Node::Seq(Vec::new())),
                    (
                        "space".to_owned(),
                        text("90000000-0000-4000-8000-000000000009"),
                    ),
                ])),
            ),
        ];
        let issued = "a0000000-0000-4000-8000-00000000000a";
        let consumed = "b0000000-0000-4000-8000-00000000000b";
        for (identity, state) in [(issued, "Issued"), (consumed, "Consumed")] {
            establish(
                &mut live,
                &request(
                    "mandate.credential.AuthorizationCode",
                    identity,
                    state,
                    &fields,
                ),
            )
            .unwrap_or_else(|error| panic!("a {state} code is established: {error}"));
        }
        let held = |identity: &str| {
            mandate_sts::store::AuthorizationCodeReads::authorization_code(
                live.codes.projection(),
                &mandate_types::AuthorizationCodeId::parse(identity).expect("an identity"),
            )
            .expect("the STS code fold materialized no code")
            .state
        };
        assert_eq!(
            held(issued),
            mandate_sts::store::AuthorizationCodeState::Issued
        );
        assert_eq!(
            held(consumed),
            mandate_sts::store::AuthorizationCodeState::Consumed,
            "a second redemption of this code would be a first success, not the declared \
             wrong-state"
        );
        assert!(
            live.ledger
                .injections
                .iter()
                .any(|entry| entry.kind == "established-prerequisite"),
            "the credential half of the redemption was derived and not written down"
        );

        let error = establish(
            &mut live,
            &request(
                "mandate.credential.AuthorizationCode",
                "c0000000-0000-4000-8000-00000000000c",
                "Expired",
                &fields,
            ),
        )
        .expect_err("a state the record does not declare was established");
        assert!(error.is_unsupported(), "{error}");
    }

    /// Every other entity is refused, and the refusal names the story.
    #[test]
    fn an_entity_with_no_adapter_writer_is_refused() {
        let mut live = live();
        let error = establish(
            &mut live,
            &request(
                "mandate.tenancy.Organization",
                ORGANIZATION,
                "Open",
                &[("display_name", text("an organization"))],
            ),
        )
        .expect_err("an entity with no adapter writer was established");
        assert!(error.is_unsupported(), "{error}");
        assert!(
            live.ledger
                .blocked
                .iter()
                .any(|entry| entry.blocked_on == "story:declared-writers"),
            "the refusal named no story"
        );
    }
}

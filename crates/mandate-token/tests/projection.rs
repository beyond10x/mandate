//! The `mandate.credential` projections and the fold that materializes them.
//!
//! Every case drives [`mandate_token::projection::Projection`] through the declared event
//! payloads alone: a record is what the log says it is, never what a handler remembers
//! (`docs/adr/0009-event-sourced-persistence.md`). The three records this crate projects —
//! `ResourceServer`, `AccessCredential` and `SigningKey` — each enter at their declared
//! initial state and move only along a declared transition.
//!
//! Two refusals are the fold's own and are decided here rather than in a handler:
//!
//! - an event naming an instance no event created, which is a lost record and not a race;
//! - a `SigningKeyRegistered` whose `key_reference` or `thumbprint` another recorded key
//!   already holds, which `credential.yaml` refuses "in every state that key can be in,
//!   including Retired and Revoked", so one piece of key material can never come back
//!   under a second identity.
//!
//! The `(organization_id, audience)` uniqueness is *not* a fold refusal. It is
//! `decision-blocker:identity-uniqueness` on the projection: the log records both
//! registrations, the smallest identity among the `Enabled` records holds the key, and the
//! write path refuses through [`Projection::admits_audience`], which returns the declared
//! `mandate.credential.Denied`.

use mandate_token::projection::{
    AccessCredential, AccessCredentialState, AudienceConflict, CredentialEvent, DenialClause,
    FoldError, Projection, RefusedOutcome, ResourceServer, ResourceServerState, SigningKey,
    SigningKeyConflict, SigningKeyIndex, SigningKeyState,
};
use mandate_token::{CredentialDescriptor, CredentialProfile};
use mandate_types::{
    Audience, AuthorityScope, AuthorizationCodeId, CorrelationId, CredentialId, CredentialKind,
    CredentialVerifier, DenialReason, Duration, EpochSnapshotRef, KeyReference, OrganizationId,
    PrincipalId, ResourceServerId, RevocationGuarantee, SigningAlgorithm, SigningKeyId, Timestamp,
    Uuid, VerifiedContext,
};

fn uuid(tag: u8) -> Uuid {
    Uuid::from_bytes([tag; 16])
}

fn organization(tag: u8) -> OrganizationId {
    OrganizationId::new(uuid(tag))
}

fn principal(tag: u8) -> PrincipalId {
    PrincipalId::new(uuid(tag))
}

fn target(tag: u8) -> ResourceServerId {
    ResourceServerId::new(uuid(tag))
}

fn credential(tag: u8) -> CredentialId {
    CredentialId::new(uuid(tag))
}

fn key(tag: u8) -> SigningKeyId {
    SigningKeyId::new(uuid(tag))
}

fn context(organization_id: OrganizationId) -> VerifiedContext {
    VerifiedContext {
        subject: principal(0x51),
        actor: None,
        organization: organization_id,
        audience: Audience::new("mandate"),
        credential: credential(0xcd),
        delegation: None,
        execution: None,
        correlation: CorrelationId::new("credential-projection"),
    }
}

fn reference_profile() -> CredentialProfile {
    CredentialProfile {
        name: "reference".to_owned(),
        kind: CredentialKind::Reference,
        revocation: RevocationGuarantee::ImmediateOnline,
        max_ttl: Duration::new("PT1H"),
        positive_cache_ttl: Duration::new("PT30S"),
        requires_online_authorization: true,
    }
}

fn descriptor(organization_id: OrganizationId, audience: &str) -> CredentialDescriptor {
    CredentialDescriptor {
        kind: CredentialKind::Reference,
        subject: principal(0x51),
        actor: None,
        organization: organization_id,
        audience: Audience::new(audience),
        scope: AuthorityScope {
            actions: Vec::new(),
            resources: Vec::new(),
            space: None,
        },
        delegation: None,
        execution: None,
        expires_at: Timestamp::new("2026-09-19T01:00:00Z"),
    }
}

fn registered(
    id: ResourceServerId,
    organization_id: OrganizationId,
    audience: &str,
) -> CredentialEvent {
    CredentialEvent::ResourceServerRegistered {
        context: context(organization_id),
        id,
        audience: Audience::new(audience),
        credential_profile: reference_profile(),
        allowed_exchange_sources: Vec::new(),
    }
}

fn issued(id: CredentialId, organization_id: OrganizationId, audience: &str) -> CredentialEvent {
    CredentialEvent::CredentialReferenceIssued {
        context: context(organization_id),
        credential_id: id,
        reference_verifier: Some(CredentialVerifier::new("digest-of-the-secret")),
        epochs: None,
        issued_at: Timestamp::new("2026-09-19T00:00:00Z"),
        descriptor: descriptor(organization_id, audience),
        target: target(0x30),
        requested_scope: AuthorityScope {
            actions: Vec::new(),
            resources: Vec::new(),
            space: None,
        },
    }
}

/// `mandate.credential.AuthorizationCodeRedeemed`, the third event that creates a credential
/// record. `credential.yaml`'s header declares that it "also seeds a
/// `mandate.credential.AccessCredential`" and "carries the whole AccessCredential record ...
/// so a fold materializes the credential from the event and the issuing registration the log
/// already holds, reading no command input or response".
fn redeemed(id: CredentialId, organization_id: OrganizationId, audience: &str) -> CredentialEvent {
    CredentialEvent::AuthorizationCodeRedeemed {
        context: context(organization_id),
        code_id: AuthorizationCodeId::new(uuid(0xac)),
        credential_id: id,
        reference_verifier: Some(CredentialVerifier::new("digest-of-the-secret")),
        epochs: None,
        issued_at: Timestamp::new("2026-09-19T00:00:00Z"),
        descriptor: descriptor(organization_id, audience),
        target: target(0x30),
    }
}

fn key_registered(id: SigningKeyId, reference: &str, thumbprint: &str) -> CredentialEvent {
    CredentialEvent::SigningKeyRegistered {
        context: context(organization(10)),
        id,
        key_reference: KeyReference::new(reference),
        thumbprint: thumbprint.to_owned(),
        algorithm: SigningAlgorithm::new("declared-by-deployment"),
        not_before: Timestamp::new("2026-09-19T00:00:00Z"),
        expires_at: Timestamp::new("2026-12-31T00:00:00Z"),
    }
}

#[test]
fn a_registration_creates_the_resource_server_in_its_declared_initial_state() {
    let log = vec![registered(target(0x30), organization(10), "api-a")];

    let held = Projection::fold(&log).expect("one creation");

    assert_eq!(
        held.resource_servers(),
        [ResourceServer {
            id: target(0x30),
            organization_id: organization(10),
            audience: Audience::new("api-a"),
            credential_profile: reference_profile(),
            allowed_exchange_sources: Vec::new(),
            state: ResourceServerState::Enabled,
        }]
    );
}

#[test]
fn disabling_moves_the_resource_server_to_its_terminal_state() {
    let log = vec![
        registered(target(0x30), organization(10), "api-a"),
        CredentialEvent::ResourceServerDisabled {
            context: context(organization(10)),
            id: target(0x30),
        },
    ];

    let held = Projection::fold(&log).expect("a creation and its move");

    assert_eq!(
        held.resource_server(&target(0x30))
            .map(|server| server.state),
        Some(ResourceServerState::Disabled)
    );
}

#[test]
fn a_disablement_naming_no_recorded_server_is_a_log_the_fold_cannot_read() {
    let log = vec![CredentialEvent::ResourceServerDisabled {
        context: context(organization(10)),
        id: target(0x30),
    }];

    assert_eq!(
        Projection::fold(&log),
        Err(FoldError::UnknownResourceServer { id: target(0x30) })
    );
}

#[test]
fn reference_issuance_creates_the_credential_carrying_the_verifier_and_nothing_else() {
    let log = vec![
        registered(target(0x30), organization(10), "api-a"),
        issued(credential(0x40), organization(10), "api-a"),
    ];

    let held = Projection::fold(&log).expect("a registration and one issuance");

    assert_eq!(
        held.credentials(),
        [AccessCredential {
            id: credential(0x40),
            descriptor: descriptor(organization(10), "api-a"),
            reference_verifier: Some(CredentialVerifier::new("digest-of-the-secret")),
            epochs: None,
            issued_at: Timestamp::new("2026-09-19T00:00:00Z"),
            state: AccessCredentialState::Active,
            // Neither is a declared field of `mandate.credential.AccessCredential`; both are
            // read from the registration the issuance named, because the guarantee a
            // credential carries is the one published when it was issued.
            target: target(0x30),
            issuing_profile: reference_profile(),
        }]
    );
}

/// An issuance naming a registration no event created is a log the fold cannot read: the
/// guarantee the credential was issued under is not recoverable from it.
#[test]
fn an_issuance_naming_no_recorded_registration_is_a_log_the_fold_cannot_read() {
    let log = vec![issued(credential(0x40), organization(10), "api-a")];

    assert_eq!(
        Projection::fold(&log),
        Err(FoldError::UnknownIssuingTarget {
            id: credential(0x40),
            target: target(0x30),
        })
    );
}

#[test]
fn self_contained_issuance_creates_the_credential_the_same_way() {
    let log = vec![
        registered(target(0x30), organization(10), "api-a"),
        CredentialEvent::CredentialSelfContainedIssued {
            context: context(organization(10)),
            credential_id: credential(0x41),
            reference_verifier: Some(CredentialVerifier::new("digest-of-the-token")),
            epochs: Some(EpochSnapshotRef::new(uuid(0x60))),
            issued_at: Timestamp::new("2026-09-19T00:00:00Z"),
            descriptor: CredentialDescriptor {
                kind: CredentialKind::SelfContained,
                ..descriptor(organization(10), "api-a")
            },
            target: target(0x30),
            requested_scope: AuthorityScope {
                actions: Vec::new(),
                resources: Vec::new(),
                space: None,
            },
        },
    ];

    let held = Projection::fold(&log).expect("a registration and one issuance");
    let record = held
        .access_credential(&credential(0x41))
        .expect("the credential the log created");

    assert_eq!(record.descriptor.kind, CredentialKind::SelfContained);
    assert_eq!(record.epochs, Some(EpochSnapshotRef::new(uuid(0x60))));
    assert_eq!(record.state, AccessCredentialState::Active);
}

/// A redemption creates the credential record exactly as an issuance does: from the event
/// and the issuing registration the log already holds, and from no command input or response.
#[test]
fn a_redemption_creates_the_credential_the_way_an_issuance_does() {
    let log = vec![
        registered(target(0x30), organization(10), "api-a"),
        redeemed(credential(0x42), organization(10), "api-a"),
    ];

    let held = Projection::fold(&log).expect("a registration and one redemption");

    assert_eq!(
        held.credentials(),
        [AccessCredential {
            id: credential(0x42),
            descriptor: descriptor(organization(10), "api-a"),
            reference_verifier: Some(CredentialVerifier::new("digest-of-the-secret")),
            epochs: None,
            issued_at: Timestamp::new("2026-09-19T00:00:00Z"),
            state: AccessCredentialState::Active,
            target: target(0x30),
            issuing_profile: reference_profile(),
        }]
    );
    assert_eq!(
        held.access_credential(&credential(0x42)),
        Projection::fold(&[
            registered(target(0x30), organization(10), "api-a"),
            issued(credential(0x42), organization(10), "api-a"),
        ])
        .expect("the same record from the issuance event")
        .access_credential(&credential(0x42)),
        "the redeemed event seeds the record the issuance event seeds"
    );
}

/// The same refusal an issuance gets, for the same reason: the guarantee the credential was
/// issued under is not recoverable from a log that never registered its target.
#[test]
fn a_redemption_naming_no_recorded_registration_is_a_log_the_fold_cannot_read() {
    let log = vec![redeemed(credential(0x42), organization(10), "api-a")];

    assert_eq!(
        Projection::fold(&log),
        Err(FoldError::UnknownIssuingTarget {
            id: credential(0x42),
            target: target(0x30),
        })
    );
}

/// The record a redemption seeded is an `AccessCredential` like any other: it is revoked
/// through the declared move and reaches the declared terminal state.
#[test]
fn a_credential_a_redemption_seeded_is_revoked_like_any_other() {
    let log = vec![
        registered(target(0x30), organization(10), "api-a"),
        redeemed(credential(0x42), organization(10), "api-a"),
        CredentialEvent::AccessCredentialRevoked {
            context: context(organization(10)),
            id: credential(0x42),
        },
    ];

    let held = Projection::fold(&log).expect("a creation and its move");

    assert_eq!(
        held.access_credential(&credential(0x42))
            .map(|record| record.state),
        Some(AccessCredentialState::Revoked)
    );
}

#[test]
fn revocation_moves_the_credential_to_its_terminal_state() {
    let log = vec![
        registered(target(0x30), organization(10), "api-a"),
        issued(credential(0x40), organization(10), "api-a"),
        CredentialEvent::AccessCredentialRevoked {
            context: context(organization(10)),
            id: credential(0x40),
        },
    ];

    let held = Projection::fold(&log).expect("a creation and its move");

    assert_eq!(
        held.access_credential(&credential(0x40))
            .map(|record| record.state),
        Some(AccessCredentialState::Revoked)
    );
}

#[test]
fn a_revocation_naming_no_recorded_credential_is_a_log_the_fold_cannot_read() {
    let log = vec![CredentialEvent::AccessCredentialRevoked {
        context: context(organization(10)),
        id: credential(0x40),
    }];

    assert_eq!(
        Projection::fold(&log),
        Err(FoldError::UnknownAccessCredential {
            id: credential(0x40)
        })
    );
}

/// `credential.yaml`: `CredentialIntrospected` "folds into no record — its `credential_id`
/// names an instance only when one exists in this log, and a fold reading it must not take
/// the name for the existence of a record some other event created".
#[test]
fn an_introspection_folds_into_nothing_and_creates_no_record_from_the_name_it_carries() {
    let before = Projection::fold(&[]).expect("an empty log");
    let log = vec![CredentialEvent::CredentialIntrospected {
        context: context(organization(10)),
        descriptor: Some(descriptor(organization(10), "api-a")),
        active: true,
        credential_id: Some(credential(0x40)),
    }];

    let held = Projection::fold(&log).expect("an introspection is readable against any log");

    assert_eq!(held, before);
    assert_eq!(held.access_credential(&credential(0x40)), None);
}

#[test]
fn a_second_registration_on_one_organization_and_audience_is_refused_with_the_declared_reason() {
    let log = vec![registered(target(0x30), organization(10), "api-a")];
    let held = Projection::fold(&log).expect("one creation");

    let denied = held
        .admits_audience(&organization(10), &Audience::new("api-a"))
        .expect_err("the audience is registered in this organization");

    assert_eq!(denied.reason, DenialReason::Denied);
    assert_eq!(denied.clause, DenialClause::AudienceAmbiguous);
    assert_eq!(denied.outcome, RefusedOutcome::Denied);
}

#[test]
fn the_same_audience_in_another_organization_is_admitted() {
    let log = vec![registered(target(0x30), organization(10), "api-a")];
    let held = Projection::fold(&log).expect("one creation");

    assert_eq!(
        held.admits_audience(&organization(11), &Audience::new("api-a")),
        Ok(())
    );
}

/// A disabled server stops holding its audience: no command un-registers one, so the
/// registration a deployment retired would otherwise take the audience out of use forever.
#[test]
fn a_disabled_server_releases_the_audience_it_held() {
    let log = vec![
        registered(target(0x30), organization(10), "api-a"),
        CredentialEvent::ResourceServerDisabled {
            context: context(organization(10)),
            id: target(0x30),
        },
    ];
    let held = Projection::fold(&log).expect("a creation and its move");

    assert_eq!(
        held.registered(&organization(10), &Audience::new("api-a")),
        None
    );
    assert_eq!(
        held.admits_audience(&organization(10), &Audience::new("api-a")),
        Ok(())
    );
}

/// Two writers that each read a free audience is a race the write path refuses to the
/// extent it can see it; the log is the record of both. Which record *holds* the key is a
/// total order over the records themselves — the smallest identity — so a rebuild that
/// presents the two streams in either order resolves it the same way.
#[test]
fn one_audience_has_one_holder_and_the_rest_are_conflicts_whatever_the_order() {
    let first = registered(target(0x30), organization(10), "api-a");
    let second = registered(target(0x31), organization(10), "api-a");

    for log in [
        vec![first.clone(), second.clone()],
        vec![second.clone(), first.clone()],
    ] {
        let held = Projection::fold(&log).expect("both registrations are recorded");

        assert_eq!(
            held.registered(&organization(10), &Audience::new("api-a"))
                .map(|server| server.id),
            Some(target(0x30))
        );
        assert_eq!(
            held.audience_conflicts(),
            [AudienceConflict {
                organization_id: organization(10),
                audience: Audience::new("api-a"),
                id: target(0x31),
            }]
        );
    }
}

#[test]
fn a_key_registration_creates_the_signing_key_in_its_declared_initial_state() {
    let log = vec![key_registered(key(0x70), "kms://one", "thumb-one")];

    let held = Projection::fold(&log).expect("one creation");

    assert_eq!(
        held.signing_keys(),
        [SigningKey {
            id: key(0x70),
            key_reference: KeyReference::new("kms://one"),
            thumbprint: "thumb-one".to_owned(),
            algorithm: SigningAlgorithm::new("declared-by-deployment"),
            not_before: Timestamp::new("2026-09-19T00:00:00Z"),
            expires_at: Timestamp::new("2026-12-31T00:00:00Z"),
            state: SigningKeyState::Recorded,
        }]
    );
}

#[test]
fn retirement_and_revocation_move_the_signing_key_along_its_declared_transitions() {
    let log = vec![
        key_registered(key(0x70), "kms://one", "thumb-one"),
        CredentialEvent::SigningKeyRetired {
            context: context(organization(10)),
            id: key(0x70),
        },
    ];
    let held = Projection::fold(&log).expect("a creation and its move");
    assert_eq!(
        held.signing_key(&key(0x70)).map(|record| record.state),
        Some(SigningKeyState::Retired)
    );

    let mut log = log;
    log.push(CredentialEvent::SigningKeyRevoked {
        context: context(organization(10)),
        id: key(0x70),
    });
    let held = Projection::fold(&log).expect("retire then revoke is a declared path");
    assert_eq!(
        held.signing_key(&key(0x70)).map(|record| record.state),
        Some(SigningKeyState::Revoked)
    );
}

#[test]
fn a_key_move_naming_no_recorded_key_is_a_log_the_fold_cannot_read() {
    let log = vec![CredentialEvent::SigningKeyRetired {
        context: context(organization(10)),
        id: key(0x70),
    }];

    assert_eq!(
        Projection::fold(&log),
        Err(FoldError::UnknownSigningKey { id: key(0x70) })
    );
}

/// "A key reference ... already held by a recorded key is refused in every state that key
/// can be in, including Retired and Revoked" (`credential.yaml`, `RegisterSigningKey`) — and
/// the refusal is the write path's, while the fold keeps both records and names the loser.
///
/// A fold refusal would be all-or-nothing: `Projection::fold` returns one `Result` for the
/// whole log, so a duplicated key reference would take every `ResourceServer` and every
/// `AccessCredential` of that log with it, and under
/// `docs/adr/0009-event-sourced-persistence.md` there is nowhere else to read those from.
#[test]
fn a_key_reference_a_revoked_key_still_holds_is_held_against_the_second_record() {
    let log = vec![
        registered(target(0x30), organization(10), "api-a"),
        issued(credential(0x40), organization(10), "api-a"),
        key_registered(key(0x70), "kms://one", "thumb-one"),
        CredentialEvent::SigningKeyRevoked {
            context: context(organization(10)),
            id: key(0x70),
        },
        key_registered(key(0x71), "kms://one", "thumb-two"),
    ];

    let held = Projection::fold(&log).expect("a duplicated index is a view, not a refusal");

    // The rest of the log survives, which is the whole reason this is a view.
    assert!(held.resource_server(&target(0x30)).is_some());
    assert!(held.access_credential(&credential(0x40)).is_some());
    assert_eq!(held.signing_keys().len(), 2);

    // The revoked key still holds the reference — "in every state that key can be in".
    assert_eq!(
        held.key_reference_holder(&KeyReference::new("kms://one"))
            .map(|holder| holder.id),
        Some(key(0x70))
    );
    assert!(!held.holds_its_key_material(&key(0x71)));
    assert!(held.holds_its_key_material(&key(0x70)));
    assert_eq!(
        held.signing_key_conflicts(),
        [SigningKeyConflict {
            id: key(0x71),
            index: SigningKeyIndex::KeyReference,
            held_by: key(0x70),
        }]
    );
}

/// The other half: the same *material* re-filed under a new reference, which is what the
/// thumbprint is on the record for.
#[test]
fn a_thumbprint_another_key_holds_is_held_against_the_second_record() {
    let log = vec![
        key_registered(key(0x70), "kms://one", "thumb-one"),
        key_registered(key(0x71), "kms://two", "thumb-one"),
    ];

    let held = Projection::fold(&log).expect("a duplicated index is a view, not a refusal");

    assert_eq!(
        held.thumbprint_holder("thumb-one").map(|holder| holder.id),
        Some(key(0x70))
    );
    assert!(!held.holds_its_key_material(&key(0x71)));
    assert_eq!(
        held.signing_key_conflicts(),
        [SigningKeyConflict {
            id: key(0x71),
            index: SigningKeyIndex::Thumbprint,
            held_by: key(0x70),
        }]
    );
}

/// Which key holds an index is a total order over the identities, not the order a rebuild
/// presents the two streams in — the same argument the audience index makes, and the same
/// answer whichever way the interleaving goes.
#[test]
fn one_index_has_one_holder_whatever_the_order() {
    let first = key_registered(key(0x70), "kms://one", "thumb-one");
    let second = key_registered(key(0x71), "kms://one", "thumb-two");

    for log in [
        vec![first.clone(), second.clone()],
        vec![second.clone(), first.clone()],
    ] {
        let held = Projection::fold(&log).expect("both registrations are recorded");

        assert_eq!(held.signing_keys().len(), 2);
        assert_eq!(
            held.key_reference_holder(&KeyReference::new("kms://one"))
                .map(|holder| holder.id),
            Some(key(0x70)),
            "the smallest identity among the keys recording it holds it"
        );
        assert_eq!(
            held.signing_key_conflicts()
                .iter()
                .map(|conflict| conflict.id)
                .collect::<Vec<_>>(),
            vec![key(0x71)]
        );
    }
}

/// A key that lost **both** indexes is named twice, once per index: the report says what it
/// lost, not merely that it lost.
#[test]
fn a_key_that_lost_both_indexes_is_named_for_each() {
    let log = vec![
        key_registered(key(0x70), "kms://one", "thumb-one"),
        key_registered(key(0x71), "kms://one", "thumb-one"),
    ];

    let held = Projection::fold(&log).expect("both registrations are recorded");

    assert_eq!(
        held.signing_key_conflicts(),
        [
            SigningKeyConflict {
                id: key(0x71),
                index: SigningKeyIndex::KeyReference,
                held_by: key(0x70),
            },
            SigningKeyConflict {
                id: key(0x71),
                index: SigningKeyIndex::Thumbprint,
                held_by: key(0x70),
            },
        ]
    );
}

/// At-least-once delivery is the kit's own guarantee, so a redelivered creation must write
/// nothing rather than return a record from a terminal state to its initial one — or, for a
/// key, be refused as its own duplicate material.
#[test]
fn a_redelivered_creation_writes_nothing() {
    let log = vec![
        registered(target(0x30), organization(10), "api-a"),
        CredentialEvent::ResourceServerDisabled {
            context: context(organization(10)),
            id: target(0x30),
        },
        registered(target(0x30), organization(10), "api-a"),
        issued(credential(0x40), organization(10), "api-a"),
        issued(credential(0x40), organization(10), "api-a"),
        redeemed(credential(0x42), organization(10), "api-a"),
        redeemed(credential(0x42), organization(10), "api-a"),
        key_registered(key(0x70), "kms://one", "thumb-one"),
        key_registered(key(0x70), "kms://one", "thumb-one"),
    ];

    let held = Projection::fold(&log).expect("a redelivery is not a second record");

    assert_eq!(held.resource_servers().len(), 1);
    assert_eq!(
        held.resource_server(&target(0x30))
            .map(|server| server.state),
        Some(ResourceServerState::Disabled)
    );
    assert_eq!(held.credentials().len(), 2);
    assert_eq!(held.signing_keys().len(), 1);
}

#[test]
fn every_event_names_the_element_it_is() {
    let names: Vec<&str> = [
        registered(target(0x30), organization(10), "api-a"),
        CredentialEvent::ResourceServerDisabled {
            context: context(organization(10)),
            id: target(0x30),
        },
        issued(credential(0x40), organization(10), "api-a"),
        CredentialEvent::CredentialSelfContainedIssued {
            context: context(organization(10)),
            credential_id: credential(0x41),
            reference_verifier: None,
            epochs: None,
            issued_at: Timestamp::new("2026-09-19T00:00:00Z"),
            descriptor: descriptor(organization(10), "api-a"),
            target: target(0x30),
            requested_scope: AuthorityScope {
                actions: Vec::new(),
                resources: Vec::new(),
                space: None,
            },
        },
        CredentialEvent::AccessCredentialRevoked {
            context: context(organization(10)),
            id: credential(0x40),
        },
        CredentialEvent::CredentialIntrospected {
            context: context(organization(10)),
            descriptor: None,
            active: false,
            credential_id: None,
        },
        key_registered(key(0x70), "kms://one", "thumb-one"),
        CredentialEvent::SigningKeyRetired {
            context: context(organization(10)),
            id: key(0x70),
        },
        CredentialEvent::SigningKeyRevoked {
            context: context(organization(10)),
            id: key(0x70),
        },
        redeemed(credential(0x42), organization(10), "api-a"),
    ]
    .iter()
    .map(CredentialEvent::ess_name)
    .collect();

    assert_eq!(
        names,
        [
            "mandate.credential.ResourceServerRegistered",
            "mandate.credential.ResourceServerDisabled",
            "mandate.credential.CredentialReferenceIssued",
            "mandate.credential.CredentialSelfContainedIssued",
            "mandate.credential.AccessCredentialRevoked",
            "mandate.credential.CredentialIntrospected",
            "mandate.credential.SigningKeyRegistered",
            "mandate.credential.SigningKeyRetired",
            "mandate.credential.SigningKeyRevoked",
            "mandate.credential.AuthorizationCodeRedeemed",
        ]
    );
}

/// **Every lifecycle arm honours the declared `from:` set of the transition its event is.**
///
/// The class, enumerated: four lifecycle events over three records, each applied to a record
/// already in a state its transition does not start from — the shape the kit's at-least-once
/// delivery produces, by redelivery or by late delivery. None of them moves the record.
///
/// `SigningKey` is the one record where this is not free: it has two terminal states and a
/// `revoke` that starts from the other one, so writing the state an event names without
/// asking which state the record is in returns a revoked key to `Retired`. The other three
/// arms are idempotent by having one terminal state each, and are listed here because a rule
/// that is only checked where it currently bites is a rule that stops being checked when the
/// contract grows a second terminal state somewhere else.
#[test]
fn every_lifecycle_arm_leaves_a_record_its_transition_does_not_start_from_alone() {
    let base = vec![
        registered(target(0x30), organization(10), "api-a"),
        issued(credential(0x40), organization(10), "api-a"),
        key_registered(key(0x70), "kms://one", "thumb-one"),
    ];

    // `ResourceServer.disable` starts from `Enabled`; a second disablement changes nothing.
    let mut log = base.clone();
    log.push(CredentialEvent::ResourceServerDisabled {
        context: context(organization(10)),
        id: target(0x30),
    });
    log.push(CredentialEvent::ResourceServerDisabled {
        context: context(organization(10)),
        id: target(0x30),
    });
    assert_eq!(
        Projection::fold(&log)
            .expect("a redelivery is readable")
            .resource_server(&target(0x30))
            .map(|record| record.state),
        Some(ResourceServerState::Disabled)
    );

    // `AccessCredential.revoke` starts from `Active`; a second revocation changes nothing.
    let mut log = base.clone();
    log.push(CredentialEvent::AccessCredentialRevoked {
        context: context(organization(10)),
        id: credential(0x40),
    });
    log.push(CredentialEvent::AccessCredentialRevoked {
        context: context(organization(10)),
        id: credential(0x40),
    });
    assert_eq!(
        Projection::fold(&log)
            .expect("a redelivery is readable")
            .access_credential(&credential(0x40))
            .map(|record| record.state),
        Some(AccessCredentialState::Revoked)
    );

    // `SigningKey.retire` starts from `Recorded` alone: a retirement after the revocation
    // that followed it leaves the key revoked.
    let mut log = base.clone();
    log.push(CredentialEvent::SigningKeyRevoked {
        context: context(organization(10)),
        id: key(0x70),
    });
    log.push(CredentialEvent::SigningKeyRetired {
        context: context(organization(10)),
        id: key(0x70),
    });
    assert_eq!(
        Projection::fold(&log)
            .expect("a late delivery is readable")
            .signing_key(&key(0x70))
            .map(|record| record.state),
        Some(SigningKeyState::Revoked)
    );

    // `SigningKey.revoke` starts from `Recorded` and `Retired`; a second revocation changes
    // nothing, and a retirement redelivered after it still does not.
    let mut log = base;
    log.push(CredentialEvent::SigningKeyRetired {
        context: context(organization(10)),
        id: key(0x70),
    });
    log.push(CredentialEvent::SigningKeyRevoked {
        context: context(organization(10)),
        id: key(0x70),
    });
    log.push(CredentialEvent::SigningKeyRevoked {
        context: context(organization(10)),
        id: key(0x70),
    });
    log.push(CredentialEvent::SigningKeyRetired {
        context: context(organization(10)),
        id: key(0x70),
    });
    assert_eq!(
        Projection::fold(&log)
            .expect("a redelivery is readable")
            .signing_key(&key(0x70))
            .map(|record| record.state),
        Some(SigningKeyState::Revoked)
    );
}

//! Adversary pass 2 against `story:credential-profiles`, `projection` unit.
//!
//! The target is the fold's own account of what it may refuse
//! (`crates/mandate-token/src/projection.rs`, module documentation):
//!
//! > [`Projection::apply`] is the **write** half: it writes what it is handed and re-checks
//! > no guard. Every guard belongs to a handler in `services/sts` ... What the fold does
//! > refuse is a log it cannot *read*.
//!
//! The same module states the one uniqueness guard it deliberately does **not** make a fold
//! refusal, and why:
//!
//! > Two writers that each read a free `(organization_id, audience)` append to two
//! > `ResourceServer` aggregates, so the kit's compare-and-set on the appending stream does
//! > not see the other: the log is the record of both registrations.
//!
//! `mandate.credential.SigningKey` carries two uniqueness guards of exactly that shape —
//! `key_reference` and `thumbprint` — decided by a read-then-write handler
//! (`services/sts/src/keys.rs`, `SigningKeyAdministration::register`) whose documentation
//! names no atomic storage index, where `Projection::admits_audience` names one
//! ("storage enforces the same index atomically"). So the racing pair is at least as
//! reachable for a key as for an audience, and the fold's treatment of the two is opposite:
//! the audience pair folds and is reported through `Projection::audience_conflicts`, while
//! the key pair returns `FoldError` from `Projection::fold`, which is all-or-nothing.
//!
//! Under `docs/adr/0009-event-sourced-persistence.md` — "the events are the record; every
//! read is a fold over them" — an all-or-nothing refusal is not a refusal of one key. It is
//! the loss of every `ResourceServer` and every `AccessCredential` the log carries.

use mandate_token::projection::{CredentialEvent, Projection};
use mandate_token::{CredentialDescriptor, CredentialProfile};
use mandate_types::{
    Audience, AuthorityScope, CorrelationId, CredentialId, CredentialKind, CredentialVerifier,
    Duration, KeyReference, OrganizationId, PrincipalId, ResourceServerId, RevocationGuarantee,
    SigningAlgorithm, SigningKeyId, Timestamp, Uuid, VerifiedContext,
};

/// A uuid built from a record prefix and an ordinal, so two records of one kind are
/// distinct and order the way `Projection::registered` orders them.
fn tagged(prefix: u8, ordinal: u8) -> Uuid {
    Uuid::from_bytes([
        prefix, ordinal, 0x28, 0xba, 0x2f, 0xa1, 0x4d, 0x8e, 0xb1, 0xb0, 0x8c, 0x1d, 0x4e, 0x5f,
        0x6a, 0x7b,
    ])
}

fn organization() -> OrganizationId {
    OrganizationId::new(tagged(0x0a, 0))
}

fn server(ordinal: u8) -> ResourceServerId {
    ResourceServerId::new(tagged(0x30, ordinal))
}

fn credential(ordinal: u8) -> CredentialId {
    CredentialId::new(tagged(0xcd, ordinal))
}

fn key(ordinal: u8) -> SigningKeyId {
    SigningKeyId::new(tagged(0x7e, ordinal))
}

fn context() -> VerifiedContext {
    VerifiedContext {
        subject: PrincipalId::new(tagged(0x51, 0)),
        actor: None,
        organization: organization(),
        audience: Audience::new("mandate"),
        credential: credential(0),
        delegation: None,
        execution: None,
        correlation: CorrelationId::new("adversary-profiles-2"),
    }
}

fn profile() -> CredentialProfile {
    CredentialProfile {
        name: "reference".to_owned(),
        kind: CredentialKind::Reference,
        revocation: RevocationGuarantee::ImmediateOnline,
        max_ttl: Duration::new("PT1H"),
        positive_cache_ttl: Duration::new("PT30S"),
        requires_online_authorization: true,
    }
}

fn descriptor() -> CredentialDescriptor {
    CredentialDescriptor {
        kind: CredentialKind::Reference,
        subject: PrincipalId::new(tagged(0x52, 0)),
        actor: None,
        organization: organization(),
        audience: Audience::new("api-a"),
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

fn registration(id: ResourceServerId, audience: &str) -> CredentialEvent {
    CredentialEvent::ResourceServerRegistered {
        context: context(),
        id,
        audience: Audience::new(audience),
        credential_profile: profile(),
        allowed_exchange_sources: Vec::new(),
    }
}

fn issuance(id: CredentialId, target: ResourceServerId) -> CredentialEvent {
    CredentialEvent::CredentialReferenceIssued {
        context: context(),
        credential_id: id,
        reference_verifier: Some(CredentialVerifier::new(format!("verifier-{id}"))),
        epochs: None,
        issued_at: Timestamp::new("2026-09-19T00:00:00Z"),
        descriptor: descriptor(),
        target,
        requested_scope: AuthorityScope {
            actions: Vec::new(),
            resources: Vec::new(),
            space: None,
        },
    }
}

fn key_registered(id: SigningKeyId, reference: &str, thumbprint: &str) -> CredentialEvent {
    CredentialEvent::SigningKeyRegistered {
        context: context(),
        id,
        key_reference: KeyReference::new(reference),
        thumbprint: thumbprint.to_owned(),
        algorithm: SigningAlgorithm::new("declared-by-deployment"),
        not_before: Timestamp::new("2026-09-19T00:00:00Z"),
        expires_at: Timestamp::new("2026-12-31T00:00:00Z"),
    }
}

/// The registry and the credentials of a log survive a second key on one `key_reference`.
///
/// The racing pair is the one the module documents for the audience index, applied to the
/// guard beside it: two `RegisterSigningKey` writers each read a free reference and each
/// append to their own `SigningKey` aggregate, so neither compare-and-set sees the other.
/// `SigningKeyAdministration::register` names no atomic storage index for this guard, where
/// `Projection::admits_audience` does name one for the audience — so if either pair can be
/// appended, this one can.
///
/// What the fold then does is not "refuse the second key". `Projection::fold` returns
/// `Err(FoldError::KeyReferenceRecorded)` for the whole log, so the `ResourceServer` and the
/// `AccessCredential` the same log carries are unreadable — and under ADR 0009 there is no
/// other place to read them from.
#[test]
fn a_second_key_on_one_reference_makes_every_other_record_of_the_log_unreadable() {
    let readable = vec![
        registration(server(1), "api-a"),
        issuance(credential(1), server(1)),
        key_registered(key(1), "kms://one", "thumb-one"),
    ];
    let held = Projection::fold(&readable).expect("a log of accepted events");
    assert!(held.resource_server(&server(1)).is_some());
    assert!(held.access_credential(&credential(1)).is_some());
    assert_eq!(held.signing_keys().len(), 1);

    // The second writer's append: its own `SigningKey` aggregate, a reference that was free
    // when it read, and a thumbprint of its own so the reference is the only collision.
    let mut raced = readable;
    raced.push(key_registered(key(2), "kms://one", "thumb-two"));

    let rebuilt = Projection::fold(&raced).unwrap_or_else(|error| {
        panic!(
            "the fold refused the whole log for one duplicated key reference, so the \
             registration and the credential it also carries are unreadable — the sibling \
             uniqueness conflict on an audience is deliberately not a fold refusal, and \
             this guard's handler names no atomic index where `admits_audience` does: \
             {error}"
        )
    });
    assert!(
        rebuilt.resource_server(&server(1)).is_some(),
        "the registration is gone with the key"
    );
    assert!(
        rebuilt.access_credential(&credential(1)).is_some(),
        "the credential is gone with the key"
    );
}

/// The control: the sibling uniqueness conflict, one record along, on the same shaped log.
///
/// Two `ResourceServerRegistered` on one `(organization_id, audience)` — the pair the module
/// documents as the log being "the record of both registrations" — fold, the loser is
/// reported through `Projection::audience_conflicts`, and the credential of the log is still
/// there. It passes, which is what makes the case above a statement about the fold's
/// treatment of the key guards and not about how this file builds a log.
#[test]
fn the_sibling_uniqueness_conflict_on_an_audience_leaves_the_log_readable() {
    let log = vec![
        registration(server(1), "api-a"),
        registration(server(2), "api-a"),
        issuance(credential(1), server(1)),
    ];

    let held = Projection::fold(&log).expect("the audience index is a view, not a refusal");

    assert_eq!(held.resource_servers().len(), 2);
    assert_eq!(
        held.registered(&organization(), &Audience::new("api-a"))
            .map(|holder| holder.id),
        Some(server(1)),
        "the smallest identity among the enabled records holds the key"
    );
    assert_eq!(
        held.audience_conflicts()
            .iter()
            .map(|conflict| conflict.id)
            .collect::<Vec<_>>(),
        vec![server(2)]
    );
    assert!(held.access_credential(&credential(1)).is_some());
}

//! Adversarial cases against `story:credential-profiles`, `projection` unit.
//!
//! The target is the fold's own stated rule
//! (`crates/mandate-token/src/projection.rs`, `Projection::apply`):
//!
//! > Writing a record is insert-if-absent at the record's own identity, because the kit's
//! > at-least-once delivery admits a redelivered creation: applying one twice must write
//! > nothing rather than **return a record from a terminal state to its initial one**.
//!
//! `mandate.credential.SigningKey` is the one record of this domain with two terminal
//! states — `Retired` and `Revoked` — and one transition (`revoke`) that starts from the
//! other terminal state. `SigningKeyRetired` and `SigningKeyRevoked` are therefore *not*
//! interchangeable under redelivery the way `ResourceServerDisabled` and
//! `AccessCredentialRevoked` are, and the fold's `move_key` writes the state it is handed
//! without asking which state the record is in.
//!
//! What that costs: `credential.yaml` says a retired key "remains admitted for verifying
//! credentials already issued under it", while a revoked one "is admitted for neither
//! issuance nor verification, and the self-contained credentials it signed are refused from
//! that point". `services/sts/src/lib.rs` names rehydrating
//! `RealSigner::new_with_revocations` from this fold — "every `Revoked` key's `id` and
//! `thumbprint`" — as the composition's next step, so a key this fold rebuilds as `Retired`
//! is a key the restarted signer does not know was compromised.

use mandate_token::projection::{
    AccessCredentialState, CredentialEvent, Projection, ResourceServerState, SigningKeyState,
};
use mandate_token::{CredentialDescriptor, CredentialProfile};
use mandate_types::{
    Audience, AuthorityScope, CorrelationId, CredentialId, CredentialKind, CredentialVerifier,
    Duration, KeyReference, OrganizationId, PrincipalId, ResourceServerId, RevocationGuarantee,
    SigningAlgorithm, SigningKeyId, Timestamp, Uuid, VerifiedContext,
};

fn uuid(tag: u8) -> Uuid {
    Uuid::from_bytes([tag; 16])
}

fn organization() -> OrganizationId {
    OrganizationId::new(uuid(10))
}

fn key() -> SigningKeyId {
    SigningKeyId::new(uuid(0x70))
}

fn server() -> ResourceServerId {
    ResourceServerId::new(uuid(0x30))
}

fn credential() -> CredentialId {
    CredentialId::new(uuid(0x40))
}

fn context() -> VerifiedContext {
    VerifiedContext {
        subject: PrincipalId::new(uuid(0x51)),
        actor: None,
        organization: organization(),
        audience: Audience::new("mandate"),
        credential: CredentialId::new(uuid(0xcd)),
        delegation: None,
        execution: None,
        correlation: CorrelationId::new("adversary-profiles-1"),
    }
}

fn key_registered() -> CredentialEvent {
    CredentialEvent::SigningKeyRegistered {
        context: context(),
        id: key(),
        key_reference: KeyReference::new("kms://one"),
        thumbprint: "thumb-one".to_owned(),
        algorithm: SigningAlgorithm::new("declared-by-deployment"),
        not_before: Timestamp::new("2026-09-19T00:00:00Z"),
        expires_at: Timestamp::new("2026-12-31T00:00:00Z"),
    }
}

fn retired() -> CredentialEvent {
    CredentialEvent::SigningKeyRetired {
        context: context(),
        id: key(),
    }
}

fn revoked() -> CredentialEvent {
    CredentialEvent::SigningKeyRevoked {
        context: context(),
        id: key(),
    }
}

/// Whatever the fold decides, a key the log revoked is never rebuilt out of `Revoked`.
///
/// Two readings are admissible and this asserts neither over the other: the fold may refuse
/// the log outright (`apply` after a terminal state "refuses ... per the contract's
/// `wrong-state`"), or it may ignore the undeclared move and leave the record where the
/// revocation put it. `Retired` is the one answer no reading of `credential.yaml` reaches:
/// `retire` starts `from: [Recorded]`, and `Revoked` is declared terminal.
fn a_revoked_key_is_never_retired(log: &[CredentialEvent], what: &str) {
    match Projection::fold(log) {
        // A log the fold refuses is a log it did not misread.
        Err(_) => {}
        Ok(held) => {
            let state = held.signing_key(&key()).map(|record| record.state);
            assert_eq!(
                state,
                Some(SigningKeyState::Revoked),
                "{what}: the key was revoked and the fold rebuilt it as {state:?}; \
                 `mandate.credential.SigningKey.revoke` is declared terminal and \
                 `retire` starts from `Recorded` alone"
            );
        }
    }
}

/// A `SigningKeyRetired` redelivered after the revocation that followed it.
///
/// The exact shape the module documentation names: at-least-once delivery, one event seen
/// twice, the second sighting arriving after the record reached a terminal state.
#[test]
fn a_retirement_redelivered_after_a_revocation_returns_the_key_from_its_terminal_state() {
    let log = vec![key_registered(), retired(), revoked(), retired()];

    a_revoked_key_is_never_retired(&log, "a redelivered retirement");
}

/// The same defect reached by ordering rather than by duplication: a retirement the kit
/// delivers after the revocation.
#[test]
fn a_retirement_delivered_after_a_revocation_returns_the_key_from_its_terminal_state() {
    let log = vec![key_registered(), revoked(), retired()];

    a_revoked_key_is_never_retired(&log, "a late retirement");
}

/// The control: the same probe against the domain's other two records, whose single
/// terminal state makes the write idempotent.
///
/// It passes, which is what makes the two cases above a statement about `move_key` and not
/// about how this file builds a log.
#[test]
fn the_other_two_records_keep_their_terminal_state_under_the_same_redelivery() {
    let profile = CredentialProfile {
        name: "reference".to_owned(),
        kind: CredentialKind::Reference,
        revocation: RevocationGuarantee::ImmediateOnline,
        max_ttl: Duration::new("PT1H"),
        positive_cache_ttl: Duration::new("PT30S"),
        requires_online_authorization: true,
    };
    let scope = AuthorityScope {
        actions: Vec::new(),
        resources: Vec::new(),
        space: None,
    };
    let descriptor = CredentialDescriptor {
        kind: CredentialKind::Reference,
        subject: PrincipalId::new(uuid(0x51)),
        actor: None,
        organization: organization(),
        audience: Audience::new("api-a"),
        scope: scope.clone(),
        delegation: None,
        execution: None,
        expires_at: Timestamp::new("2026-09-19T01:00:00Z"),
    };
    let log = vec![
        CredentialEvent::ResourceServerRegistered {
            context: context(),
            id: server(),
            audience: Audience::new("api-a"),
            credential_profile: profile,
            allowed_exchange_sources: Vec::new(),
        },
        CredentialEvent::ResourceServerDisabled {
            context: context(),
            id: server(),
        },
        CredentialEvent::ResourceServerDisabled {
            context: context(),
            id: server(),
        },
        CredentialEvent::CredentialReferenceIssued {
            context: context(),
            credential_id: credential(),
            reference_verifier: Some(CredentialVerifier::new("digest-of-the-secret")),
            epochs: None,
            issued_at: Timestamp::new("2026-09-19T00:00:00Z"),
            descriptor,
            target: server(),
            requested_scope: scope,
        },
        CredentialEvent::AccessCredentialRevoked {
            context: context(),
            id: credential(),
        },
        CredentialEvent::AccessCredentialRevoked {
            context: context(),
            id: credential(),
        },
    ];

    let held = Projection::fold(&log).expect("a redelivery is not a second record");

    assert_eq!(
        held.resource_server(&server()).map(|record| record.state),
        Some(ResourceServerState::Disabled)
    );
    assert_eq!(
        held.access_credential(&credential())
            .map(|record| record.state),
        Some(AccessCredentialState::Revoked)
    );
}

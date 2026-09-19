//! Adversarial cases against the credential half of
//! `mandate.credential.AuthorizationCodeRedeemed`, which `story:oauth-transaction` added to
//! this crate's fold.
//!
//! Two lines of attack this crate's own suite does not take.
//!
//! - **The generated JSON schema.** `crates/mandate-token/tests/contract_agreement.rs` round
//!   trips every payload through the generated *Rust* shape, whose optionals are
//!   `Presence<T>`; nothing here validates a payload against
//!   `generated/schema/events/*.schema.json`, which is where `additionalProperties: false`,
//!   `required`, `pattern` and `format` are decided and where an absent optional written as
//!   `null` is refused. `services/sts` validates the payloads *it* emits; this crate declares
//!   the same payload and is where a fold reads it.
//! - **"the same record from the same two sources".** `credential.yaml`'s header says the
//!   redeemed event "carries the whole AccessCredential record ... exactly the record fields
//!   `mandate.credential.CredentialReferenceIssued` carries", and
//!   `crates/mandate-token/src/projection.rs` writes all three creators through one body. The
//!   case that decides it is the matrix: the same record fields on each of the three
//!   creating events must fold to the same `AccessCredential`, with every optional carried
//!   and with none of them.

use mandate_testkit::contract::assert_event_conforms;
use mandate_token::projection::{
    AccessCredential, AccessCredentialState, CredentialEvent, FoldError, Projection,
};
use mandate_token::{CredentialDescriptor, CredentialProfile};
use mandate_types::{
    Audience, AuthorityScope, AuthorizationCodeId, CorrelationId, CredentialId, CredentialKind,
    CredentialVerifier, DelegationId, Duration, EpochSnapshotRef, ExecutionId, OrganizationId,
    PrincipalId, ResourceServerId, RevocationGuarantee, Timestamp, Uuid, VerifiedContext,
};
use serde_json::Value;

fn uuid(tag: u8) -> Uuid {
    Uuid::from_bytes([tag; 16])
}

fn organization() -> OrganizationId {
    OrganizationId::new(uuid(10))
}

fn target() -> ResourceServerId {
    ResourceServerId::new(uuid(0x30))
}

fn credential() -> CredentialId {
    CredentialId::new(uuid(0x42))
}

fn code_id() -> AuthorizationCodeId {
    AuthorizationCodeId::new(uuid(0xac))
}

fn scope() -> AuthorityScope {
    AuthorityScope {
        actions: Vec::new(),
        resources: Vec::new(),
        space: None,
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

/// A context carrying every optional, or none of them.
fn context(carried: bool) -> VerifiedContext {
    VerifiedContext {
        subject: PrincipalId::new(uuid(0x51)),
        actor: carried.then(|| PrincipalId::new(uuid(0x52))),
        organization: organization(),
        audience: Audience::new("api-a"),
        credential: credential(),
        delegation: carried.then(|| DelegationId::new(uuid(0x53))),
        execution: carried.then(|| ExecutionId::new(uuid(0x54))),
        correlation: CorrelationId::new("adversary"),
    }
}

/// A descriptor carrying every optional, or none of them.
fn descriptor(carried: bool) -> CredentialDescriptor {
    CredentialDescriptor {
        kind: CredentialKind::Reference,
        subject: PrincipalId::new(uuid(0x51)),
        actor: carried.then(|| PrincipalId::new(uuid(0x52))),
        organization: organization(),
        audience: Audience::new("api-a"),
        scope: scope(),
        delegation: carried.then(|| DelegationId::new(uuid(0x53))),
        execution: carried.then(|| ExecutionId::new(uuid(0x54))),
        expires_at: Timestamp::new("2026-09-19T01:00:00Z"),
    }
}

fn registered() -> CredentialEvent {
    CredentialEvent::ResourceServerRegistered {
        context: context(false),
        id: target(),
        audience: Audience::new("api-a"),
        credential_profile: reference_profile(),
        allowed_exchange_sources: Vec::new(),
    }
}

fn redeemed(carried: bool) -> CredentialEvent {
    redeemed_for(carried, credential(), target())
}

fn redeemed_for(
    carried: bool,
    credential_id: CredentialId,
    target: ResourceServerId,
) -> CredentialEvent {
    CredentialEvent::AuthorizationCodeRedeemed {
        context: context(carried),
        code_id: code_id(),
        credential_id,
        reference_verifier: carried.then(|| CredentialVerifier::new("digest-of-the-secret")),
        epochs: carried.then(|| EpochSnapshotRef::new(uuid(0x60))),
        issued_at: Timestamp::new("2026-09-19T00:00:00Z"),
        descriptor: descriptor(carried),
        target,
    }
}

fn reference_issued(carried: bool) -> CredentialEvent {
    reference_issued_for(carried, credential())
}

fn reference_issued_for(carried: bool, credential_id: CredentialId) -> CredentialEvent {
    CredentialEvent::CredentialReferenceIssued {
        context: context(carried),
        credential_id,
        reference_verifier: carried.then(|| CredentialVerifier::new("digest-of-the-secret")),
        epochs: carried.then(|| EpochSnapshotRef::new(uuid(0x60))),
        issued_at: Timestamp::new("2026-09-19T00:00:00Z"),
        descriptor: descriptor(carried),
        target: target(),
        requested_scope: scope(),
    }
}

fn self_contained_issued(carried: bool) -> CredentialEvent {
    CredentialEvent::CredentialSelfContainedIssued {
        context: context(carried),
        credential_id: credential(),
        reference_verifier: carried.then(|| CredentialVerifier::new("digest-of-the-secret")),
        epochs: carried.then(|| EpochSnapshotRef::new(uuid(0x60))),
        issued_at: Timestamp::new("2026-09-19T00:00:00Z"),
        descriptor: descriptor(carried),
        target: target(),
        requested_scope: scope(),
    }
}

/// Every key a JSON document carries, at any depth, that is `null`.
fn null_paths(document: &Value, path: &str, found: &mut Vec<String>) {
    match document {
        Value::Null => found.push(path.to_owned()),
        Value::Object(fields) => {
            for (key, value) in fields {
                null_paths(value, &format!("{path}/{key}"), found);
            }
        }
        Value::Array(items) => {
            for (index, value) in items.iter().enumerate() {
                null_paths(value, &format!("{path}/{index}"), found);
            }
        }
        _ => {}
    }
}

/// **The payload this crate declares conforms to the generated schema, carried and bare.**
///
/// `additionalProperties: false`, `required`, the `uuid` pattern and the `date-time` format
/// are all decided by `generated/schema/events/mandate.credential.AuthorizationCodeRedeemed.schema.json`
/// and by nothing this crate's suite runs. The bare form is the half that matters: the
/// schema spells absence by leaving the key out, so an optional written as `null` is
/// refused, and the generated Rust shape's `Presence<T>` would accept it.
///
/// Holds against the tree.
#[test]
fn the_redeemed_payload_conforms_to_the_generated_schema_carried_and_bare() {
    for carried in [true, false] {
        let event = redeemed(carried);
        assert_eq!(
            event.ess_name(),
            "mandate.credential.AuthorizationCodeRedeemed"
        );
        let payload = serde_json::to_value(&event).expect("the payload encodes as JSON");
        assert_event_conforms(event.ess_name(), &payload);

        let mut nulls = Vec::new();
        null_paths(&payload, "", &mut nulls);
        assert!(
            nulls.is_empty(),
            "carried={carried}: an absent optional is written as null at {nulls:?}: {payload}"
        );
        assert!(
            !payload.to_string().contains("REDACTED"),
            "carried={carried}: a redaction marker reached the payload: {payload}"
        );
        if !carried {
            assert_eq!(payload.get("reference_verifier"), None);
            assert_eq!(payload.get("epochs"), None);
            assert_eq!(payload["context"].get("actor"), None);
            assert_eq!(payload["descriptor"].get("delegation"), None);
        }
    }
}

/// **The three creating events fold to the same record, carried and bare.**
///
/// `credential.yaml`'s header: the redeemed event "carries the whole AccessCredential record
/// ... exactly the record fields `mandate.credential.CredentialReferenceIssued` carries", and
/// `crates/mandate-token/src/projection.rs`'s `record_credential` is the one body all three
/// go through. The matrix is what decides it: same record fields in, same
/// `AccessCredential` out — including `issuing_profile`, which is read from the registration
/// the log already holds and not from the event.
///
/// Holds against the tree.
#[test]
fn every_creating_event_folds_to_the_same_access_credential_record() {
    for carried in [true, false] {
        let expected = AccessCredential {
            id: credential(),
            descriptor: descriptor(carried),
            reference_verifier: carried.then(|| CredentialVerifier::new("digest-of-the-secret")),
            epochs: carried.then(|| EpochSnapshotRef::new(uuid(0x60))),
            issued_at: Timestamp::new("2026-09-19T00:00:00Z"),
            state: AccessCredentialState::Active,
            target: target(),
            issuing_profile: reference_profile(),
        };
        for (what, creator) in [
            ("CredentialReferenceIssued", reference_issued(carried)),
            (
                "CredentialSelfContainedIssued",
                self_contained_issued(carried),
            ),
            ("AuthorizationCodeRedeemed", redeemed(carried)),
        ] {
            let held = Projection::fold(&[registered(), creator])
                .unwrap_or_else(|error| panic!("{what} (carried={carried}): {error}"));
            assert_eq!(
                held.access_credential(&credential()),
                Some(expected.clone()),
                "{what} (carried={carried}) folds to the record the other creators fold to"
            );
            assert_eq!(held.credentials().len(), 1, "{what}");
        }
    }
}

/// **A redemption naming a target no event registered is a log the fold cannot read, and it
/// writes nothing before it says so.**
///
/// The refusal `CredentialReferenceIssued` gets, for the reason `AccessCredential` gives: the
/// guarantee a credential carries is the one published by the registration it was issued
/// under, so a log that cannot answer it is not a log this fold can read. The half the unit's
/// own case does not decide is that the refusal is total — the record is not half written,
/// and a credential created earlier in the same log is left alone.
///
/// Holds against the tree.
#[test]
fn a_redemption_naming_an_unregistered_target_writes_nothing_at_all() {
    let other = CredentialId::new(uuid(0x43));
    let log = vec![
        registered(),
        reference_issued_for(true, other),
        redeemed_for(true, credential(), ResourceServerId::new(uuid(0x31))),
    ];

    assert_eq!(
        Projection::fold(&log),
        Err(FoldError::UnknownIssuingTarget {
            id: credential(),
            target: ResourceServerId::new(uuid(0x31)),
        })
    );

    // The same log up to the unreadable event is readable, and holds only the credential the
    // readable half created: the refusal is the whole fold's, not a partial write.
    let readable = Projection::fold(&log[..2]).expect("the registration and one issuance");
    assert_eq!(readable.credentials().len(), 1);
    assert!(readable.access_credential(&other).is_some());
    assert!(readable.access_credential(&credential()).is_none());
}

/// **A redelivered redemption does not resurrect a revoked credential.**
///
/// The kit's delivery is at-least-once, and `record_credential` is insert-if-absent "at the
/// record's own identity". Insert-if-absent that tested the *state* rather than the identity
/// would move a revoked credential back to `Active` on a redelivery — the one mutation of
/// that body a suite testing redelivery against a fresh record cannot see.
///
/// Holds against the tree.
#[test]
fn a_redelivered_redemption_does_not_resurrect_a_revoked_credential() {
    let log = vec![
        registered(),
        redeemed(true),
        CredentialEvent::AccessCredentialRevoked {
            context: context(false),
            id: credential(),
        },
        redeemed(true),
    ];

    let held = Projection::fold(&log).expect("a creation, its move, and a redelivery");

    assert_eq!(
        held.access_credential(&credential())
            .map(|record| record.state),
        Some(AccessCredentialState::Revoked),
        "the terminal state is not left by a redelivered creation"
    );
    assert_eq!(held.credentials().len(), 1);

    // And a redelivery of the *other* family's creation for the same identity is the same
    // answer: the guard is the identity and never the event.
    let held = Projection::fold(&[
        registered(),
        redeemed(true),
        CredentialEvent::AccessCredentialRevoked {
            context: context(false),
            id: credential(),
        },
        reference_issued(true),
    ])
    .expect("a creation, its move, and another creator for the same identity");
    assert_eq!(
        held.access_credential(&credential())
            .map(|record| record.state),
        Some(AccessCredentialState::Revoked)
    );
    assert_eq!(held.credentials().len(), 1);
}

/// **`apply` on a live projection and `fold` from `&[]` agree, field for field, with the
/// redemption arm in the log.**
///
/// `docs/adr/0009-event-sourced-persistence.md`: the read model is the fold, and a live
/// projection that drifted from a rebuild would be a record no log supports.
///
/// Holds against the tree.
#[test]
fn the_live_projection_and_the_rebuild_agree_with_the_redemption_arm_in_the_log() {
    let log = vec![
        registered(),
        redeemed(true),
        reference_issued_for(false, CredentialId::new(uuid(0x43))),
        CredentialEvent::AccessCredentialRevoked {
            context: context(false),
            id: credential(),
        },
    ];

    let mut live = Projection::default();
    for event in &log {
        live.apply(event).expect("a log of accepted events");
    }

    assert_eq!(
        Projection::fold(&log).expect("the same log"),
        live,
        "the rebuild is the live projection"
    );
    assert_eq!(
        Projection::fold(&[]).expect("an empty log"),
        Projection::default()
    );
    assert_eq!(live.credentials().len(), 2);
}

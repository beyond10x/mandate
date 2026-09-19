//! What each handler emits, decided against the contract rather than against this file.
//!
//! Every accepted outcome is put through the three checks
//! `crates/mandate-testkit/src/contract.rs` performs, each reading a generated projection
//! and nothing else: the payload against `generated/schema/events/<name>.schema.json`, the
//! emission against the outcome the IR declares, and every payload field against the
//! source the contract declares for it.
//!
//! The denied paths are checked the same way: the refusal names the outcome it is
//! ([`mandate_identity::RefusedOutcome`]), that outcome is looked up in the IR, and the
//! emission list handed to the harness is empty — so "a denial emits nothing" is decided
//! against the contract's declaration of that outcome. Each denied case also asserts the
//! log is the one it was, which is `mandate.identity.Denied`'s "no credential, authority
//! or lifecycle mutation on refusal" in the only form a fold can carry.

use mandate_identity::{
    EpochSnapshotRecorded, Generation, IdentityEvent, IdentityLog, IdentityRead,
    IncrementSecurityEpoch, RefusedOutcome, SecurityEpochRecorded, SecurityEpochWrite,
    SessionOpened, StreamVersion, revoke_session,
};
use mandate_testkit::contract::{
    assert_event_conforms, assert_payload_sources, assert_single_emission,
};
use mandate_types::{
    Audience, CorrelationId, CredentialId, DenialReason, EpochSnapshotRef, OrganizationId,
    PrincipalId, SecurityEpochTarget, SessionId, Timestamp, Uuid, VerifiedContext,
};
use serde::Serialize;
use serde_json::{Value, json};

const INCREMENT: &str = "mandate.identity.IncrementSecurityEpoch";
const REVOKE: &str = "mandate.identity.RevokeSession";

fn uuid(tag: u8) -> Uuid {
    Uuid::from_bytes([tag; 16])
}

fn principal() -> PrincipalId {
    PrincipalId::new(uuid(1))
}

fn organization() -> OrganizationId {
    OrganizationId::new(uuid(2))
}

fn handle() -> EpochSnapshotRef {
    EpochSnapshotRef::new(uuid(10))
}

fn session_id() -> SessionId {
    SessionId::new(uuid(20))
}

fn context() -> VerifiedContext {
    VerifiedContext {
        subject: principal(),
        actor: None,
        organization: organization(),
        audience: Audience::new("mandate"),
        credential: CredentialId::new(uuid(0xcd)),
        delegation: None,
        execution: None,
        correlation: CorrelationId::new("identity-alignment"),
    }
}

fn encoded<T: Serialize>(value: &T) -> Value {
    serde_json::to_value(value).expect("a declared value encodes as JSON")
}

/// One accepted outcome, through all three checks.
///
/// The element is the one the event answers ([`IdentityEvent::ess_name`]) and never a
/// literal written here: `assert_single_emission` reads what the IR declares the command's
/// accepted outcome emits, so a name the event answered wrongly fails against the contract
/// rather than against a string this file repeats. The schema cannot decide it — the three
/// declared `{context, id}` payloads of this domain are structurally identical — so the
/// emission lookup is the oracle.
fn accepted(command: &str, input: &Value, event: &IdentityEvent) {
    let document = encoded(event);
    let element = event.ess_name();
    assert_single_emission(command, "accepted", &[(element, &document)]);
    assert_event_conforms(element, &document);
    assert_payload_sources(command, input, None, element, &document);
}

/// One refused outcome: the outcome the refusal names is declared by the contract, and it
/// emitted nothing.
fn refused(command: &str, denial: &mandate_identity::Denial) {
    assert_single_emission(command, denial.outcome().ir_name(), &[]);
}

/// One principal and organization at known generations, one snapshot against them, and one
/// active session bound to it.
fn world() -> IdentityLog {
    let mut log = IdentityLog::new().with_as_of(Timestamp::new("2026-09-19T00:00:00Z"));
    log.record(IdentityEvent::SecurityEpochRecorded(
        SecurityEpochRecorded {
            target: SecurityEpochTarget::Principal(principal()),
            generation: Generation::new(3).expect("a non-negative generation"),
        },
    ));
    log.record(IdentityEvent::SecurityEpochRecorded(
        SecurityEpochRecorded {
            target: SecurityEpochTarget::Organization(organization()),
            generation: Generation::new(7).expect("a non-negative generation"),
        },
    ));
    log.record(IdentityEvent::EpochSnapshotRecorded(
        EpochSnapshotRecorded {
            id: handle(),
            principal_id: principal(),
            organization_id: organization(),
            connection_id: None,
        },
    ));
    log.record(IdentityEvent::SessionOpened(SessionOpened {
        id: session_id(),
        principal_id: principal(),
        organization_id: organization(),
        connection_id: None,
        epochs: handle(),
        expires_at: Timestamp::new("2026-12-31T00:00:00Z"),
    }));
    log
}

#[test]
fn increment_security_epoch_emits_exactly_the_declared_event() {
    let mut log = world();
    let target = SecurityEpochTarget::Principal(principal());
    let input = IncrementSecurityEpoch::new(context(), target.clone());
    let expected = log.current(&target).version();

    let emitted = input
        .execute(&mut log, expected)
        .expect("the stream is at the version the writer read");

    accepted(
        INCREMENT,
        &encoded(&input),
        &IdentityEvent::SecurityEpochIncremented(emitted),
    );
    assert_eq!(
        log.current(&target).generation(),
        Generation::new(4).expect("a non-negative generation"),
        "the one selected target advanced by exactly one"
    );
    assert_eq!(
        log.current(&SecurityEpochTarget::Organization(organization()))
            .generation(),
        Generation::new(7).expect("a non-negative generation"),
        "every other dimension is untouched"
    );
}

#[test]
fn a_refused_increment_emits_nothing_and_leaves_the_log_unchanged() {
    // The stream moved since the token was read: the concurrent writer is refused rather
    // than merged (`decision-blocker:epoch-atomicity`).
    let mut log = world();
    let target = SecurityEpochTarget::Principal(principal());
    let stale = log.current(&target).version();
    IncrementSecurityEpoch::new(context(), target.clone())
        .execute(&mut log, stale)
        .expect("the first writer commits");
    let held = log.clone();

    let denial = IncrementSecurityEpoch::new(context(), target.clone())
        .execute(&mut log, stale)
        .expect_err("the second writer read before the first committed");

    assert_eq!(denial.reason(), DenialReason::Unavailable);
    refused(INCREMENT, &denial);
    assert_eq!(log, held, "a refusal appends nothing");

    // The declared maximum: the increment denies from then on rather than wrapping or
    // reusing a generation.
    let mut at_maximum = IdentityLog::new();
    at_maximum.record(IdentityEvent::SecurityEpochRecorded(
        SecurityEpochRecorded {
            target: target.clone(),
            generation: Generation::MAX,
        },
    ));
    let held = at_maximum.clone();
    let expected = at_maximum.current(&target).version();

    let denial = IncrementSecurityEpoch::new(context(), target)
        .execute(&mut at_maximum, expected)
        .expect_err("`Generation::MAX` does not advance");

    assert_eq!(denial.reason(), DenialReason::Denied);
    refused(INCREMENT, &denial);
    assert_eq!(at_maximum, held, "a refusal appends nothing");
}

#[test]
fn revoke_session_emits_exactly_the_declared_event() {
    let mut log = world();
    let input = json!({"id": encoded(&session_id()), "context": encoded(&context())});

    let emitted = revoke_session(&mut log, &context(), session_id())
        .expect("an active session of this tenant");

    accepted(REVOKE, &input, &IdentityEvent::SessionRevoked(emitted));
    assert!(
        !log.resolve(&session_id())
            .expect("nothing is deleted")
            .is_active(),
        "the declared `revoke` move is folded"
    );
}

#[test]
fn a_refused_revocation_emits_nothing_and_leaves_the_log_unchanged() {
    let mut log = world();
    let held = log.clone();

    // The declared `denied` outcome: no such session.
    let unknown = revoke_session(&mut log, &context(), SessionId::new(uuid(99)))
        .expect_err("the fold records no such session");
    assert_eq!(unknown.reason(), DenialReason::InvalidCredential);
    assert_eq!(unknown.outcome(), RefusedOutcome::Denied);
    refused(REVOKE, &unknown);

    // The declared `denied` outcome: the session is outside the verified organization.
    let elsewhere = VerifiedContext {
        organization: OrganizationId::new(uuid(3)),
        ..context()
    };
    let outside = revoke_session(&mut log, &elsewhere, session_id())
        .expect_err("the session belongs to another organization");
    assert_eq!(outside.reason(), DenialReason::TenantMismatch);
    assert_eq!(outside.outcome(), RefusedOutcome::Denied);
    refused(REVOKE, &outside);

    assert_eq!(log, held, "a refusal appends nothing");

    // The declared `wrong-state` outcome: `revoke` starts from `Active` alone.
    revoke_session(&mut log, &context(), session_id()).expect("the first revocation is accepted");
    let held = log.clone();
    let again = revoke_session(&mut log, &context(), session_id())
        .expect_err("`Revoked` is the declared terminal state");

    assert_eq!(again.outcome(), RefusedOutcome::WrongState);
    assert_eq!(again.outcome().ir_name(), "wrong-state");
    refused(REVOKE, &again);
    assert_eq!(log, held, "a refusal appends nothing");
}

#[test]
fn the_write_port_refuses_a_stream_version_it_was_not_read_at() {
    let mut log = IdentityLog::new();
    let target = SecurityEpochTarget::Organization(organization());

    let denial = log
        .increment(&context(), &target, StreamVersion::new(7))
        .expect_err("the stream is at the initial version");

    assert_eq!(denial.reason(), DenialReason::Unavailable);
    refused(INCREMENT, &denial);
    assert!(log.events().is_empty(), "a refusal appends nothing");
}

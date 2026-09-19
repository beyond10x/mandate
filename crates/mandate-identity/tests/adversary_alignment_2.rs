//! Adversary pass 2: the append guard decides the declared lexical form of the expiry on
//! the federated login payload and not on `mandate.identity.SessionOpened`, the sibling
//! opening event this crate declares itself.
//!
//! `crates/mandate-identity/src/port.rs:297-303` states the rule the login path follows:
//! "the form is decided here, once, for **every** declared field and not only the
//! identifiers: the expiry is an RFC 3339 `date-time` and is read the same way. A payload
//! that fails any of them is refused by `IdentityLog::try_record` rather than folded into
//! a session the entity's own schema would refuse."
//!
//! `SessionOpened` reaches the same log through the same `try_record`, carries the same
//! declared `expires_at` (`generated/schema/events/mandate.identity.SessionOpened.schema
//! .json`: `"format": "date-time"`), and is written by a host — "no command in this
//! contract declares such an open and no outcome emits it; it is reserved for the
//! control-plane component that publishes it" (`src/session.rs:47-54`). The oracle here is
//! the generated schema, read by `mandate_testkit::contract`, and not this file's opinion.

use mandate_identity::{
    EpochSnapshotRecorded, IdentityEvent, IdentityLog, IdentityRead, SessionOpened,
};
use mandate_testkit::contract::check_event_conforms;
use mandate_types::{EpochSnapshotRef, OrganizationId, PrincipalId, SessionId, Timestamp, Uuid};

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

/// A log whose snapshot handle is already recorded, so the ordering guard on an opening
/// is satisfied and the expiry is the only thing left to decide.
fn log_holding_the_snapshot() -> IdentityLog {
    let mut log = IdentityLog::new();
    // Coordinator amendment after correction round 2 (ruling A2-5): a snapshot recording
    // is refused unless every dimension it names already states a generation, so the two
    // dimensions state theirs (zero) first.
    for target in [
        mandate_types::SecurityEpochTarget::Principal(principal()),
        mandate_types::SecurityEpochTarget::Organization(organization()),
    ] {
        log.try_record(IdentityEvent::SecurityEpochRecorded(
            mandate_identity::SecurityEpochRecorded {
                target,
                generation: mandate_identity::Generation::ZERO,
            },
        ))
        .expect("a dimension states its generation before a snapshot names it");
    }
    log.try_record(IdentityEvent::EpochSnapshotRecorded(
        EpochSnapshotRecorded {
            id: handle(),
            principal_id: principal(),
            organization_id: organization(),
            connection_id: None,
        },
    ))
    .expect("the snapshot the opening names is recorded first");
    log
}

/// An opening carrying a value the declared `date-time` does not admit.
fn opened_with(expires_at: &str) -> SessionOpened {
    SessionOpened {
        id: session_id(),
        principal_id: principal(),
        organization_id: organization(),
        connection_id: None,
        epochs: handle(),
        expires_at: Timestamp::new(expires_at),
    }
}

/// The log appends a `SessionOpened` payload the closed schema refuses.
#[test]
fn the_log_appends_a_session_opened_whose_expiry_is_not_the_declared_date_time() {
    let mut log = log_holding_the_snapshot();
    let opened = opened_with("2026-09-19");
    let payload = serde_json::to_value(&opened).expect("the declared payload serializes");
    let refused = check_event_conforms("mandate.identity.SessionOpened", &payload)
        .expect_err("the closed schema declares `expires_at` as a `date-time`");

    assert!(
        log.try_record(IdentityEvent::SessionOpened(opened))
            .is_err(),
        "the append guard admitted a payload the contract refuses: {refused}"
    );
}

/// The fold hands out a `mandate.identity.Session` built from that payload.
#[test]
fn the_fold_materializes_a_session_from_an_opening_the_contract_refuses() {
    let mut log = log_holding_the_snapshot();
    let opened = opened_with("never");
    let payload = serde_json::to_value(&opened).expect("the declared payload serializes");
    let refused = check_event_conforms("mandate.identity.SessionOpened", &payload)
        .expect_err("the closed schema declares `expires_at` as a `date-time`");
    log.record(IdentityEvent::SessionOpened(opened));

    assert_eq!(
        log.resolve(&session_id())
            .map(|session| session.expires_at().as_str().to_owned()),
        None,
        "the fold materialized a session whose declared `expires_at` names no instant, \
         from an event the contract refuses: {refused}"
    );
}

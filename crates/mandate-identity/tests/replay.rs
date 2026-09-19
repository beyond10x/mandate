//! Each durable record of `mandate.identity` is rebuilt from its events alone.
//!
//! `docs/adr/0009-event-sourced-persistence.md`: "A command produces domain events; the
//! events are the record; every read is a fold over them ... State tables are projections:
//! derived, droppable, rebuildable, never authoritative."
//!
//! Every case drives the real API: the login's own payload opens the session, the real
//! `refresh_session` and `revoke_session` decide over the fold, and the rebuild is a
//! second log seeded with the first one's events and nothing else. Nothing reconstructs
//! state by re-running a command.
//!
//! Both sides share one fold, so `rebuilt == live` alone is close to a tautology: a field
//! the fold drops is dropped identically on both sides. Each case therefore *also*
//! asserts the rebuilt record field for field against the values the events carried. The
//! equality says the rebuild is complete; the field comparison says the log is what it was
//! rebuilt from. This is the shape `crates/mandate-model/tests/replay.rs` established.

use mandate_contract::events::MandateFederationFederationAuthenticated;
use mandate_contract::types::{
    MandateCoreAudience, MandateCoreCorrelationId, MandateCoreEpochSnapshotRef,
    MandateCoreFederationConnectionId, MandateCoreOrganizationId, MandateCorePrincipalId,
    MandateCoreSessionId,
};
use mandate_identity::{
    EpochSnapshotRecorded, Generation, IdentityEvent, IdentityLog, IdentityRead,
    IncrementSecurityEpoch, SecurityEpochRecorded, SessionState, refresh_session, revoke_session,
};
use mandate_types::{
    Audience, CorrelationId, CredentialId, DenialReason, EpochSnapshotRef, FederationConnectionId,
    OrganizationId, PrincipalId, SecurityEpochTarget, SessionId, Timestamp, Uuid, VerifiedContext,
};

const EXPIRES_AT: &str = "2026-12-31T00:00:00Z";
const AS_OF: &str = "2026-09-19T00:00:00Z";

fn uuid(tag: u8) -> Uuid {
    Uuid::from_bytes([tag; 16])
}

/// The declared uuid form, as the generated shapes carry it: a string, because
/// `mandate-contract` states structure and not lexical form.
fn declared(tag: u8) -> String {
    uuid(tag).to_string()
}

fn principal() -> PrincipalId {
    PrincipalId::new(uuid(1))
}

fn organization() -> OrganizationId {
    OrganizationId::new(uuid(2))
}

fn connection() -> FederationConnectionId {
    FederationConnectionId::new(uuid(4))
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

/// The payload `mandate.federation.AuthenticateFederation`'s accepted outcome emits, which
/// **creates** `mandate.identity.Session` (`federation.yaml`).
///
/// It is the generated shape and not a copy: the direction is
/// `mandate-federation → mandate-identity` and never the reverse, so this crate folds the
/// contract's own payload.
fn login() -> MandateFederationFederationAuthenticated {
    MandateFederationFederationAuthenticated {
        session_id: MandateCoreSessionId(declared(20)),
        principal_id: MandateCorePrincipalId(declared(1)),
        audience: MandateCoreAudience("mandate".to_owned()),
        correlation: MandateCoreCorrelationId("identity-alignment".to_owned()),
        connection_id: MandateCoreFederationConnectionId(declared(4)),
        organization_id: MandateCoreOrganizationId(declared(2)),
        epochs: MandateCoreEpochSnapshotRef(declared(10)),
        expires_at: EXPIRES_AT.to_owned(),
    }
}

/// The same log, rebuilt from its events and nothing else.
fn rebuilt(live: &IdentityLog) -> IdentityLog {
    let mut replayed = IdentityLog::new().with_as_of(Timestamp::new(AS_OF));
    for event in live.events() {
        replayed.record(event.clone());
    }
    replayed
}

/// `mandate.identity.Session`: opened by a federated login, refreshed, then revoked.
#[test]
fn a_session_replays_from_the_login_that_opened_it() {
    let mut live = IdentityLog::new().with_as_of(Timestamp::new(AS_OF));
    live.record(IdentityEvent::SecurityEpochRecorded(
        SecurityEpochRecorded {
            target: SecurityEpochTarget::Principal(principal()),
            generation: Generation::new(3).expect("a non-negative generation"),
        },
    ));
    live.record(IdentityEvent::SecurityEpochRecorded(
        SecurityEpochRecorded {
            target: SecurityEpochTarget::Organization(organization()),
            generation: Generation::new(7).expect("a non-negative generation"),
        },
    ));
    live.record(IdentityEvent::SecurityEpochRecorded(
        SecurityEpochRecorded {
            target: SecurityEpochTarget::Federation(connection()),
            generation: Generation::new(1).expect("a non-negative generation"),
        },
    ));
    live.record(IdentityEvent::EpochSnapshotRecorded(
        EpochSnapshotRecorded {
            id: handle(),
            principal_id: principal(),
            organization_id: organization(),
            connection_id: Some(connection()),
        },
    ));
    // Step 9 of the resolution order: the login is the session's creation record.
    live.record(IdentityEvent::FederationAuthenticated(login()));

    let refreshed = refresh_session(&live, &session_id()).expect("every generation matches");
    assert_eq!(refreshed.session_id(), &session_id());

    revoke_session(&mut live, &context(), session_id()).expect("an active session of this tenant");

    let replayed = rebuilt(&live);
    let session = replayed
        .resolve(&session_id())
        .expect("the login opened the session");

    // Every declared field of `mandate.identity.Session`, read off the rebuilt record.
    assert_eq!(session.id(), &session_id());
    assert_eq!(session.principal(), &principal());
    assert_eq!(session.organization(), &organization());
    assert_eq!(session.connection(), Some(&connection()));
    assert_eq!(session.epochs(), &handle());
    assert_eq!(session.expires_at(), &Timestamp::new(EXPIRES_AT));
    assert_eq!(session.state(), SessionState::Revoked);

    assert_eq!(
        Some(session),
        live.resolve(&session_id()),
        "the rebuilt record is the live one"
    );
    assert_eq!(
        refresh_session(&replayed, &session_id())
            .expect_err("a revoked session does not refresh")
            .reason(),
        DenialReason::InvalidCredential,
        "the revocation replayed too"
    );
}

/// A session identity is opened once, whichever of the two declared opening events
/// arrives first.
///
/// `identity.yaml` records that nothing in the contract "declares what a fold does when
/// both arrive for one session; that is `story:federation-identity-alignment`'s to
/// settle". This is the settlement: the second open is refused, in both orders, because
/// `Revoked` is declared terminal and a reopened identity would leave it.
#[test]
fn a_second_open_of_a_session_the_log_already_records_is_refused() {
    let opened = mandate_identity::SessionOpened {
        id: session_id(),
        principal_id: principal(),
        organization_id: organization(),
        connection_id: None,
        epochs: handle(),
        expires_at: Timestamp::new(EXPIRES_AT),
    };

    // Both logs state the generations the snapshot's dimensions hold and then record the
    // snapshot the two openings name: an opening whose `epochs` handle the log does not
    // record, or a recording whose dimensions it has said nothing about, is refused for
    // *that* reason, which is not the one this case is about.
    let seeding: Vec<IdentityEvent> = [
        (SecurityEpochTarget::Principal(principal()), 3),
        (SecurityEpochTarget::Organization(organization()), 7),
        (SecurityEpochTarget::Federation(connection()), 1),
    ]
    .into_iter()
    .map(|(target, value)| {
        IdentityEvent::SecurityEpochRecorded(SecurityEpochRecorded {
            target,
            generation: Generation::new(value).expect("a non-negative generation"),
        })
    })
    .chain(std::iter::once(IdentityEvent::EpochSnapshotRecorded(
        EpochSnapshotRecorded {
            id: handle(),
            principal_id: principal(),
            organization_id: organization(),
            connection_id: Some(connection()),
        },
    )))
    .collect();

    let mut federated_first = IdentityLog::new();
    for event in &seeding {
        federated_first.record(event.clone());
    }
    federated_first.record(IdentityEvent::FederationAuthenticated(login()));
    let held = federated_first.clone();
    federated_first
        .try_record(IdentityEvent::SessionOpened(opened.clone()))
        .expect_err("the login already opened this session identity");
    assert_eq!(federated_first, held, "a refused event is not appended");
    assert_eq!(
        federated_first
            .resolve(&session_id())
            .expect("the login's session")
            .connection(),
        Some(&connection()),
        "the record is the login's, not the second open's"
    );

    let mut opened_first = IdentityLog::new();
    for event in &seeding {
        opened_first.record(event.clone());
    }
    opened_first.record(IdentityEvent::SessionOpened(opened));
    let held = opened_first.clone();
    opened_first
        .try_record(IdentityEvent::FederationAuthenticated(login()))
        .expect_err("a `SessionOpened` already opened this session identity");
    assert_eq!(opened_first, held, "a refused event is not appended");
    assert_eq!(
        opened_first
            .resolve(&session_id())
            .expect("the first open's session")
            .connection(),
        None,
        "the record is the first open's"
    );
}

/// `mandate.identity.SecurityEpochSnapshot`: rebuilt from its recording and the
/// generations the log held at that point.
#[test]
fn an_epoch_snapshot_replays_from_its_events() {
    let mut live = IdentityLog::new();
    for (target, value) in [
        (SecurityEpochTarget::Principal(principal()), 3),
        (SecurityEpochTarget::Organization(organization()), 7),
        (SecurityEpochTarget::Federation(connection()), 1),
    ] {
        live.record(IdentityEvent::SecurityEpochRecorded(
            SecurityEpochRecorded {
                target,
                generation: Generation::new(value).expect("a non-negative generation"),
            },
        ));
    }
    live.record(IdentityEvent::EpochSnapshotRecorded(
        EpochSnapshotRecorded {
            id: handle(),
            principal_id: principal(),
            organization_id: organization(),
            connection_id: Some(connection()),
        },
    ));

    let replayed = rebuilt(&live);
    let snapshot = replayed.snapshot(&handle()).expect("the recording");

    // The declared fields, and the per-dimension generations the fold binds from the log.
    assert_eq!(snapshot.id(), &handle());
    assert_eq!(snapshot.principal(), &principal());
    assert_eq!(snapshot.organization(), &organization());
    assert_eq!(snapshot.connection(), Some(&connection()));
    assert_eq!(
        snapshot.recorded(&SecurityEpochTarget::Principal(principal())),
        Generation::new(3)
    );
    assert_eq!(
        snapshot.recorded(&SecurityEpochTarget::Organization(organization())),
        Generation::new(7)
    );
    assert_eq!(
        snapshot.recorded(&SecurityEpochTarget::Federation(connection())),
        Generation::new(1)
    );
    assert_eq!(
        Some(snapshot),
        live.snapshot(&handle()),
        "the rebuilt record is the live one"
    );
}

/// The three generation records: recorded, then incremented by exactly one, with the
/// maximum denied.
///
/// `mandate.identity.PrincipalSecurityEpoch`, `OrganizationSecurityEpoch` and
/// `FederationSecurityEpoch` each declare one `generation`, and the fold is the record:
/// `SecurityEpochRecorded` seeds it and `SecurityEpochIncremented` advances it.
#[test]
fn each_security_epoch_replays_from_its_events() {
    for (target, seeded) in [
        (SecurityEpochTarget::Principal(principal()), 3),
        (SecurityEpochTarget::Organization(organization()), 7),
        (SecurityEpochTarget::Federation(connection()), 1),
    ] {
        let mut live = IdentityLog::new();
        live.record(IdentityEvent::SecurityEpochRecorded(
            SecurityEpochRecorded {
                target: target.clone(),
                generation: Generation::new(seeded).expect("a non-negative generation"),
            },
        ));
        let expected = live.current(&target).version();
        IncrementSecurityEpoch::new(context(), target.clone())
            .execute(&mut live, expected)
            .expect("the stream is at the version the writer read");

        let replayed = rebuilt(&live);
        assert_eq!(
            replayed.current(&target).generation(),
            Generation::new(seeded + 1).expect("a non-negative generation"),
            "the rebuilt generation is the seeded one advanced by exactly one"
        );
        assert_eq!(
            replayed.current(&target),
            live.current(&target),
            "the rebuilt record is the live one, version included"
        );
        for other in [
            SecurityEpochTarget::Principal(PrincipalId::new(uuid(9))),
            SecurityEpochTarget::Organization(OrganizationId::new(uuid(9))),
            SecurityEpochTarget::Federation(FederationConnectionId::new(uuid(9))),
        ] {
            assert_eq!(
                replayed.current(&other).generation(),
                Generation::ZERO,
                "an increment on one target leaves every other dimension untouched"
            );
        }
    }

    // The maximum denies rather than wrapping, and the denial appends nothing — so the
    // rebuild of the same log is the same record.
    let target = SecurityEpochTarget::Principal(principal());
    let mut live = IdentityLog::new();
    live.record(IdentityEvent::SecurityEpochRecorded(
        SecurityEpochRecorded {
            target: target.clone(),
            generation: Generation::MAX,
        },
    ));
    let expected = live.current(&target).version();
    let denial = IncrementSecurityEpoch::new(context(), target.clone())
        .execute(&mut live, expected)
        .expect_err("`Generation::MAX` does not advance");

    assert_eq!(denial.reason(), DenialReason::Denied);
    assert_eq!(live.events().len(), 1, "a refusal appends nothing");
    assert_eq!(
        rebuilt(&live).current(&target).generation(),
        Generation::MAX
    );
}

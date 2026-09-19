//! Adversary pass **2** over the realization round of `story:declared-writers`, unit A3
//! (`principal-fold`), taken after correction round 1.
//!
//! Pass 1 attacked the two literals `federation.yaml` pins in this payload, and the
//! correction made `principal_of` enforce both. This pass attacks the *other* half of the
//! same seam's own promise — the one the correction did not touch.
//!
//! `crates/mandate-identity/src/port.rs` states the rule twice, in two places, and neither
//! is hedged:
//!
//! * `session_of`: "the form is decided here, once, for **every** declared field and not
//!   only the identifiers: the expiry is an RFC 3339 `date-time` and is read the same way.
//!   A payload that fails any of them is refused by `IdentityLog::try_record` rather than
//!   folded into a session the entity's own schema would refuse." It parses all six.
//! * The `SessionOpened` arm of `IdentityLog::refusal`: "**A payload the closed schema
//!   refuses is never appended.**" That is a statement about the log, not about one arm.
//!
//! `principal_of` opens by calling itself "the same seam as `session_of`" and says it
//! decides "the lexical form of **every** declared identifier". It parses **one** field of
//! the ten this payload declares. `mandate.federation.ExternalPrincipalProvisioned` pins a
//! uuid pattern on `organization_id`, `connection_id` and `external_principal_id` and
//! `format: date-time` on `linked_at`
//! (`generated/schema/events/mandate.federation.ExternalPrincipalProvisioned.schema.json`),
//! and a payload violating any of the four is appended to the log and materializes a
//! `mandate.identity.Principal`.
//!
//! The oracle is the generated schema, read through `mandate_testkit::contract`, not a
//! sentence here: every case below first asserts that the payload it builds is one the
//! contract's own closed schema refuses, and only then asks the log about it. The control
//! beside them is the login arm, which refuses exactly those payloads over the same log.

use mandate_contract::events::{
    MandateFederationExternalPrincipalProvisioned, MandateFederationFederationAuthenticated,
};
use mandate_contract::types::{
    MandateCoreAudience, MandateCoreCorrelationId, MandateCoreEpochSnapshotRef,
    MandateCoreExternalLinkMethod, MandateCoreExternalPrincipalId, MandateCoreExternalSubject,
    MandateCoreFederationConnectionId, MandateCoreOrganizationId, MandateCorePrincipalId,
    MandateCorePrincipalKind, MandateCoreSessionId,
};
use mandate_identity::{
    EpochSnapshotRecorded, Generation, IdentityEvent, IdentityLog, IdentityRead,
    SecurityEpochRecorded,
};
use mandate_testkit::contract::check_event_conforms;
use mandate_types::{
    EpochSnapshotRef, FederationConnectionId, OrganizationId, PrincipalId, SecurityEpochTarget,
    SessionId, Timestamp, Uuid,
};
use serde::Serialize;
use serde_json::Value;

const PROVISIONED: &str = "mandate.federation.ExternalPrincipalProvisioned";
const AUTHENTICATED: &str = "mandate.federation.FederationAuthenticated";
const DISPLAY_NAME: &str = "subject-one";
const EXPIRES_AT: &str = "2026-12-31T00:00:00Z";
const AS_OF: &str = "2026-09-19T00:00:00Z";

/// A string in none of the declared lexical forms: not a uuid and not an instant.
const MALFORMED: &str = "not-a-declared-form";

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

fn encoded<T: Serialize>(value: &T) -> Value {
    serde_json::to_value(value).expect("a generated payload encodes as JSON")
}

/// The seeding event of `mandate.identity.Principal`, in the generated shape the fold
/// reads it as, with every declared field in the form the contract admits.
fn provisioned() -> MandateFederationExternalPrincipalProvisioned {
    MandateFederationExternalPrincipalProvisioned {
        organization_id: MandateCoreOrganizationId(declared(2)),
        correlation: MandateCoreCorrelationId("adversary-writers-2".to_owned()),
        connection_id: MandateCoreFederationConnectionId(declared(4)),
        principal_id: MandateCorePrincipalId(declared(1)),
        kind: MandateCorePrincipalKind::User,
        display_name: DISPLAY_NAME.to_owned(),
        external_principal_id: MandateCoreExternalPrincipalId(declared(0x71)),
        subject: MandateCoreExternalSubject("subject-one".to_owned()),
        link_method: MandateCoreExternalLinkMethod::ConfiguredFederation,
        linked_at: AS_OF.to_owned(),
    }
}

/// The opening event the control reads, with every declared field in the admitted form.
fn login() -> MandateFederationFederationAuthenticated {
    MandateFederationFederationAuthenticated {
        session_id: MandateCoreSessionId(declared(20)),
        principal_id: MandateCorePrincipalId(declared(1)),
        audience: MandateCoreAudience("mandate".to_owned()),
        correlation: MandateCoreCorrelationId("adversary-writers-2".to_owned()),
        connection_id: MandateCoreFederationConnectionId(declared(4)),
        organization_id: MandateCoreOrganizationId(declared(2)),
        epochs: MandateCoreEpochSnapshotRef(declared(10)),
        expires_at: EXPIRES_AT.to_owned(),
    }
}

/// The three generations and the snapshot every opening's `epochs` handle needs before
/// the log will admit an opening at all, so the control refuses for the reason it claims
/// and not for a missing snapshot.
fn seeded() -> IdentityLog {
    let mut log = IdentityLog::new().with_as_of(Timestamp::new(AS_OF));
    for (target, value) in [
        (SecurityEpochTarget::Principal(principal()), 3),
        (SecurityEpochTarget::Organization(organization()), 7),
        (SecurityEpochTarget::Federation(connection()), 1),
    ] {
        log.record(IdentityEvent::SecurityEpochRecorded(
            SecurityEpochRecorded {
                target,
                generation: Generation::new(value).expect("a non-negative generation"),
            },
        ));
    }
    log.record(IdentityEvent::EpochSnapshotRecorded(
        EpochSnapshotRecorded {
            id: handle(),
            principal_id: principal(),
            organization_id: organization(),
            connection_id: Some(connection()),
        },
    ));
    log
}

/// A declared identifier of the seeding event, out of its declared lexical form, is not
/// appended — the rule `IdentityLog` states for the opening arm beside it.
///
/// `principal_of` says it decides "the lexical form of every declared identifier". Three
/// identifiers of this payload besides `principal_id` carry the uuid pattern in the
/// generated schema, and the fold parses none of them: it copies `principal_id`, `kind`
/// and `display_name` into the record and drops the rest unread, so a payload the closed
/// schema refuses reaches the log and materializes a `mandate.identity.Principal` out of
/// an event no conforming producer could have written.
#[test]
fn a_provisioning_carrying_an_identifier_the_closed_schema_refuses_is_not_appended() {
    let malformed = [
        (
            "organization_id",
            MandateFederationExternalPrincipalProvisioned {
                organization_id: MandateCoreOrganizationId(MALFORMED.to_owned()),
                ..provisioned()
            },
        ),
        (
            "connection_id",
            MandateFederationExternalPrincipalProvisioned {
                connection_id: MandateCoreFederationConnectionId(MALFORMED.to_owned()),
                ..provisioned()
            },
        ),
        (
            "external_principal_id",
            MandateFederationExternalPrincipalProvisioned {
                external_principal_id: MandateCoreExternalPrincipalId(MALFORMED.to_owned()),
                ..provisioned()
            },
        ),
    ];

    for (field, payload) in malformed {
        // The oracle, and it is the contract's own: the generated schema pins a uuid
        // pattern on this field, so this payload is not one the contract declares.
        assert!(
            check_event_conforms(PROVISIONED, &encoded(&payload)).is_err(),
            "the closed schema admits a malformed `{field}`, so there is nothing here to \
             measure"
        );

        let mut log = IdentityLog::new();
        let appended = log.try_record(IdentityEvent::ExternalPrincipalProvisioned(payload));

        assert!(
            appended.is_err(),
            "`{field}` is out of its declared lexical form and the closed schema refuses \
             the payload, yet IdentityLog appended it: `principal_of` \
             (crates/mandate-identity/src/port.rs) parses `principal_id` alone, where \
             `session_of` beside it parses every declared field of the payload it reads, \
             and the SessionOpened arm states the rule as `a payload the closed schema \
             refuses is never appended`"
        );
        assert_eq!(log, IdentityLog::new(), "a refused event is not appended");
        assert_eq!(
            log.principal(&principal()),
            None,
            "a payload the contract refuses materializes no principal"
        );
    }
}

/// The same gap at the one field the sibling arm singles out.
///
/// `mandate.identity.SessionOpened`'s arm names `expires_at` as "the one field a host can
/// get wrong", because it is a `Timestamp` and "a `Timestamp` carries a lexical form
/// verbatim"; `session_of` decides it with `names_an_instant`. The seeding event carries
/// `linked_at`, declared `format: date-time` by the same generator, and `principal_of`
/// never looks at it.
#[test]
fn a_provisioning_whose_linked_at_names_no_instant_is_not_appended() {
    let payload = MandateFederationExternalPrincipalProvisioned {
        linked_at: MALFORMED.to_owned(),
        ..provisioned()
    };

    assert!(
        check_event_conforms(PROVISIONED, &encoded(&payload)).is_err(),
        "the closed schema admits a `linked_at` that names no instant, so there is \
         nothing here to measure"
    );

    let mut log = IdentityLog::new();
    let appended = log.try_record(IdentityEvent::ExternalPrincipalProvisioned(payload));

    assert!(
        appended.is_err(),
        "`linked_at` names no instant and the closed schema refuses the payload, yet \
         IdentityLog appended it: the declared `date-time` is decided for the opening \
         event's `expires_at` and for nothing on the seeding event"
    );
    assert_eq!(log, IdentityLog::new(), "a refused event is not appended");
}

/// Control, and it holds: the opening arm refuses every declared field the closed schema
/// refuses, over the same log and through the same entry point.
///
/// This is what makes the two cases above a measurement of a divergence rather than a
/// requirement invented here. The log is seeded with the snapshot and the three
/// generations first, and the well-formed opening is accepted, so each refusal below is
/// the lexical form and not a missing handle.
#[test]
fn probe_the_login_arm_refuses_every_declared_field_the_closed_schema_refuses() {
    let mut accepting = seeded();
    accepting
        .try_record(IdentityEvent::FederationAuthenticated(login()))
        .expect("a well-formed opening whose snapshot the log already records");

    let malformed = [
        (
            "session_id",
            MandateFederationFederationAuthenticated {
                session_id: MandateCoreSessionId(MALFORMED.to_owned()),
                ..login()
            },
        ),
        (
            "principal_id",
            MandateFederationFederationAuthenticated {
                principal_id: MandateCorePrincipalId(MALFORMED.to_owned()),
                ..login()
            },
        ),
        (
            "organization_id",
            MandateFederationFederationAuthenticated {
                organization_id: MandateCoreOrganizationId(MALFORMED.to_owned()),
                ..login()
            },
        ),
        (
            "connection_id",
            MandateFederationFederationAuthenticated {
                connection_id: MandateCoreFederationConnectionId(MALFORMED.to_owned()),
                ..login()
            },
        ),
        (
            "epochs",
            MandateFederationFederationAuthenticated {
                epochs: MandateCoreEpochSnapshotRef(MALFORMED.to_owned()),
                ..login()
            },
        ),
        (
            "expires_at",
            MandateFederationFederationAuthenticated {
                expires_at: MALFORMED.to_owned(),
                ..login()
            },
        ),
    ];

    for (field, payload) in malformed {
        assert!(
            check_event_conforms(AUTHENTICATED, &encoded(&payload)).is_err(),
            "the closed schema admits a malformed `{field}` on the opening event"
        );

        let mut log = seeded();
        let held = log.clone();
        let appended = log.try_record(IdentityEvent::FederationAuthenticated(payload));

        assert!(
            appended.is_err(),
            "the opening arm admitted a malformed `{field}`"
        );
        assert_eq!(log, held, "a refused event is not appended");
        assert_eq!(
            log.resolve(&session_id()),
            None,
            "a payload the contract refuses materializes no session"
        );
    }
}

/// Probe, and it holds: ruling 5 in the other order.
///
/// The unit pins the explicit-link path — a session for a principal no provisioning
/// created — and the just-in-time order, provisioning before login. Neither case asks what
/// happens when the provisioning arrives *after* a session already named that principal,
/// which is what a redelivery or a backfill of the federation stream produces. The
/// provisioning is recordable and the record it creates is the one it carries: the opening
/// names a principal and creates nothing, so it does not make the later creation
/// unrecordable.
#[test]
fn probe_a_provisioning_after_a_session_that_names_the_principal_is_recorded_and_answered() {
    let mut log = seeded();
    log.try_record(IdentityEvent::FederationAuthenticated(login()))
        .expect("the explicit-link path opens a session for a principal with no record");
    assert_eq!(
        log.principal(&principal()),
        None,
        "an opening is not a creation record for the principal it names"
    );

    log.try_record(IdentityEvent::ExternalPrincipalProvisioned(provisioned()))
        .expect("a principal no recorded event created is still creatable");

    let record = log
        .principal(&principal())
        .expect("the provisioning seeded the principal");
    assert_eq!(record.id(), &principal());
    assert_eq!(record.display_name(), DISPLAY_NAME);
    assert_eq!(
        log.resolve(&session_id())
            .expect("the session is still there")
            .principal(),
        &principal(),
        "the session the opening created is unchanged by the creation that followed it"
    );
}

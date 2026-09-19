//! Adversary pass 1 over `story:federation-identity-alignment`, the `mandate-identity`
//! half. Every case drives the real fold and the real handlers and decides them against
//! `generated/schema/events/*` or `generated/ir/system.json`.

use std::collections::BTreeSet;

use mandate_contract::events::MandateFederationFederationAuthenticated;
use mandate_contract::types::{
    MandateCoreAudience, MandateCoreCorrelationId, MandateCoreEpochSnapshotRef,
    MandateCoreFederationConnectionId, MandateCoreOrganizationId, MandateCorePrincipalId,
    MandateCoreSessionId,
};
use mandate_identity::{
    EpochSnapshotRecorded, Generation, IdentityEvent, IdentityLog, IdentityRead,
    IncrementSecurityEpoch, SecurityEpochRecorded, SessionRevoked, refresh_session,
};
use mandate_testkit::contract::check_event_conforms;
use mandate_types::{
    Audience, CorrelationId, CredentialId, DenialReason, EpochSnapshotRef, FederationConnectionId,
    OrganizationId, PrincipalId, SecurityEpochTarget, SessionId, Timestamp, Uuid, VerifiedContext,
};
use serde_json::Value;

const EXPIRES_AT: &str = "2026-12-31T00:00:00Z";
const AS_OF: &str = "2026-09-19T00:00:00Z";

fn uuid(tag: u8) -> Uuid {
    Uuid::from_bytes([tag; 16])
}

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
        correlation: CorrelationId::new("adversary-alignment-1"),
    }
}

/// The payload `mandate.federation.AuthenticateFederation`'s accepted outcome emits, in
/// the generated shape this crate folds.
fn login() -> MandateFederationFederationAuthenticated {
    MandateFederationFederationAuthenticated {
        session_id: MandateCoreSessionId(declared(20)),
        principal_id: MandateCorePrincipalId(declared(1)),
        audience: MandateCoreAudience("mandate".to_owned()),
        correlation: MandateCoreCorrelationId("adversary-alignment-1".to_owned()),
        connection_id: MandateCoreFederationConnectionId(declared(4)),
        organization_id: MandateCoreOrganizationId(declared(2)),
        epochs: MandateCoreEpochSnapshotRef(declared(10)),
        expires_at: EXPIRES_AT.to_owned(),
    }
}

/// The compiled contract.
fn system_ir() -> Value {
    const IR: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../generated/ir/system.json"
    );
    let text = std::fs::read_to_string(IR).expect("the generated IR is readable");
    serde_json::from_str(&text).expect("the generated IR is JSON")
}

/// The append guard decides every lexical form the contract declares on a login payload,
/// not only the identifiers.
#[test]
fn the_log_refuses_a_login_whose_expiry_is_not_the_declared_date_time() {
    let mut malformed = login();
    malformed.expires_at = "the end of the month".to_owned();
    let payload = serde_json::to_value(&malformed).expect("a generated shape encodes as JSON");

    let refused_by_the_contract =
        check_event_conforms("mandate.federation.FederationAuthenticated", &payload);
    assert!(
        refused_by_the_contract.is_err(),
        "the generated schema declares `expires_at` as an RFC 3339 date-time, so it must \
         refuse this payload before the rest of this case means anything"
    );

    let mut log = IdentityLog::new().with_as_of(Timestamp::new(AS_OF));
    let appended = log.try_record(IdentityEvent::FederationAuthenticated(malformed));
    let materialized = log.resolve(&session_id());

    assert!(
        appended.is_err(),
        "`IdentityLog::try_record` appended a `mandate.federation.FederationAuthenticated` \
         payload that generated/schema/events/mandate.federation.FederationAuthenticated\
         .schema.json refuses, and the fold materialized {materialized:?} from it"
    );
}

/// A security-epoch increment that postdates a login stales that login's session; the
/// session's snapshot recording precedes the login, as the log requires.
#[test]
fn an_increment_after_a_login_stales_that_login_s_session() {
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

    // Coordinator ruling after adversary pass 1 (A1-4): an opening event whose `epochs`
    // handle has no preceding `EpochSnapshotRecorded` is refused, so the recording comes
    // first; the property this case pins is that the increment stales the login anyway.
    log.record(IdentityEvent::EpochSnapshotRecorded(
        EpochSnapshotRecorded {
            id: handle(),
            principal_id: principal(),
            organization_id: organization(),
            connection_id: Some(connection()),
        },
    ));

    // Step 9 of the resolution order: the login opens the session, against a principal
    // whose authoritative generation is 3.
    log.record(IdentityEvent::FederationAuthenticated(login()));

    // The principal's credentials are revoked after that login. Every session issued
    // before this increment is issued against generation 3 and is now stale.
    let target = SecurityEpochTarget::Principal(principal());
    let expected = log.current(&target).version();
    IncrementSecurityEpoch::new(context(), target.clone())
        .execute(&mut log, expected)
        .expect("the stream is at the version the writer read");
    assert_eq!(
        log.current(&target).generation(),
        Generation::new(4).expect("a non-negative generation"),
        "the increment landed"
    );

    let refreshed = refresh_session(&log, &session_id());
    let denial = refreshed.as_ref().err().map(|denial| denial.reason());
    assert_eq!(
        denial,
        Some(DenialReason::StaleEpoch),
        "the session was opened before the increment and refreshed after it: \
         {refreshed:?}"
    );
}

/// A sibling ESS name on a `{context, id}` identity event is refused by the generated
/// schema of the element the name points at.
#[test]
fn a_sibling_ess_name_on_a_session_revocation_is_refused_by_the_generated_schema() {
    let revoked = IdentityEvent::SessionRevoked(SessionRevoked {
        context: context(),
        id: session_id(),
    });
    assert_eq!(
        revoked.ess_name(),
        "mandate.identity.SessionRevoked",
        "the name the event answers today"
    );
    let document = serde_json::to_value(&revoked).expect("a declared payload encodes as JSON");
    assert!(
        check_event_conforms(revoked.ess_name(), &document).is_ok(),
        "the payload conforms to the element it names itself as"
    );

    // Coordinator ruling after adversary pass 1 (A1-5): the three `{context, id}` identity
    // payloads are one declared shape, so the schema cannot decide the name; the oracle is
    // the emission lookup, which `tests/emitted_events.rs` now performs with
    // `event.ess_name()`. A sibling name is refused there and the right name admitted.
    for sibling in [
        "mandate.identity.PrincipalDisabled",
        "mandate.identity.RefreshCredentialRevoked",
    ] {
        let verdict = mandate_testkit::contract::check_single_emission(
            "mandate.identity.RevokeSession",
            "accepted",
            &[(sibling, &document)],
        );
        assert!(
            verdict.is_err(),
            "a revocation emitting under the sibling name {sibling} passed the emission \
             lookup: {verdict:?}"
        );
    }
    mandate_testkit::contract::check_single_emission(
        "mandate.identity.RevokeSession",
        "accepted",
        &[(revoked.ess_name(), &document)],
    )
    .expect("the declared name is the one emission the accepted outcome names");
}

/// The declared elements of this domain the crate does not realize are the ones its own
/// registry documentation names.
#[test]
fn the_unrealized_elements_are_the_ones_the_registry_documents_as_absent() {
    let ir = system_ir();
    let realized: BTreeSet<&str> = mandate_identity::ESS_REALIZATIONS
        .iter()
        .map(|(element, _)| *element)
        .collect();

    let mut absent: BTreeSet<String> = BTreeSet::new();
    for kind in ["commands", "events", "entities", "errors", "types"] {
        let Some(index) = ir[kind].as_object() else {
            continue;
        };
        for element in index.keys() {
            if element.starts_with("mandate.identity.") && !realized.contains(element.as_str()) {
                absent.insert(element.clone());
            }
        }
    }

    // Coordinator ruling after adversary pass 1 (A1-6): the crate names every element it
    // does not realize in `ESS_UNREALIZED`, element by element with a reason; the two
    // lists must be the same set, in both directions.
    let documented: BTreeSet<String> = mandate_identity::ESS_UNREALIZED
        .iter()
        .map(|(element, _reason)| (*element).to_owned())
        .collect();

    assert_eq!(
        absent,
        documented,
        "the registry names {} unrealized elements and the contract declares {} this crate \
         does not realize",
        documented.len(),
        absent.len()
    );
}

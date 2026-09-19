//! Adversary pass over the realization round of `story:declared-writers`, unit A3
//! (`principal-fold`).
//!
//! One line of attack: the pinned literals of the seeding event.
//!
//! `crates/mandate-identity/src/port.rs`'s `principal_of` says what it decides, under the
//! heading "**The literals the contract pins**", and closes it with: "It is enforced here
//! because the write path is not the only way an event reaches a fold, which is the same
//! reason `mandate_federation::record::Projection::apply` enforces it."
//!
//! `systems/mandate/domains/federation.yaml` pins **two** literals in
//! `mandate.federation.ExternalPrincipalProvisioned`'s payload, and
//! `crates/mandate-federation/src/record.rs` says so in as many words — "`federation.yaml`
//! pins two literals in this payload" — and refuses both: `FoldError::ProvisionedKind` for
//! a `kind` other than `User` and `FoldError::ProvisionedLinkMethod` for a `link_method`
//! other than `ConfiguredFederation`. This fold enforces the first and not the second, so
//! one payload is "not the declared seeding event" to one fold and the seeding event to
//! the other, over the same log.
//!
//! The probe beside it is the same guard's other half, kept so a reader can see the shape
//! the refusal takes when it does fire.

use mandate_contract::events::MandateFederationExternalPrincipalProvisioned;
use mandate_contract::types::{
    MandateCoreCorrelationId, MandateCoreExternalLinkMethod, MandateCoreExternalPrincipalId,
    MandateCoreExternalSubject, MandateCoreFederationConnectionId, MandateCoreOrganizationId,
    MandateCorePrincipalId, MandateCorePrincipalKind,
};
use mandate_identity::{IdentityEvent, IdentityLog, IdentityRead};
use mandate_types::{PrincipalId, Uuid};

const DISPLAY_NAME: &str = "subject-one";

fn uuid(tag: u8) -> Uuid {
    Uuid::from_bytes([tag; 16])
}

fn declared(tag: u8) -> String {
    uuid(tag).to_string()
}

fn principal() -> PrincipalId {
    PrincipalId::new(uuid(1))
}

/// The seeding event of `mandate.identity.Principal`, in the generated shape the fold
/// reads it as, carrying both literals `federation.yaml` pins.
fn provisioned() -> MandateFederationExternalPrincipalProvisioned {
    MandateFederationExternalPrincipalProvisioned {
        organization_id: MandateCoreOrganizationId(declared(2)),
        correlation: MandateCoreCorrelationId("adversary-writers-1".to_owned()),
        connection_id: MandateCoreFederationConnectionId(declared(4)),
        principal_id: MandateCorePrincipalId(declared(1)),
        kind: MandateCorePrincipalKind::User,
        display_name: DISPLAY_NAME.to_owned(),
        external_principal_id: MandateCoreExternalPrincipalId(declared(0x71)),
        subject: MandateCoreExternalSubject("subject-one".to_owned()),
        link_method: MandateCoreExternalLinkMethod::ConfiguredFederation,
        linked_at: "2026-09-19T00:00:00Z".to_owned(),
    }
}

/// The second pinned literal, which this fold does not decide.
///
/// `mandate.core.ExternalLinkMethod` declares five methods and `federation.yaml` pins one
/// of them in this payload. A payload carrying any of the other four is refused by
/// `mandate_federation::record::Projection::apply` as not the declared seeding event — it
/// answers `FoldError::ProvisionedLinkMethod` — and is accepted here, materializing a
/// `mandate.identity.Principal` from a payload the contract's own pin excludes.
///
/// Both folds read one log. A log that one of them calls unreadable is not a log the other
/// may read a record out of.
#[test]
fn a_provisioning_whose_pinned_link_method_is_not_the_declared_one_is_refused() {
    for undeclared in [
        MandateCoreExternalLinkMethod::Administrator,
        MandateCoreExternalLinkMethod::AuthenticatedConfirmation,
        MandateCoreExternalLinkMethod::VerifiedMigration,
        MandateCoreExternalLinkMethod::SecuritySupport,
    ] {
        let payload = MandateFederationExternalPrincipalProvisioned {
            link_method: undeclared.clone(),
            ..provisioned()
        };

        let mut log = IdentityLog::new();
        let refused = log.try_record(IdentityEvent::ExternalPrincipalProvisioned(payload));

        assert!(
            refused.is_err(),
            "{undeclared:?} is not the literal `federation.yaml` pins, so this payload is \
             not the declared seeding event"
        );
        assert_eq!(log, IdentityLog::new(), "a refused event is not appended");
        assert_eq!(
            log.principal(&principal()),
            None,
            "{undeclared:?} materializes no principal"
        );
    }
}

/// Probe, and it holds: the payload carrying both pinned literals is the seeding event,
/// and the record it materializes is the one it carries.
#[test]
fn probe_the_payload_carrying_both_pinned_literals_seeds_the_principal() {
    let mut log = IdentityLog::new();
    log.try_record(IdentityEvent::ExternalPrincipalProvisioned(provisioned()))
        .expect("both pinned literals are the declared ones");

    let record = log
        .principal(&principal())
        .expect("the provisioning seeded the principal");

    assert_eq!(record.id(), &principal());
    assert_eq!(record.display_name(), DISPLAY_NAME);
}

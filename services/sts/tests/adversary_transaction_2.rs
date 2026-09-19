//! Adversary pass 2 — `story:oauth-transaction`, after correction round 1.
//!
//! Pass 1's rulings F1–F4 landed a new port surface (`is_public`, `redirect_registered`), a
//! deployment code-lifetime ceiling, and a new contract document:
//! `services/sts/tests/declared_denials.rs`. This file drives that document, and the port
//! it introduced, against the code the same unit wrote.
//!
//! Neither case here asserts a preference. Each asserts a sentence the unit itself wrote:
//!
//! - [`the_denial_table_carries_no_row_for_a_clause_introspection_produces`] asserts
//!   `declared_denials.rs`'s own claim — "every `(command, clause)` pair this crate can
//!   produce is decided against `generated/ir/system.json`" and `ROWS` is "Every
//!   `(command, clause)` pair this crate's handlers construct". The pair
//!   `(IntrospectCredential, OrganizationMismatch)` is constructed at
//!   `services/sts/src/resolve.rs:498` and `ROWS` carries no row for it, so neither
//!   direction of that document's check ever sees it.
//! - [`a_client_reader_that_cannot_answer_enabled_is_reported_as_a_disabled_client`]
//!   asserts the fail-closed rule the same correction wrote into
//!   `services/sts/src/code.rs`: "a reader that holds no answer has decided nothing", which
//!   `is_public` and `redirect_registered` answer with `DenialReason::Unavailable`.
//!   `is_enabled` answers a reader that cannot answer with `DenialReason::Denied` and
//!   `DenialClause::ClientDisabled` — the positive refusal the port's own doc comment says
//!   is a *different* refusal from "not registered".

use std::collections::BTreeSet;

use mandate_sts::RequestContext;
use mandate_sts::code::{OAuthClientReads, admitted_client};
use mandate_sts::issue::Sha256Digest;
use mandate_sts::resolve::{IntrospectCredential, IntrospectionParts, introspect_credential};
use mandate_token::projection::{CredentialEvent, DenialClause, Projection};
use mandate_token::verifier::verifier_for;
use mandate_token::{CredentialDescriptor, CredentialProfile};
use mandate_types::{
    Audience, AuthorityScope, CorrelationId, CredentialId, CredentialKind, CredentialProof,
    DenialReason, Duration, OAuthClientId, OrganizationId, PrincipalId, RedirectUri,
    ResourceServerId, RevocationGuarantee, Timestamp, Uuid, VerifiedContext,
};

fn uuid(tag: u8) -> Uuid {
    Uuid::from_bytes([tag; 16])
}

fn organization(tag: u8) -> OrganizationId {
    OrganizationId::new(uuid(tag))
}

fn client() -> OAuthClientId {
    OAuthClientId::new(uuid(0x0c))
}

fn context(organization_id: OrganizationId) -> VerifiedContext {
    VerifiedContext {
        subject: PrincipalId::new(uuid(0x51)),
        actor: None,
        organization: organization_id,
        audience: Audience::new("mandate"),
        credential: CredentialId::new(uuid(0xcd)),
        delegation: None,
        execution: None,
        correlation: CorrelationId::new("adversary-transaction-2"),
    }
}

fn request() -> RequestContext {
    RequestContext {
        correlation: CorrelationId::new("adversary-transaction-2"),
        at: Timestamp::new("2026-09-19T00:00:00Z"),
        epochs: None,
    }
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

/// The material the caller presents as its own proof.
const CALLER_SECRET: &[u8] = b"adversary-2-caller-secret-material";

/// The material the caller presents as the credential to introspect.
const PRESENTED_SECRET: &[u8] = b"adversary-2-presented-secret-material";

fn proof(material: &[u8]) -> CredentialProof {
    CredentialProof::from_bytes(material.to_vec())
}

fn descriptor(organization_id: OrganizationId, audience: &str) -> CredentialDescriptor {
    CredentialDescriptor {
        kind: CredentialKind::Reference,
        subject: PrincipalId::new(uuid(0x51)),
        actor: None,
        organization: organization_id,
        audience: Audience::new(audience),
        scope: scope(),
        delegation: None,
        execution: None,
        expires_at: Timestamp::new("2026-09-19T01:00:00Z"),
    }
}

/// Two organizations that each registered the same audience, each holding one live
/// reference credential.
///
/// `(organization_id, audience)` is the registration key, so two organizations registering
/// `api-a` is an ordinary deployment and not a constructed one. The caller's credential is
/// organization 10's; the credential it presents is organization 11's, for the same
/// audience.
fn two_organizations_sharing_an_audience() -> (Projection, ResourceServerId) {
    let caller_target = ResourceServerId::new(uuid(0x40));
    let other_target = ResourceServerId::new(uuid(0x41));
    let fold = Projection::fold(&[
        CredentialEvent::ResourceServerRegistered {
            context: context(organization(10)),
            id: caller_target,
            audience: Audience::new("api-a"),
            credential_profile: reference_profile(),
            allowed_exchange_sources: Vec::new(),
        },
        CredentialEvent::ResourceServerRegistered {
            context: context(organization(11)),
            id: other_target,
            audience: Audience::new("api-a"),
            credential_profile: reference_profile(),
            allowed_exchange_sources: Vec::new(),
        },
        CredentialEvent::CredentialReferenceIssued {
            context: context(organization(10)),
            credential_id: CredentialId::new(uuid(0xc1)),
            reference_verifier: Some(verifier_for(&Sha256Digest, &proof(CALLER_SECRET))),
            epochs: None,
            issued_at: Timestamp::new("2026-09-19T00:00:00Z"),
            descriptor: descriptor(organization(10), "api-a"),
            target: caller_target,
            requested_scope: scope(),
        },
        CredentialEvent::CredentialReferenceIssued {
            context: context(organization(11)),
            credential_id: CredentialId::new(uuid(0xc2)),
            reference_verifier: Some(verifier_for(&Sha256Digest, &proof(PRESENTED_SECRET))),
            epochs: None,
            issued_at: Timestamp::new("2026-09-19T00:00:00Z"),
            descriptor: descriptor(organization(11), "api-a"),
            target: other_target,
            requested_scope: scope(),
        },
    ])
    .expect("two registrations and two issuances");
    (fold, caller_target)
}

/// Every `DenialClause` variant `services/sts/tests/declared_denials.rs` rows for one
/// command, read out of that file's own `ROWS` table.
///
/// The table is a document this unit wrote about itself, so it is read as one. Parsing is
/// line-oriented and confined to the `const ROWS` block: a row's command is a line that is
/// nothing but a quoted element name, and a row's clause is a line that begins
/// `DenialClause::`. `Source::EntityInvariant("mandate.credential.SigningKey", …)` is not a
/// bare quoted line and does not reset the command.
fn rowed_clauses(command: &str) -> BTreeSet<String> {
    const TABLE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/declared_denials.rs");
    let text = std::fs::read_to_string(TABLE).expect("the denial table is readable");
    let rows = text
        .split_once("const ROWS:")
        .expect("declared_denials.rs declares ROWS")
        .1;
    let rows = rows
        .split_once("\n];")
        .expect("the ROWS table is terminated")
        .0;

    let mut current: Option<String> = None;
    let mut rowed = BTreeSet::new();
    for line in rows.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix('"')
            && let Some(name) = rest.strip_suffix("\",")
        {
            current = Some(name.to_owned());
            continue;
        }
        if let Some(rest) = line.strip_prefix("DenialClause::")
            && let Some(clause) = rest.strip_suffix(',')
            && current.as_deref() == Some(command)
        {
            rowed.insert(clause.to_owned());
        }
    }
    rowed
}

/// **The denial table this correction landed does not carry every pair this crate
/// constructs.**
///
/// `services/sts/tests/declared_denials.rs` opens: "every `(command, clause)` pair this
/// crate can produce is decided against `generated/ir/system.json`, and a clause whose
/// phrase the contract does not carry fails here naming both", and its `ROWS` is documented
/// as "Every `(command, clause)` pair this crate's handlers construct, with what declares
/// it". Correction round 1's ruling F4 accepted the unit on that claim.
///
/// `introspect_credential` refuses a presented credential of another organization with
/// `DenialClause::OrganizationMismatch` (`services/sts/src/resolve.rs:498`), and `ROWS`
/// carries no row pairing that clause with `mandate.credential.IntrospectCredential`. It is
/// not caught by the other direction either: `assert_clauses_match_rows` runs for the two
/// authorization-code commands alone.
///
/// The half that matters for the contract is that the pair has no obvious phrase to be
/// given. `IntrospectCredential`'s declared denial names "Caller proof lacks introspection
/// authority for the registered server/tenant", "is itself invalid, revoked or expired",
/// "the presented credential proof is malformed", "principal/connection/epoch validation
/// fails", "audience mismatches" and "authoritative online resolution is unavailable" — and
/// none of those is "the presented credential is another organization's", which is what
/// this branch refuses.
#[test]
fn the_denial_table_carries_no_row_for_a_clause_introspection_produces() {
    let (fold, _) = two_organizations_sharing_an_audience();

    // The handler produces the pair, through the real `introspect_credential`, on an
    // ordinary deployment: two organizations that each registered `api-a`.
    let denied = introspect_credential(
        &IntrospectCredential {
            caller_proof: proof(CALLER_SECRET),
            credential_proof: proof(PRESENTED_SECRET),
        },
        &request(),
        &fold,
        IntrospectionParts {
            digest: &Sha256Digest,
            resolution: &fold,
        },
    )
    .expect_err("a presented credential of another organization");

    assert_eq!(denied.reason, DenialReason::TenantMismatch);
    assert_eq!(
        denied.clause,
        DenialClause::OrganizationMismatch,
        "services/sts/src/resolve.rs refuses a presented credential of another organization"
    );

    // The table is parsed, and the parse is shown to work before anything is concluded from
    // what it does not contain.
    let rowed = rowed_clauses("mandate.credential.IntrospectCredential");
    for known in [
        "ProofMalformed",
        "AudienceMismatch",
        "ResolutionUnavailable",
    ] {
        assert!(
            rowed.contains(known),
            "the ROWS parse is broken: no {known} row for IntrospectCredential, read {rowed:?}"
        );
    }

    assert!(
        rowed.contains("OrganizationMismatch"),
        "services/sts/src/resolve.rs constructs (IntrospectCredential, OrganizationMismatch) \
         and services/sts/tests/declared_denials.rs rows {rowed:?} for that command, so the \
         file's claim to decide `every (command, clause) pair this crate can produce` \
         against the contract does not hold for this pair"
    );
}

/// **The same port fails closed two ways: `Unavailable` for two of its questions and a
/// positive `ClientDisabled` for the third.**
///
/// Correction round 1 gave [`mandate_sts::code::OAuthClientReads`] two new questions and one
/// rule for both: "`None` is not 'yes': a reader that holds no answer has not decided that
/// this client is public, and `admitted_client` fails closed on it with
/// `DenialReason::Unavailable`" (`services/sts/src/code.rs`). `redirect_registered` carries
/// the same sentence, `SessionReads::epoch_standing` carries it for the session port, and
/// `CredentialResolution` carries it for the resolution port — four ports, one crate-wide
/// reading of a reader that cannot answer.
///
/// `is_enabled` is the exception, and its own doc comment is what makes it one: "'not
/// registered' and 'registered and disabled' are different refusals, exactly as they are for
/// a resource server". `admitted_client` writes `clients.is_enabled(client_id) != Some(true)`
/// and returns `DenialClause::ClientDisabled` with `DenialReason::Denied` — the second of
/// those two refusals — for a reader that answered neither.
///
/// **What reaches it: nothing found.** `RecordedClients` answers `None` to `is_enabled` only
/// for a client it also answers `None` to `client_organization` for, and `admitted_client`
/// refuses that one `ClientUnregistered` first. The deployment adapter over
/// `mandate_federation`'s fold is the composition's (`story:product-listener`) and is not in
/// this tree, so this case builds the reader rather than finding one. The finding is that
/// the port admits a state its own rule does not cover, not that a caller is reaching it
/// today.
#[test]
fn a_client_reader_that_cannot_answer_enabled_is_reported_as_a_disabled_client() {
    /// A reader that knows the registration and cannot answer whether it is enabled.
    struct CannotAnswerEnabled;

    impl OAuthClientReads for CannotAnswerEnabled {
        fn client_organization(&self, _: &OAuthClientId) -> Option<OrganizationId> {
            Some(organization(10))
        }

        fn is_enabled(&self, _: &OAuthClientId) -> Option<bool> {
            None
        }

        fn is_public(&self, _: &OAuthClientId) -> Option<bool> {
            Some(true)
        }

        fn redirect_registered(&self, _: &OAuthClientId, _: &RedirectUri) -> Option<bool> {
            Some(true)
        }
    }

    let denied = admitted_client(&client(), &organization(10), &CannotAnswerEnabled, true)
        .expect_err("a reader that cannot answer whether the client is enabled");

    assert_eq!(
        denied.reason,
        DenialReason::Unavailable,
        "a reader that holds no answer has decided nothing — the rule services/sts/src/code.rs \
         states for is_public and redirect_registered — but is_enabled answers {:?} with \
         {:?}, which is the positive refusal its own port doc calls a different refusal from \
         `not registered`",
        denied.reason,
        denied.clause
    );
}

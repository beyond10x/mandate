//! Adversary pass 1 over `story:federation-identity-alignment`, the `mandate-federation`
//! half. Every case drives the real handlers and decides them against
//! `generated/ir/system.json` or against `Projection::fold`, never against a sentence
//! written here.

use mandate_federation::authorize::{
    AuthorizationCode, AuthorizationCodeState, PresentedRedemption, RequestBinding,
    ValidateAuthorizationCode, validate_authorization_code,
};
use mandate_federation::disable::{UnlinkExternalPrincipal, unlink_external_principal};
use mandate_federation::link::{LinkExternalPrincipal, link_external_principal};
use mandate_federation::pkce::{PkceDigest, StandInDigest};
use mandate_federation::publicclient::RecordedClients;
use mandate_federation::record::{
    Projection, RegisterFederationConnection, register_federation_connection,
};
use mandate_federation::{
    ESS_REALIZATIONS, ExternalPrincipalStore, PrincipalState, RecordedPrincipals, RefusedOutcome,
    RequestContext, SequentialAllocator,
};
use mandate_identity::IdentityLog;
use mandate_model::TenantResolutionRule;
use mandate_testkit::contract::check_single_emission;
use mandate_types::value::Uuid;
use mandate_types::{
    Action, Audience, AuthorityScope, AuthorizationCodeId, ClientId, CorrelationId, CredentialId,
    CredentialProof, ExternalLinkMethod, ExternalSubject, Issuer, OAuthClientId, OrganizationId,
    PkceMethod, PrincipalId, RedirectUri, ResourceServerId, SessionId, Timestamp, VerifiedContext,
};

const ISSUER: &str = "https://idp.example";
const SUBJECT: &str = "subject-one";
const REGISTERED: &str = "https://app.example/callback";

/// The instant the writer that appended second read its request at. It is the *earlier*
/// of the two, which is the order `record_link` resolves the composite key by.
const EARLY: &str = "2026-09-18T00:00:00Z";
/// The instant the writer that appended first read its request at.
const LATE: &str = "2026-09-19T00:00:00Z";

fn uuid(tag: u8) -> Uuid {
    Uuid::from_bytes([tag; 16])
}

fn organization() -> OrganizationId {
    OrganizationId::new(uuid(10))
}

fn principal() -> PrincipalId {
    PrincipalId::new(uuid(0x21))
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
        correlation: CorrelationId::new("adversary-alignment-1"),
    }
}

fn request_at(at: &str) -> RequestContext {
    RequestContext {
        audience: Audience::new("mandate"),
        correlation: CorrelationId::new("adversary-alignment-1"),
        credential: CredentialId::new(uuid(0xcd)),
        at: Timestamp::new(at),
    }
}

fn unconditional() -> TenantResolutionRule {
    TenantResolutionRule {
        configured_organization: organization(),
        verified_claim_name: None,
        verified_claim_value: None,
    }
}

/// A verifier in the declared form. A synthetic marker, never credential material.
fn verifier() -> CredentialProof {
    let mut text = String::from("mandate-adversary-verifier-one");
    while text.len() < 43 {
        text.push('~');
    }
    CredentialProof::from_bytes(text.into_bytes())
}

/// The element the crate's own registry names as the one a symbol realizes.
fn realized_element(symbol_suffix: &str) -> &'static str {
    let matches: Vec<&'static str> = ESS_REALIZATIONS
        .iter()
        .filter(|(_, symbol)| symbol.replace(' ', "").ends_with(symbol_suffix))
        .map(|(element, _)| *element)
        .collect();
    match matches.as_slice() {
        [single] => single,
        other => panic!(
            "mandate_federation::ESS_REALIZATIONS names {} elements for `{symbol_suffix}`: {other:?}",
            other.len()
        ),
    }
}

/// The refusal a consumed authorization code produces names an outcome the contract
/// declares for the command this crate registers the handler against.
#[test]
fn a_consumed_code_refusal_names_an_outcome_the_contract_declares_for_its_command() {
    let code = AuthorizationCode {
        id: AuthorizationCodeId::new(uuid(0xc0)),
        client_id: OAuthClientId::new(uuid(0x0c)),
        session_id: SessionId::new(uuid(0x5e)),
        challenge: StandInDigest.challenge(&verifier()),
        method: PkceMethod::S256,
        redirect_uri: RedirectUri::new(REGISTERED),
        expires_at: Timestamp::new("2026-09-19T12:00:00Z"),
        target: ResourceServerId::new(uuid(0x7a)),
        scope: AuthorityScope {
            actions: vec![Action::new("read")],
            resources: Vec::new(),
            space: None,
        },
        // The declared terminal state.
        state: AuthorizationCodeState::Consumed,
    };
    let input = ValidateAuthorizationCode {
        code,
        binding: RequestBinding {
            state: "state-from-the-authorization-request".to_owned(),
            nonce: "nonce-from-the-authorization-request".to_owned(),
        },
        presented: PresentedRedemption {
            redirect_uri: RedirectUri::new(REGISTERED),
            verifier: Some(verifier()),
            state: "state-from-the-authorization-request".to_owned(),
            nonce: Some("nonce-from-the-authorization-request".to_owned()),
        },
    };
    let registry = RecordedClients::new();
    let sessions = IdentityLog::new();

    let denied = validate_authorization_code(
        &input,
        &request_at(LATE),
        &registry,
        &registry,
        &sessions,
        &StandInDigest,
    )
    .expect_err("`Consumed` is the declared terminal state");

    // Coordinator ruling after adversary pass 1 (A1-1): `AuthorizePublicClient` is
    // non-consuming and declares `accepted` and `denied` only; the wrong-state outcome for
    // a consumed code is `RedeemAuthorizationCode`'s (story:oauth-integration).
    assert_eq!(
        denied.outcome,
        RefusedOutcome::Denied,
        "a consumed code at the non-consuming validation is the declared denied outcome"
    );

    // Exactly what `crates/mandate-federation/tests/emitted_events.rs`'s `refused` helper
    // does for every other handler in this crate: look the outcome the refusal names up
    // on the command the crate's registry says the handler realizes.
    let command = realized_element("::validate_authorization_code");
    let looked_up = check_single_emission(command, denied.outcome.ir_name(), &[]);
    assert!(
        looked_up.is_ok(),
        "the refusal names the outcome `{}`, and {command} (the element \
         mandate_federation::ESS_REALIZATIONS pairs with this handler) does not declare \
         it: {looked_up:?}",
        denied.outcome.ir_name()
    );
}

/// An unlink decided before a concurrent link on the same key landed leaves a durable log
/// that `Projection::fold` cannot read at all.
#[test]
fn an_unlink_decided_before_a_concurrent_link_landed_leaves_the_log_unfoldable() {
    let mut allocator = SequentialAllocator::new();
    let registered = register_federation_connection(
        &RegisterFederationConnection {
            context: context(),
            issuer: Issuer::new(ISSUER),
            client_id: ClientId::new("configured-client"),
            tenant_resolution: unconditional(),
            jit_provisioning: true,
        },
        &Projection::default(),
        &mut allocator,
    )
    .expect("the organization binding is the caller's own");
    let created = registered.event;
    let after_registration =
        Projection::fold(std::slice::from_ref(&created)).expect("one creation");

    let principals = RecordedPrincipals::over(after_registration).with_principal(
        principal(),
        organization(),
        PrincipalState::Active,
    );
    let link = LinkExternalPrincipal {
        context: context(),
        connection_id: registered.connection_id,
        external_subject: ExternalSubject::new(SUBJECT),
        principal_id: principal(),
        method: ExternalLinkMethod::Administrator,
    };

    // Two writers on two `ExternalPrincipal` aggregates. Each is decided against the
    // projection as it stood before either append, which is the read-then-write window
    // `src/disable.rs` says the kit's compare-and-set closes — and it does not, because
    // the compare-and-set is on the *appending* aggregate's stream version and these are
    // two different aggregates.
    let first = link_external_principal(
        &link,
        &request_at(LATE),
        &principals,
        &principals,
        &mut allocator,
    )
    .expect("the key is free when this writer reads");
    let second = link_external_principal(
        &link,
        &request_at(EARLY),
        &principals,
        &principals,
        &mut allocator,
    )
    .expect("the key is free when this writer reads too");
    assert_ne!(
        first.external_principal_id, second.external_principal_id,
        "two writers, two link records"
    );

    // The first writer's append lands. The unlink is decided against that projection,
    // where its record holds the key and is `Linked`.
    let after_first =
        Projection::fold(&[created.clone(), first.event.clone()]).expect("one creation, one link");
    assert!(
        after_first
            .external_principal(&first.external_principal_id)
            .is_some(),
        "the record the unlink is decided against"
    );
    let unlinked = unlink_external_principal(
        &UnlinkExternalPrincipal {
            id: first.external_principal_id,
            context: context(),
        },
        &after_first,
    )
    .expect("a `Linked` record inside the caller's verified organization");

    // The durable log, in the order the three appends committed.
    let log = vec![created, first.event, second.event, unlinked];

    let rebuilt = Projection::fold(&log);
    assert!(
        rebuilt.is_ok(),
        "every command was accepted against the state it read, and the projection no \
         longer rebuilds from the log they wrote — so no federation read model exists at \
         all: {rebuilt:?}"
    );
}

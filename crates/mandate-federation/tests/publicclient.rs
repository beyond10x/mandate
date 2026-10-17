//! The registered public-client read port, its `pub` double, and the exact-redirect,
//! `public`, lifecycle and organization checks `AuthorizeClient` names.
//!
//! `pkce-redirect` (`tests/security/cases.json:405`) is `story:oauth-integration`'s and
//! is underwritten here as a predicate: a redirect that is not byte-identical to a
//! registered one is refused. Nothing here consumes a code or creates a credential.

use mandate_federation::publicclient::{
    OAuthClientStore, RecordedClients, registered_client, registered_public_client,
};
use mandate_federation::record::{OAuthClient, OAuthClientState, Projection};
use mandate_federation::register_client::{
    ConfiguredAdmission, RegisterOAuthClient, register_o_auth_client,
};
use mandate_federation::{DenialClause, SequentialAllocator};
use mandate_types::value::Uuid;
use mandate_types::{
    Audience, CorrelationId, CredentialId, DenialReason, OAuthClientId, OrganizationId, PkceMethod,
    PrincipalId, RedirectUri, VerifiedContext,
};

const REGISTERED: &str = "https://app.example/callback";
const SECOND_REGISTERED: &str = "https://app.example/other";

fn uuid(tag: u8) -> Uuid {
    Uuid::from_bytes([tag; 16])
}

fn organization(tag: u8) -> OrganizationId {
    OrganizationId::new(uuid(tag))
}

fn client_id(tag: u8) -> OAuthClientId {
    OAuthClientId::new(uuid(tag))
}

/// The caller the admission holds client-administration authority for.
fn administrator() -> PrincipalId {
    PrincipalId::new(uuid(0x51))
}

fn redirect(text: &str) -> RedirectUri {
    RedirectUri::new(text)
}

fn client(public: bool, state: OAuthClientState) -> OAuthClient {
    OAuthClient {
        id: client_id(0x0c),
        organization_id: organization(10),
        client_type: if public {
            mandate_types::OAuthClientType::Public
        } else {
            mandate_types::OAuthClientType::Confidential
        },
        secret_verifiers: Vec::new(),
        pkce_required: public,
        trusted_peers: Vec::new(),
        post_logout_redirect_uris: Vec::new(),
        redirect_uris: vec![redirect(REGISTERED), redirect(SECOND_REGISTERED)],
        pkce_method: PkceMethod::S256,
        state,
    }
}

fn recorded() -> RecordedClients {
    RecordedClients::new().with_client(client(true, OAuthClientState::Recorded))
}

#[test]
fn a_registered_public_client_resolves_for_an_exactly_registered_redirect() {
    for uri in [REGISTERED, SECOND_REGISTERED] {
        let resolved = registered_public_client(
            &recorded(),
            &client_id(0x0c),
            &redirect(uri),
            &organization(10),
        )
        .expect("a public, recorded client of this organization admits its own redirect");

        assert_eq!(resolved.id, client_id(0x0c));
        assert_eq!(
            resolved.pkce_method,
            PkceMethod::S256,
            "the contract declares one method, and the client requires it"
        );
    }
}

#[test]
fn a_client_the_read_model_does_not_answer_is_refused() {
    let denied = registered_public_client(
        &recorded(),
        &client_id(0x0d),
        &redirect(REGISTERED),
        &organization(10),
    )
    .expect_err("an unanswered client is not a registered public client");

    assert_eq!(denied.reason, DenialReason::Denied);
    assert_eq!(denied.clause, DenialClause::ClientUnknown);
}

#[test]
fn a_confidential_client_is_refused() {
    let clients = RecordedClients::new().with_client(client(false, OAuthClientState::Recorded));

    let denied = registered_public_client(
        &clients,
        &client_id(0x0c),
        &redirect(REGISTERED),
        &organization(10),
    )
    .expect_err("a client that is not public is not a registered public client");

    assert_eq!(denied.reason, DenialReason::Denied);
    assert_eq!(denied.clause, DenialClause::ClientNotPublic);
}

#[test]
fn a_disabled_client_is_refused() {
    let clients = RecordedClients::new().with_client(client(true, OAuthClientState::Disabled));

    let denied = registered_public_client(
        &clients,
        &client_id(0x0c),
        &redirect(REGISTERED),
        &organization(10),
    )
    .expect_err("`Disabled` is the declared terminal state");

    assert_eq!(denied.reason, DenialReason::Denied);
    assert_eq!(denied.clause, DenialClause::ClientDisabled);
}

#[test]
fn a_client_bound_to_another_organization_is_refused() {
    let denied = registered_public_client(
        &recorded(),
        &client_id(0x0c),
        &redirect(REGISTERED),
        &organization(11),
    )
    .expect_err("the client's organization is the binding, not the caller's claim");

    assert_eq!(denied.reason, DenialReason::TenantMismatch);
    assert_eq!(denied.clause, DenialClause::OrganizationMismatch);
}

/// `pkce-redirect` (`tests/security/cases.json:405`): "Redirect differs from exact
/// registered/authorized URI" denies. Each value below differs from a registered one by
/// one byte, one segment, one query or one case fold; none is normalized into a match.
#[test]
fn a_redirect_that_is_not_byte_identical_to_a_registered_one_is_refused() {
    for presented in [
        "https://app.example/callback/",
        "https://app.example/Callback",
        "https://APP.example/callback",
        "https://app.example/callback?code=1",
        "https://app.example/callback#fragment",
        "http://app.example/callback",
        "https://app.example/callback/../callback",
        "",
    ] {
        let denied = registered_public_client(
            &recorded(),
            &client_id(0x0c),
            &redirect(presented),
            &organization(10),
        )
        .expect_err("a redirect is admitted only when it is byte-identical to a registered one");

        assert_eq!(denied.reason, DenialReason::Denied);
        assert_eq!(
            denied.clause,
            DenialClause::RedirectMismatch,
            "{presented} is refused for the redirect binding"
        );
    }
}

#[test]
fn a_fold_over_no_registration_answers_the_port_and_resolves_no_client() {
    // A log that carries no `mandate.federation.OAuthClientRegistered` records no client,
    // and the port answers that rather than defaulting one into existence.
    let projection = Projection::default();

    assert_eq!(projection.clients(), &[]);
    assert_eq!(projection.client(&client_id(0x0c)), None);

    let denied = registered_public_client(
        &projection,
        &client_id(0x0c),
        &redirect(REGISTERED),
        &organization(10),
    )
    .expect_err("an empty read model answers no registered client");

    assert_eq!(denied.clause, DenialClause::ClientUnknown);
}

/// The registered client `AuthorizeClient` reads is the one the real command wrote.
///
/// Every case above fixtures a client through the `pub` double, because until
/// `mandate.federation.RegisterOAuthClient` was declared no event created one. This drives
/// the real handler, folds the event it emits, and reads the result through the same
/// predicate: the client the port resolves is the record the registration wrote, field for
/// field, and the redirect binding is decided against the registered set and nothing else.
#[test]
fn a_client_registered_through_the_real_command_is_what_the_port_resolves() {
    let mut allocator = SequentialAllocator::new();
    let input = RegisterOAuthClient {
        context: VerifiedContext {
            subject: administrator(),
            actor: None,
            organization: organization(10),
            audience: Audience::new("mandate"),
            credential: CredentialId::new(uuid(0xcd)),
            delegation: None,
            execution: None,
            correlation: CorrelationId::new("declared-writers"),
        },
        client_type: mandate_types::OAuthClientType::Public,
        secret_verifiers: Vec::new(),
        pkce_required: true,
        trusted_peers: Vec::new(),
        post_logout_redirect_uris: Vec::new(),
        redirect_uris: vec![redirect(REGISTERED), redirect(SECOND_REGISTERED)],
        pkce_method: PkceMethod::S256,
    };
    let registered = register_o_auth_client(
        &input,
        &ConfiguredAdmission::new()
            .with_administrator(administrator())
            .with_organization(organization(10))
            .with_redirect_uri(organization(10), redirect(REGISTERED))
            .with_redirect_uri(organization(10), redirect(SECOND_REGISTERED)),
        &mut allocator,
    )
    .expect("an administrator of an admitted organization registering admitted redirects");

    let projection = Projection::fold(&[registered.event]).expect("one creation");

    for uri in [REGISTERED, SECOND_REGISTERED] {
        let resolved = registered_public_client(
            &projection,
            &registered.id,
            &redirect(uri),
            &organization(10),
        )
        .expect("the registered client admits its own redirects");

        assert_eq!(
            resolved,
            OAuthClient {
                id: registered.id,
                organization_id: organization(10),
                client_type: mandate_types::OAuthClientType::Public,
                secret_verifiers: Vec::new(),
                pkce_required: true,
                trusted_peers: Vec::new(),
                post_logout_redirect_uris: Vec::new(),
                redirect_uris: vec![redirect(REGISTERED), redirect(SECOND_REGISTERED)],
                pkce_method: PkceMethod::S256,
                state: OAuthClientState::Recorded,
            },
            "the record the port resolves is the one the registration wrote"
        );
    }

    let denied = registered_public_client(
        &projection,
        &registered.id,
        &redirect("https://app.example/callback/"),
        &organization(10),
    )
    .expect_err("a redirect the registration did not record is not admitted");

    assert_eq!(denied.clause, DenialClause::RedirectMismatch);
}

// ------------------------------------------------- registered_client (AuthorizeClient)

#[test]
fn a_confidential_client_that_does_not_require_pkce_is_admitted_without_a_challenge() {
    let mut confidential = client(false, OAuthClientState::Recorded);
    confidential.pkce_required = false;
    let clients = RecordedClients::new().with_client(confidential);

    let resolved = registered_client(
        &clients,
        &client_id(0x0c),
        &redirect(REGISTERED),
        &organization(10),
        false,
    )
    .expect("a confidential client that does not require PKCE admits a request without one");
    assert_eq!(resolved.id, client_id(0x0c));
}

#[test]
fn a_client_that_requires_pkce_is_refused_a_request_without_a_challenge() {
    // A public client always requires it, even with `pkce_required` recorded false; a
    // confidential one requires it when its registration says so.
    let mut lax_public = client(true, OAuthClientState::Recorded);
    lax_public.pkce_required = false;
    let strict_confidential = {
        let mut record = client(false, OAuthClientState::Recorded);
        record.pkce_required = true;
        record
    };
    for record in [lax_public, strict_confidential] {
        let clients = RecordedClients::new().with_client(record);
        let denied = registered_client(
            &clients,
            &client_id(0x0c),
            &redirect(REGISTERED),
            &organization(10),
            false,
        )
        .expect_err("a request without a challenge is refused");
        assert_eq!(denied.reason, DenialReason::Denied);
        assert_eq!(denied.clause, DenialClause::ChallengeAbsent);
        assert!(
            registered_client(
                &clients,
                &client_id(0x0c),
                &redirect(REGISTERED),
                &organization(10),
                true,
            )
            .is_ok(),
            "the same request with a challenge is admitted"
        );
    }
}

#[test]
fn registered_client_keeps_the_registration_refusals() {
    let clients = recorded();
    let other_organization = registered_client(
        &clients,
        &client_id(0x0c),
        &redirect(REGISTERED),
        &organization(11),
        true,
    )
    .expect_err("another organization's client");
    assert_eq!(
        other_organization.clause,
        DenialClause::OrganizationMismatch
    );
    let unregistered = registered_client(
        &clients,
        &client_id(0x0c),
        &redirect("https://elsewhere.example/cb"),
        &organization(10),
        true,
    )
    .expect_err("an unregistered redirect");
    assert_eq!(unregistered.clause, DenialClause::RedirectMismatch);
}

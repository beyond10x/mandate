//! Security review of `RegisterOAuthClient`: the refusals its `denied` outcome declares that
//! the input alone decides.
//!
//! `systems/mandate/domains/federation.yaml`, `RegisterOAuthClient.denied`: "a public client
//! states a secret verifier or does not require PKCE, a confidential client states no verifier
//! or more than two, a trusted peer names the client itself or no client registered in the
//! verified organization". The conformance runner reaches those scenarios by arming a fault in
//! the admission port, so the handler is never asked to decide them. These cases ask it, with
//! an admission that admits the caller, the organization and the redirect URI, so the only
//! thing left to refuse is the clause each case names.

use mandate_federation::register_client::{
    ConfiguredAdmission, RegisterOAuthClient, register_o_auth_client,
};
use mandate_federation::{DenialClause, IdentityAllocator, SequentialAllocator};
use mandate_types::value::Uuid;
use mandate_types::{
    Audience, CorrelationId, CredentialId, CredentialVerifier, OAuthClientId, OAuthClientType,
    OrganizationId, PkceMethod, PrincipalId, RedirectUri, VerifiedContext,
};

const REDIRECT: &str = "https://app.example/callback";

fn uuid(tag: u8) -> Uuid {
    Uuid::from_bytes([tag; 16])
}

fn context() -> VerifiedContext {
    VerifiedContext {
        subject: PrincipalId::new(uuid(0x51)),
        actor: None,
        organization: OrganizationId::new(uuid(10)),
        audience: Audience::new("mandate"),
        credential: CredentialId::new(uuid(0xcd)),
        delegation: None,
        execution: None,
        correlation: CorrelationId::new("security-review"),
    }
}

fn admitting() -> ConfiguredAdmission {
    ConfiguredAdmission::new()
        .with_administrator(PrincipalId::new(uuid(0x51)))
        .with_organization(OrganizationId::new(uuid(10)))
        .with_redirect_uri(OrganizationId::new(uuid(10)), RedirectUri::new(REDIRECT))
}

fn verifier(tag: &str) -> CredentialVerifier {
    CredentialVerifier::new(format!("kv1.review.{tag}"))
}

fn input(client_type: OAuthClientType) -> RegisterOAuthClient {
    RegisterOAuthClient {
        context: context(),
        client_type,
        secret_verifiers: Vec::new(),
        redirect_uris: vec![RedirectUri::new(REDIRECT)],
        pkce_method: PkceMethod::S256,
        pkce_required: true,
        trusted_peers: Vec::new(),
        post_logout_redirect_uris: Vec::new(),
    }
}

fn refused(name: &str, input: &RegisterOAuthClient) {
    let mut allocator = SequentialAllocator::new();
    let decided = register_o_auth_client(input, &admitting(), &mut allocator);
    assert!(
        decided.is_err(),
        "{name}: registered and emitted {:?}",
        decided.map(|registered| registered.event)
    );
}

#[test]
fn a_public_client_that_does_not_require_pkce_is_refused() {
    let mut public = input(OAuthClientType::Public);
    public.pkce_required = false;
    refused("a public client with pkce_required false", &public);
}

#[test]
fn a_public_client_stating_a_secret_verifier_is_refused() {
    let mut public = input(OAuthClientType::Public);
    public.secret_verifiers = vec![verifier("one")];
    refused("a public client with a secret verifier", &public);
}

#[test]
fn a_confidential_client_stating_no_verifier_is_refused() {
    let confidential = input(OAuthClientType::Confidential);
    refused("a confidential client with no verifier", &confidential);
}

#[test]
fn a_confidential_client_stating_three_verifiers_is_refused() {
    let mut confidential = input(OAuthClientType::Confidential);
    confidential.secret_verifiers = vec![verifier("one"), verifier("two"), verifier("three")];
    refused("a confidential client with three verifiers", &confidential);
}

#[test]
fn a_trusted_peer_naming_no_registered_client_is_refused() {
    let mut confidential = input(OAuthClientType::Confidential);
    confidential.secret_verifiers = vec![verifier("one")];
    // No client is registered at all, so this peer is in no organization, the caller's
    // included: a peer the registration cannot place inside the verified organization.
    confidential.trusted_peers = vec![OAuthClientId::new(uuid(0xee))];
    refused("a trusted peer naming no registered client", &confidential);
}

// The other side of each boundary: what the same clauses admit, and the one peer clause
// the cases above do not reach.

fn clause_of(input: &RegisterOAuthClient, admission: &ConfiguredAdmission) -> DenialClause {
    register_o_auth_client(input, admission, &mut SequentialAllocator::new())
        .expect_err("refused")
        .clause
}

#[test]
fn each_input_decided_refusal_names_its_own_clause() {
    let mut public = input(OAuthClientType::Public);
    public.secret_verifiers = vec![verifier("one")];
    assert_eq!(
        clause_of(&public, &admitting()),
        DenialClause::PublicClientVerifier
    );
    let mut public = input(OAuthClientType::Public);
    public.pkce_required = false;
    assert_eq!(
        clause_of(&public, &admitting()),
        DenialClause::PublicClientPkceOptional
    );
    let confidential = input(OAuthClientType::Confidential);
    assert_eq!(
        clause_of(&confidential, &admitting()),
        DenialClause::ConfidentialVerifierAbsent
    );
    let mut confidential = input(OAuthClientType::Confidential);
    confidential.secret_verifiers = vec![verifier("one"), verifier("two"), verifier("three")];
    assert_eq!(
        clause_of(&confidential, &admitting()),
        DenialClause::ConfidentialVerifierExcess
    );
    let mut confidential = input(OAuthClientType::Confidential);
    confidential.secret_verifiers = vec![verifier("one")];
    confidential.trusted_peers = vec![OAuthClientId::new(uuid(0xee))];
    assert_eq!(
        clause_of(&confidential, &admitting()),
        DenialClause::TrustedPeerUnknown
    );
}

#[test]
fn a_confidential_client_with_two_verifiers_pkce_optional_and_a_registered_peer_is_admitted() {
    let peer = OAuthClientId::new(uuid(0xee));
    let mut confidential = input(OAuthClientType::Confidential);
    confidential.secret_verifiers = vec![verifier("one"), verifier("two")];
    confidential.pkce_required = false;
    confidential.trusted_peers = vec![peer];
    let admission = admitting().with_registered_client(OrganizationId::new(uuid(10)), peer);
    let registered =
        register_o_auth_client(&confidential, &admission, &mut SequentialAllocator::new());
    assert!(registered.is_ok(), "{registered:?}");
}

#[test]
fn a_peer_registered_in_another_organization_is_refused() {
    let peer = OAuthClientId::new(uuid(0xee));
    let mut confidential = input(OAuthClientType::Confidential);
    confidential.secret_verifiers = vec![verifier("one")];
    confidential.trusted_peers = vec![peer];
    let admission = admitting().with_registered_client(OrganizationId::new(uuid(11)), peer);
    assert_eq!(
        clause_of(&confidential, &admission),
        DenialClause::TrustedPeerUnknown
    );
}

#[test]
fn a_trusted_peer_naming_the_client_itself_is_refused_whatever_the_admission_answers() {
    // The identity this registration will be given, read off an identical allocator.
    let itself = SequentialAllocator::new().next_o_auth_client_id();
    let mut confidential = input(OAuthClientType::Confidential);
    confidential.secret_verifiers = vec![verifier("one")];
    confidential.trusted_peers = vec![itself];
    // An admission that would place that identity in the organization.
    let admission = admitting().with_registered_client(OrganizationId::new(uuid(10)), itself);
    assert_eq!(
        clause_of(&confidential, &admission),
        DenialClause::TrustedPeerSelf
    );
}

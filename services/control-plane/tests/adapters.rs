//! The three cross-crate port adapters, and the `code` → `code_id` resolution.
//!
//! Each adapter presents one crate's read model as another crate's declared port, because
//! `dependency-boundaries.json` gives neither crate the other: `mandate-federation` has no
//! `mandate-sts`, and `mandate-sts` has neither `mandate-federation` nor `mandate-identity`
//! (`services/sts/src/code.rs`, `services/sts/src/binding.rs`). The adapters land in the
//! composition for that reason (`story:product-listener`, ruling D1).
//!
//! # The doubles used here, named
//!
//! * [`mandate_sts::issue::Sha256Digest`] — not a double: it is the shipped digest, and the
//!   one the composition wires.
//! * [`mandate_sts::CountingSecrets`] and [`mandate_sts::SequentialAllocator`] — **doubles**,
//!   declared `pub` in that crate for exactly this. Both mint predictable values; a
//!   deployment mints from a CSPRNG.
//!
//! Nothing here opens a socket. `tests/serve.rs` is the road over HTTP.

use mandate_control_plane::adapters::{
    Configuration, ConfigurationRefused, Deployment, IssuerRefused, OAuthClientReadsOver,
    SessionProofs, SessionReadsOver, TargetRegistryOver, resolve_code_id, session_proof_verifier,
};
use mandate_federation::authorize::TargetRegistry;
use mandate_federation::record::{FederationEvent, OAuthClientState, Projection};
use mandate_federation::verifier::{ConstructedVerifier, VerifiedProof};
use mandate_federation::verifier_real::FixedClock;
use mandate_identity::{
    EpochSnapshotRecorded, Generation, IdentityEvent, IdentityLog, IdentityRead,
    SecurityEpochRecorded, SessionOpened, SessionRevoked,
};
use mandate_sts::binding::{EpochStanding, SessionReads};
use mandate_sts::code::{
    AuthorizationCodeParts, CodeIssuance, CodeLifetime, IssueAuthorizationCode, OAuthClientReads,
};
use mandate_sts::issue::Sha256Digest;
use mandate_sts::registry::{RegisterResourceServer, register_resource_server};
use mandate_sts::store::{AuthorizationCodeReads, CodeProjection};
use mandate_sts::{CountingSecrets, RequestContext, SecretSource, SequentialAllocator};
use mandate_token::CredentialProfile;
use mandate_token::projection::Projection as CredentialProjection;
use mandate_token::verifier::{CredentialDomain, verifier_in};
use mandate_types::{
    Audience, AuthorityScope, CorrelationId, CredentialId, CredentialKind, CredentialProof,
    Duration, OAuthClientId, OrganizationId, PkceChallenge, PkceMethod, PrincipalId, RedirectUri,
    ResourceServerId, RevocationGuarantee, SecurityEpochTarget, SessionId, Timestamp, Transient,
    Uuid, VerifiedContext,
};

fn uuid(tag: u8) -> Uuid {
    Uuid::from_bytes([tag; 16])
}

fn organization() -> OrganizationId {
    OrganizationId::new(uuid(0x0a))
}

fn principal() -> PrincipalId {
    PrincipalId::new(uuid(0x51))
}

fn session() -> SessionId {
    SessionId::new(uuid(0x5e))
}

fn client() -> OAuthClientId {
    OAuthClientId::new(uuid(0x0c))
}

fn redirect() -> RedirectUri {
    RedirectUri::new("https://client.example/callback")
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
        correlation: CorrelationId::new("adapters"),
    }
}

fn request() -> RequestContext {
    RequestContext {
        correlation: CorrelationId::new("adapters"),
        at: Timestamp::new("2026-09-19T00:00:00Z"),
        epochs: None,
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

/// A credential fold holding one enabled registration, and its identity.
fn registered_target() -> (CredentialProjection, ResourceServerId) {
    let mut allocator = SequentialAllocator::new();
    let registered = register_resource_server(
        &RegisterResourceServer {
            context: context(),
            audience: Audience::new("https://api.example"),
            profile: reference_profile(),
            allowed_exchange_sources: Vec::new(),
        },
        &CredentialProjection::default(),
        &mut allocator,
    )
    .expect("a free audience in the caller's own organization");
    let mut fold = CredentialProjection::default();
    fold.apply(&registered.event).expect("a readable history");
    (fold, registered.resource_server_id)
}

/// A federation fold holding one client, as the event that registers it writes it.
fn recorded_client(public: bool, state: OAuthClientState) -> Projection {
    let mut fold = Projection::default();
    fold.apply(&FederationEvent::OAuthClientRegistered {
        context: context(),
        id: client(),
        organization_id: organization(),
        public,
        redirect_uris: vec![redirect()],
        pkce_method: PkceMethod::S256,
    })
    .expect("a readable history");
    if state == OAuthClientState::Disabled {
        fold.apply(&FederationEvent::OAuthClientDisabled {
            context: context(),
            id: client(),
        })
        .expect("a readable history");
    }
    fold
}

/// An identity fold holding one snapshot and one open session over it.
fn opened_session(expires_at: &str) -> IdentityLog {
    let mut log = IdentityLog::new();
    // The fold binds a snapshot to the generation each dimension holds when the recording
    // lands, and refuses a snapshot naming a dimension no generation has been stated for.
    for target in [
        SecurityEpochTarget::Principal(principal()),
        SecurityEpochTarget::Organization(organization()),
    ] {
        log.try_record(IdentityEvent::SecurityEpochRecorded(
            SecurityEpochRecorded {
                target,
                generation: Generation::ZERO,
            },
        ))
        .expect("the first generation of a dimension is recorded");
    }
    log.try_record(IdentityEvent::EpochSnapshotRecorded(
        EpochSnapshotRecorded {
            id: mandate_types::EpochSnapshotRef::new(uuid(0x3e)),
            principal_id: principal(),
            organization_id: organization(),
            connection_id: None,
        },
    ))
    .expect("a snapshot over stated generations is recorded");
    log.try_record(IdentityEvent::SessionOpened(SessionOpened {
        id: session(),
        principal_id: principal(),
        organization_id: organization(),
        connection_id: None,
        epochs: mandate_types::EpochSnapshotRef::new(uuid(0x3e)),
        expires_at: Timestamp::new(expires_at),
    }))
    .expect("an opening over a recorded snapshot is recorded");
    log
}

// ---------------------------------------------------------------------------------------
// `mandate_federation::authorize::TargetRegistry` over `mandate_sts::registry::ResourceServerReads`
// ---------------------------------------------------------------------------------------

#[test]
fn the_target_registry_answers_from_the_sts_registration_fold() {
    let (fold, target) = registered_target();
    let registry = TargetRegistryOver::over(&fold);

    assert!(
        registry.can_answer(&target),
        "a fold that holds the registered set can answer for a target in it"
    );
    assert_eq!(
        registry.target_organization(&target),
        Some(organization()),
        "the organization the registration binds, read from the STS fold"
    );
}

#[test]
fn the_target_registry_reports_an_unregistered_target_and_not_its_own_blindness() {
    let (fold, _) = registered_target();
    let registry = TargetRegistryOver::over(&fold);
    let unregistered = ResourceServerId::new(uuid(0x4f));

    assert!(
        registry.can_answer(&unregistered),
        "the fold sees its own registered set, so it has decided"
    );
    assert_eq!(
        registry.target_organization(&unregistered),
        None,
        "no event registered this target"
    );
}

// ---------------------------------------------------------------------------------------
// `mandate_sts::code::OAuthClientReads` over `mandate_federation::record::Projection`
// ---------------------------------------------------------------------------------------

#[test]
fn the_client_reads_answer_all_four_questions_from_the_federation_fold() {
    let fold = recorded_client(true, OAuthClientState::Recorded);
    let clients = OAuthClientReadsOver::over(&fold);

    assert_eq!(clients.client_organization(&client()), Some(organization()));
    assert_eq!(clients.is_enabled(&client()), Some(true));
    assert_eq!(clients.is_public(&client()), Some(true));
    assert_eq!(
        clients.redirect_registered(&client(), &redirect()),
        Some(true)
    );
    assert_eq!(
        clients.redirect_registered(&client(), &RedirectUri::new("https://client.example/other")),
        Some(false),
        "the registered set is compared byte for byte and nothing is normalized"
    );
}

#[test]
fn the_client_reads_tell_disabled_and_confidential_from_unregistered() {
    let disabled = recorded_client(true, OAuthClientState::Disabled);
    assert_eq!(
        OAuthClientReadsOver::over(&disabled).is_enabled(&client()),
        Some(false),
        "registered and disabled is a different answer from not registered"
    );

    let confidential = recorded_client(false, OAuthClientState::Recorded);
    assert_eq!(
        OAuthClientReadsOver::over(&confidential).is_public(&client()),
        Some(false)
    );

    let empty = Projection::default();
    let clients = OAuthClientReadsOver::over(&empty);
    assert_eq!(clients.client_organization(&client()), None);
    assert_eq!(clients.is_enabled(&client()), None);
    assert_eq!(clients.is_public(&client()), None);
    assert_eq!(clients.redirect_registered(&client(), &redirect()), None);
}

// ---------------------------------------------------------------------------------------
// `mandate_sts::binding::SessionReads` over `mandate_identity::IdentityRead`
// ---------------------------------------------------------------------------------------

#[test]
fn the_session_reads_answer_from_the_identity_fold() {
    let log = opened_session("2026-12-31T00:00:00Z");
    let sessions = SessionReadsOver::over(&log);

    let binding = sessions.resolve(&session()).expect("the opened session");
    assert_eq!(binding.id, session());
    assert_eq!(binding.subject, principal());
    assert_eq!(binding.organization, organization());
    assert_eq!(
        binding.epochs,
        Some(mandate_types::EpochSnapshotRef::new(uuid(0x3e)))
    );
    assert_eq!(binding.expires_at, Timestamp::new("2026-12-31T00:00:00Z"));
    assert!(!binding.revoked);

    assert_eq!(
        sessions.epoch_standing(&mandate_types::EpochSnapshotRef::new(uuid(0x3e))),
        Some(EpochStanding::Current),
        "every dimension the snapshot names is at the authoritative generation"
    );
    assert_eq!(
        sessions.epoch_standing(&mandate_types::EpochSnapshotRef::new(uuid(0x3f))),
        None,
        "a snapshot the fold does not record is not reported as current"
    );
    assert_eq!(sessions.resolve(&SessionId::new(uuid(0x5f))), None);
}

#[test]
fn the_session_reads_carry_revocation_and_a_moved_generation() {
    let mut log = opened_session("2026-12-31T00:00:00Z");
    log.record(IdentityEvent::SecurityEpochRecorded(
        SecurityEpochRecorded {
            target: SecurityEpochTarget::Principal(principal()),
            generation: Generation::new(1).expect("a non-negative generation"),
        },
    ));
    log.record(IdentityEvent::SessionRevoked(SessionRevoked {
        context: context(),
        id: session(),
    }));

    let sessions = SessionReadsOver::over(&log);
    assert!(
        sessions
            .resolve(&session())
            .expect("the revoked session")
            .revoked,
        "the terminal Revoked state reaches the redemption's port"
    );
    assert_eq!(
        sessions.epoch_standing(&mandate_types::EpochSnapshotRef::new(uuid(0x3e))),
        Some(EpochStanding::Stale(SecurityEpochTarget::Principal(
            principal()
        ))),
        "the dimension that moved is the one the refusal names"
    );
}

// ---------------------------------------------------------------------------------------
// `code` → `code_id`: the by-verifier read the token endpoint resolves through
// ---------------------------------------------------------------------------------------

/// Issue one code and fold it, returning the fold, the code returned once, and its identity.
fn issued_code() -> (CodeProjection, mandate_types::CredentialSecret, Uuid) {
    let (servers, target) = registered_target();
    let clients = recorded_client(true, OAuthClientState::Recorded);
    let mut secrets = CountingSecrets::new();
    let mut allocator = SequentialAllocator::new();
    let issuance = CodeIssuance::new(CodeLifetime::new(Duration::new("PT5M")));
    let outcome = issuance
        .issue(
            &IssueAuthorizationCode {
                context: context(),
                client_id: client(),
                session_id: session(),
                target,
                requested_scope: AuthorityScope {
                    actions: Vec::new(),
                    resources: Vec::new(),
                    space: None,
                },
                challenge: PkceChallenge::new("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"),
                method: PkceMethod::S256,
                redirect_uri: redirect(),
                expires_at: Timestamp::new("2026-09-19T00:04:00Z"),
            },
            &request(),
            &servers,
            &OAuthClientReadsOver::over(&clients),
            AuthorizationCodeParts {
                digest: &Sha256Digest,
                secrets: &mut secrets,
                allocator: &mut allocator,
            },
        )
        .expect("every declared condition of an issuance holds");
    let mut fold = CodeProjection::default();
    fold.apply(&outcome.event).expect("a readable history");
    let code_id = outcome.code_id;
    (fold, outcome.code, uuid_of(code_id))
}

fn uuid_of(id: mandate_types::AuthorizationCodeId) -> Uuid {
    // The identity is compared by its rendered form, which is the only surface both sides
    // of this case share.
    Uuid::parse(&id.to_string()).expect("a declared identity renders its own lexical form")
}

#[test]
fn the_token_endpoint_resolves_a_presented_code_to_the_code_id_it_names() {
    let (fold, code, code_id) = issued_code();
    let presented = CredentialProof::from_bytes(code.expose_material().to_vec());

    let resolved = resolve_code_id(&fold, &Sha256Digest, &presented)
        .expect("the code the issuance returned resolves to the record it minted");
    assert_eq!(
        uuid_of(resolved),
        code_id,
        "the identity `RedeemAuthorizationCode` is called with is the server's, resolved \
         from the presented proof and never taken from the wire"
    );
}

#[test]
fn a_code_that_resolves_to_nothing_is_the_declared_unknown_code_denial() {
    let (fold, _, _) = issued_code();
    let mut elsewhere = CountingSecrets::new();
    for _ in 0..8 {
        let other = elsewhere.next_secret();
        let presented = CredentialProof::from_bytes(other.expose_material().to_vec());
        if resolve_code_id(&fold, &Sha256Digest, &presented).is_some() {
            continue;
        }
        assert_eq!(
            resolve_code_id(&fold, &Sha256Digest, &presented),
            None,
            "a proof no record's verifier was derived from resolves to nothing"
        );
        return;
    }
    panic!("the double minted only codes this fold holds");
}

#[test]
fn the_lookup_is_by_the_stored_verifier_and_never_by_the_secret() {
    let (fold, code, code_id) = issued_code();
    let record = fold
        .authorization_codes()
        .first()
        .expect("the issued code")
        .clone();

    assert_eq!(
        record.verifier,
        verifier_in(
            &Sha256Digest,
            CredentialDomain::AuthorizationCodeVerifier,
            &code
        ),
        "what the record keeps is the domain-separated verifier `issue.rs` stores"
    );
    assert_ne!(
        record.verifier.as_str().as_bytes(),
        code.expose_material(),
        "the code itself is returned once and never recorded"
    );

    // Presenting the *stored verifier* is not presenting the code: the record is resolved
    // by digesting what was presented, not by comparing it to the stored text.
    let as_if_the_verifier_were_the_code =
        CredentialProof::from_bytes(record.verifier.as_str().as_bytes().to_vec());
    assert_eq!(
        resolve_code_id(&fold, &Sha256Digest, &as_if_the_verifier_were_the_code),
        None,
        "a caller holding the verifier holds nothing this read admits"
    );

    // And the domain separation holds: the same material digested as a reference secret
    // resolves to no authorization code.
    let in_another_domain = verifier_in(&Sha256Digest, CredentialDomain::ReferenceSecret, &code);
    assert_ne!(
        record.verifier, in_another_domain,
        "the code's digest space is its own"
    );
    assert_eq!(
        uuid_of(
            resolve_code_id(
                &fold,
                &Sha256Digest,
                &CredentialProof::from_bytes(code.expose_material().to_vec())
            )
            .expect("the code still resolves")
        ),
        code_id
    );
}

#[test]
fn the_by_verifier_read_answers_for_the_record_the_code_names() {
    let (fold, code, code_id) = issued_code();
    let verifier = verifier_in(
        &Sha256Digest,
        CredentialDomain::AuthorizationCodeVerifier,
        &code,
    );
    let record = AuthorizationCodeReads::authorization_code_by_verifier(&fold, &verifier)
        .expect("the record whose stored verifier this is");
    assert_eq!(uuid_of(record.id), code_id);
    assert_eq!(
        AuthorizationCodeReads::authorization_code_by_verifier(
            &fold,
            &mandate_types::CredentialVerifier::new("not a verifier this log holds"),
        ),
        None,
    );
}

// ---------------------------------------------------------------------------------------
// The session proof the composition mints, and resolves back
// ---------------------------------------------------------------------------------------

#[test]
fn a_session_proof_resolves_to_the_session_it_was_minted_for() {
    let mut secrets = CountingSecrets::new();
    let minted = secrets.next_secret();
    let mut proofs = SessionProofs::new();
    proofs.record(&Sha256Digest, &minted, session());

    let presented = CredentialProof::from_bytes(minted.expose_material().to_vec());
    assert_eq!(proofs.resolve(&Sha256Digest, &presented), Some(session()));

    let other = secrets.next_secret();
    assert_eq!(
        proofs.resolve(
            &Sha256Digest,
            &CredentialProof::from_bytes(other.expose_material().to_vec())
        ),
        None,
        "a proof nothing minted resolves to no session"
    );
}

#[test]
fn a_session_proof_lives_in_its_own_digest_space() {
    let mut secrets = CountingSecrets::new();
    let minted = secrets.next_secret();

    let session_space = session_proof_verifier(&Sha256Digest, &minted);
    for domain in [
        CredentialDomain::ReferenceSecret,
        CredentialDomain::SelfContainedToken,
        CredentialDomain::AuthorizationCodeVerifier,
    ] {
        assert_ne!(
            session_space,
            verifier_in(&Sha256Digest, domain, &minted),
            "a session proof presented where {domain:?} material is expected resolves to \
             nothing"
        );
    }
}

// ---------------------------------------------------------------------------------------
// The configuration a deployment is built from (correction round 1, F6 and F9)
// ---------------------------------------------------------------------------------------

/// The verifier double, as `tests/serve.rs` wires it.
fn configured_verifier() -> ConstructedVerifier {
    ConstructedVerifier::admitting(
        &[mandate_types::SigningAlgorithm::new("ES256")],
        VerifiedProof::new(
            mandate_types::Issuer::new("https://idp.example"),
            mandate_types::ExternalSubject::new("subject-1"),
            mandate_types::ClientId::new("mandate-at-idp"),
        ),
    )
    .expect("a non-empty algorithm allowlist")
}

/// A configuration with each value a case varies named.
fn configuration(issuer: &str, code_lifetime: &str, session_lifetime: &str) -> Configuration {
    Configuration {
        issuer: issuer.to_owned(),
        code_lifetime: CodeLifetime::new(Duration::new(code_lifetime)),
        session_lifetime: Duration::new(session_lifetime),
        keys: Vec::new(),
    }
}

type Wired = Deployment<ConstructedVerifier, FixedClock, CountingSecrets, SequentialAllocator>;

/// The deployment that configuration builds, or why it builds none.
fn built(configuration: Configuration) -> Result<Wired, ConfigurationRefused> {
    Deployment::new(
        configuration,
        configured_verifier(),
        FixedClock::at(1_789_084_800),
        CountingSecrets::new(),
        SequentialAllocator::new(),
    )
}

/// A lifetime that names no span is refused where it is read.
///
/// `adapters::instant::span_of` answers `None` for a duration that names no span, and the two
/// sites that read the configured lifetimes used to answer `0` for one — which puts a code's
/// `expires_at` at the request instant, which `services/sts/src/code.rs` refuses as
/// `ExpiryUnbounded`. A deployment built that way starts, serves logins, and refuses every
/// authorization; nothing in the exit status, the startup or the refusal a client reads says
/// the configuration is the reason. It is refused at construction instead.
#[test]
fn a_lifetime_that_names_no_span_is_refused_at_construction() {
    assert_eq!(
        built(configuration("https://mandate.example", "PT", "PT8H")).err(),
        Some(ConfigurationRefused::CodeLifetimeUnbounded),
        "`PT` names no span"
    );
    assert_eq!(
        built(configuration("https://mandate.example", "PT5M", "P1M")).err(),
        Some(ConfigurationRefused::SessionLifetimeUnbounded),
        "a month is not a number of seconds"
    );
    assert_eq!(
        built(configuration("https://mandate.example", "PT0S", "PT8H")).err(),
        Some(ConfigurationRefused::CodeLifetimeUnbounded),
        "a code lifetime of zero seconds expires every code at the instant it is issued"
    );
    assert!(
        built(configuration("https://mandate.example", "PT5M", "PT8H")).is_ok(),
        "the lifetimes the binary defaults to are served"
    );
}

/// RFC 8414 section 2: "The authorization server's issuer identifier ... MUST be a URL that
/// uses the `https` scheme and has no query or fragment components." A deployment that
/// publishes a metadata document naming something else names an issuer no client can validate
/// against, so the identifier is decided at construction. `http` on the loopback is admitted
/// for a deployment a developer runs on their own machine, and nowhere else.
#[test]
fn an_issuer_that_is_not_an_issuer_identifier_is_refused_at_construction() {
    for (issuer, refused) in [
        ("mandate.example", IssuerRefused::SchemeUnadmitted),
        ("http://mandate.example", IssuerRefused::SchemeUnadmitted),
        ("https://", IssuerRefused::HostMissing),
        (
            "https://mandate.example?tenant=acme",
            IssuerRefused::QueryComponent,
        ),
        (
            "https://mandate.example#tenant",
            IssuerRefused::FragmentComponent,
        ),
        (
            "https://mandate.example//",
            IssuerRefused::RepeatedTrailingSlash,
        ),
    ] {
        assert_eq!(
            built(configuration(issuer, "PT5M", "PT8H")).err(),
            Some(ConfigurationRefused::Issuer(refused)),
            "{issuer}"
        );
    }
    for admitted in [
        "https://mandate.example",
        "https://mandate.example/mandate",
        "http://127.0.0.1:8080",
        "http://localhost:8080",
        "http://[::1]:8080",
    ] {
        assert!(
            built(configuration(admitted, "PT5M", "PT8H")).is_ok(),
            "{admitted} is an issuer identifier this deployment publishes"
        );
    }
}

/// The issuer is normalised once, at construction, and both consumers read the normalised
/// value: the metadata document's `issuer` member and every endpoint built from it, and the
/// audience the federation request context names. One trailing `/` is trimmed — RFC 8414
/// section 3.1 joins the well-known path onto the identifier, so `.../` and `...` publish the
/// same document — and a second one is refused rather than guessed at.
#[test]
fn the_metadata_document_and_the_federation_audience_read_one_normalised_issuer() {
    let deployment = built(configuration("https://mandate.example/", "PT5M", "PT8H"))
        .expect("an issuer identifier with one trailing slash");
    assert_eq!(deployment.issuer(), "https://mandate.example");
    assert_eq!(
        deployment.metadata().issuer,
        deployment.issuer(),
        "the published document names the normalised identifier"
    );
    assert_eq!(
        deployment.audience(),
        Audience::new(deployment.issuer()),
        "the federation audience is the same value and not the configured text"
    );
    assert_eq!(
        deployment.metadata().jwks_uri,
        "https://mandate.example/oauth/jwks",
        "an endpoint is the normalised identifier joined with the route table's path"
    );
}

/// **Both lifetimes are bounded above as well as below** (correction round 2, F4).
///
/// The lower bound alone left the failure round 1 was written against open at the other end:
/// `--code-lifetime PT99999999H` is a well-formed duration `span_of` reads, and the expiry it
/// puts on a code is past the year 9999. `adapters::instant::at` renders the year with
/// `{year:04}` — a minimum width, not a maximum — and the STS's own reader
/// (`services/sts/src/lib.rs:312-320`, `pub(crate)`) requires a `-` at offset 4, so it refuses
/// the timestamp this deployment rendered and the handler answers `ExpiryUnbounded` — which
/// reaches the client as `server_error`, per authorization request, with exit status 0 and
/// nothing said at startup.
///
/// The boundary is stated here against RFC 3339's own last four-digit-year instant rather
/// than against the check's arithmetic: a span that puts
/// `instant::LATEST_CHECKED_REQUEST_INSTANT` at `9999-12-31T23:59:59Z` is admitted, and one
/// second more is refused.
#[test]
fn a_lifetime_whose_expiry_this_deployment_cannot_render_is_refused_at_startup() {
    for lifetime in ["PT99999999H", "P106751991167D"] {
        assert_eq!(
            built(configuration("https://mandate.example", lifetime, "PT8H")).err(),
            Some(ConfigurationRefused::CodeLifetimeUnbounded),
            "a code lifetime of {lifetime} renders an expiry no reader on this road reads"
        );
        assert_eq!(
            built(configuration("https://mandate.example", "PT5M", lifetime)).err(),
            Some(ConfigurationRefused::SessionLifetimeUnbounded),
            "a session lifetime of {lifetime}"
        );
    }
    assert!(
        built(configuration(
            "https://mandate.example",
            "PT8760H",
            "PT8760H"
        ))
        .is_ok(),
        "a year is a lifetime this deployment renders"
    );

    // 9999-12-31T23:59:59Z, the last instant RFC 3339's four-digit year names.
    let last_renderable: i64 = 253_402_300_799;
    let largest =
        last_renderable - mandate_control_plane::adapters::instant::LATEST_CHECKED_REQUEST_INSTANT;
    assert!(
        built(configuration(
            "https://mandate.example",
            &format!("PT{largest}S"),
            "PT8H"
        ))
        .is_ok(),
        "the largest span whose expiry is still renderable is admitted"
    );
    assert_eq!(
        built(configuration(
            "https://mandate.example",
            &format!("PT{}S", largest + 1),
            "PT8H"
        ))
        .err(),
        Some(ConfigurationRefused::CodeLifetimeUnbounded),
        "one second past it is not"
    );
}

// ---------------------------------------------------------------------------------------
// The principal a just-in-time login mints (`story:jit-principal-record`)
// ---------------------------------------------------------------------------------------

/// A just-in-time login leaves a `mandate.identity.Principal` for the principal it minted.
///
/// `mandate.federation.ExternalPrincipalProvisioned` is that record's declared writer
/// (`identity.yaml`'s header), and the login's accepted outcome names the `PrincipalId` the
/// provisioning minted. The identity fold must hold the record under that identity: a road
/// that carries a principal through login and token issuance with no record of it trusts a
/// principal it never wrote down.
#[test]
fn a_just_in_time_login_records_the_principal_its_event_declares() {
    let mut deployment = built(configuration("https://mandate.example", "PT5M", "PT8H"))
        .expect("a configuration this deployment serves");
    let connection_id = mandate_types::FederationConnectionId::new(uuid(0xc0));
    deployment
        .record_federation(&FederationEvent::FederationConnectionCreated {
            context: context(),
            connection_id,
            issuer: mandate_types::Issuer::new("https://idp.example"),
            client_id: mandate_types::ClientId::new("mandate-at-idp"),
            tenant_resolution: mandate_model::TenantResolutionRule {
                configured_organization: organization(),
                verified_claim_name: None,
                verified_claim_value: None,
            },
            jit_provisioning: true,
        })
        .expect("a readable federation history");
    assert!(
        deployment.federation().links().is_empty(),
        "nothing is linked before the first login"
    );

    let login = deployment
        .authenticate(&mandate_server::decode::AuthenticateFederation {
            connection_id,
            proof: CredentialProof::from_bytes(b"an idp proof".to_vec()),
        })
        .expect("a connection admitting provisioning opens the first login a session");

    let recorded = deployment.identity().principal(&login.principal_id);
    let principal = recorded.unwrap_or_else(|| {
        panic!(
            "the identity fold holds no mandate.identity.Principal for the minted principal {:?}",
            login.principal_id
        )
    });
    assert_eq!(principal.id(), &login.principal_id);
    assert_eq!(principal.kind(), mandate_types::PrincipalKind::User);
    assert_eq!(
        principal.state(),
        mandate_identity::PrincipalState::Active,
        "a provisioned principal is created active"
    );
}

//! Adversary pass 2 on `story:sts-lifetime-bounds`, at `d57dc0a`.
//!
//! Each case drives one clause of the corrected sentence `services/sts/src/registry.rs`
//! writes over `admits_profile`:
//!
//! > a profile admitted here issues a readable expiry for every request before
//! > `3000-01-01`. [...] the issuance decides that per request, and refuses as
//! > `ExpiryUnbounded` exactly the request instants after `9999-12-31T23:59:59Z` minus
//! > `max_ttl`, under this profile or under a record carrying one this handler refused.
//!
//! - [`an_admitted_profile_issues_readably_for_every_request_before_3000`]: the first clause,
//!   at a request instant the reader reads and that is before `3000-01-01`.
//! - [`a_self_contained_issuance_under_a_refused_bound_is_refused_after_9999_minus_max_ttl`]:
//!   the "exactly" clause, on the self-contained family, whose lifetime is the signer's.
//! - [`a_redemption_under_a_refused_bound_is_refused_after_9999_minus_max_ttl`]: the same
//!   clause, on the redemption, whose expiry is narrowed to the code's.

use mandate_sts::binding::{RecordedSessions, SessionBinding};
use mandate_sts::code::{
    AuthorizationCodeParts, CodeIssuance, CodeLifetime, IssueAuthorizationCode, RecordedClients,
};
use mandate_sts::issue::{
    IssueReferenceCredential, IssueSelfContainedCredential, ReferenceParts, SelfContainedParts,
    Sha256Digest, StaticSigner, issue_reference_credential, issue_self_contained_credential,
};
use mandate_sts::redemption::{
    BoundReads, RedeemAuthorizationCode, RedemptionParts, redeem_authorization_code,
};
use mandate_sts::registry::{RegisterResourceServer, register_resource_server};
use mandate_sts::store::CodeProjection;
use mandate_sts::{CountingSecrets, RequestContext, SequentialAllocator};
use mandate_token::CredentialProfile;
use mandate_token::projection::{CredentialEvent, DenialClause, Denied, Projection};
use mandate_types::{
    Audience, AuthorityScope, CorrelationId, CredentialId, CredentialKind, CredentialProof,
    DenialReason, Duration, EpochSnapshotRef, Issuer, OAuthClientId, OrganizationId, PkceChallenge,
    PkceMethod, PrincipalId, RedirectUri, ResourceServerId, RevocationGuarantee, SessionId,
    Timestamp, Transient, Uuid, VerifiedContext,
};

/// About 7 118 years: refused from `3000-01-01`; the refusal line is `2881-06-10T00:00:00Z`.
const REFUSED_BOUND: &str = "P2600000D";

fn uuid(tag: u8) -> Uuid {
    Uuid::from_bytes([tag; 16])
}

fn organization() -> OrganizationId {
    OrganizationId::new(uuid(10))
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
        correlation: CorrelationId::new("adversary-lifetime-bounds-2"),
    }
}

fn scope() -> AuthorityScope {
    AuthorityScope {
        actions: Vec::new(),
        resources: Vec::new(),
        space: None,
    }
}

fn snapshot() -> EpochSnapshotRef {
    EpochSnapshotRef::new(uuid(0x60))
}

fn profile(kind: CredentialKind, max_ttl: &str) -> CredentialProfile {
    CredentialProfile {
        name: "profile".to_owned(),
        kind,
        revocation: RevocationGuarantee::BoundedOffline,
        max_ttl: Duration::new(max_ttl),
        positive_cache_ttl: Duration::new("PT0S"),
        requires_online_authorization: false,
    }
}

fn request_at(at: &str) -> RequestContext {
    RequestContext {
        correlation: CorrelationId::new("adversary-lifetime-bounds-2"),
        at: Timestamp::new(at),
        epochs: Some(snapshot()),
    }
}

fn expiry_unbounded() -> Denied {
    Denied::new(DenialReason::Denied, DenialClause::ExpiryUnbounded)
}

fn register(profile: CredentialProfile) -> Result<(Projection, ResourceServerId), Denied> {
    register_resource_server(
        &RegisterResourceServer {
            context: context(),
            audience: Audience::new("api-a"),
            profile,
            allowed_exchange_sources: Vec::new(),
        },
        &Projection::default(),
        &mut SequentialAllocator::new(),
    )
    .map(|outcome| {
        (
            Projection::fold(std::slice::from_ref(&outcome.event)).expect("one creation"),
            outcome.resource_server_id,
        )
    })
}

/// A record carrying `profile`, as `adversary_lifetime_bounds_1.rs` builds it.
fn recorded(profile: CredentialProfile) -> (Projection, ResourceServerId) {
    let id = ResourceServerId::new(uuid(0x40));
    let log = vec![CredentialEvent::ResourceServerRegistered {
        context: context(),
        id,
        audience: Audience::new("api-a"),
        credential_profile: profile,
        allowed_exchange_sources: Vec::new(),
    }];
    (Projection::fold(&log).expect("one creation"), id)
}

/// registry.rs: "a profile admitted here issues a readable expiry for every request before
/// `3000-01-01`". `0000-01-01T00:00:00+01:00` is a request instant `instant::seconds_of`
/// reads, and it is before `3000-01-01`; the suite's own
/// `an_issuance_whose_expiry_would_fall_before_the_year_zero_is_refused` shows it refused.
#[test]
fn an_admitted_profile_issues_readably_for_every_request_before_3000() {
    let (servers, target) =
        register(profile(CredentialKind::Reference, "PT1S")).expect("PT1S is admitted");
    let issued = issue_reference_credential(
        &IssueReferenceCredential {
            context: context(),
            target,
            requested_scope: scope(),
        },
        &request_at("0000-01-01T00:00:00+01:00"),
        &servers,
        ReferenceParts {
            digest: &Sha256Digest,
            secrets: &mut CountingSecrets::new(),
            allocator: &mut SequentialAllocator::new(),
        },
    );
    assert!(
        issued.is_ok(),
        "registry.rs: an admitted profile `issues a readable expiry for every request before \
         3000-01-01`; got {:?}",
        issued.map(|outcome| outcome.descriptor.expires_at)
    );
}

/// registry.rs: the issuance "refuses as `ExpiryUnbounded` exactly the request instants
/// after `9999-12-31T23:59:59Z` minus `max_ttl`, [...] under a record carrying one this
/// handler refused". The self-contained family's lifetime is the signer's, not `max_ttl`.
#[test]
fn a_self_contained_issuance_under_a_refused_bound_is_refused_after_9999_minus_max_ttl() {
    assert!(
        register(profile(CredentialKind::SelfContained, REFUSED_BOUND)).is_err(),
        "premise: the registration handler refuses this bound"
    );
    let (servers, target) = recorded(profile(CredentialKind::SelfContained, REFUSED_BOUND));
    let signer = StaticSigner::new("kid-one", 86_400);
    let issued = issue_self_contained_credential(
        &IssueSelfContainedCredential {
            context: context(),
            target,
            requested_scope: scope(),
        },
        // One second past the line the registry doc draws for this bound.
        &request_at("2881-06-10T00:00:00Z"),
        &servers,
        SelfContainedParts {
            digest: &Sha256Digest,
            allocator: &mut SequentialAllocator::new(),
            signer: &signer,
            issuer: &Issuer::new("https://sts.example"),
        },
    );
    assert_eq!(
        issued.map(|outcome| outcome.descriptor.expires_at),
        Err(expiry_unbounded()),
        "registry.rs: refused `exactly the request instants after 9999-12-31T23:59:59Z minus \
         max_ttl`"
    );
}

/// The same clause, on the third issuing site: the redemption narrows the expiry to the
/// code's own, which the reader has already read.
#[test]
fn a_redemption_under_a_refused_bound_is_refused_after_9999_minus_max_ttl() {
    const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    const REDIRECT: &str = "https://client.example/callback";
    let client = OAuthClientId::new(uuid(0x0c));
    let session = SessionId::new(uuid(0x5e));
    // Far past the line the registry doc draws for this bound (2881-06-10T00:00:00Z).
    let late = request_at("9000-01-01T00:00:00Z");
    let (servers, target) = recorded(profile(CredentialKind::Reference, REFUSED_BOUND));
    let clients = RecordedClients::new()
        .enabled(client, organization())
        .redirect(client, RedirectUri::new(REDIRECT));
    let sessions = RecordedSessions::new()
        .session(SessionBinding {
            id: session,
            subject: PrincipalId::new(uuid(0x51)),
            organization: organization(),
            epochs: Some(snapshot()),
            expires_at: Timestamp::new("9000-01-01T12:00:00Z"),
            revoked: false,
        })
        .current(snapshot());

    let code = CodeIssuance::new(CodeLifetime::new(Duration::new("PT5M")))
        .issue(
            &IssueAuthorizationCode {
                context: context(),
                client_id: client,
                session_id: session,
                target,
                requested_scope: scope(),
                challenge: PkceChallenge::new(CHALLENGE),
                method: PkceMethod::S256,
                redirect_uri: RedirectUri::new(REDIRECT),
                expires_at: Timestamp::new("9000-01-01T00:05:00Z"),
            },
            &late,
            &servers,
            &clients,
            AuthorizationCodeParts {
                digest: &Sha256Digest,
                secrets: &mut CountingSecrets::new(),
                allocator: &mut SequentialAllocator::new(),
            },
        )
        .expect("premise: a code is issued against the record");
    let codes = CodeProjection::fold(std::slice::from_ref(&code.event)).expect("one creation");

    let redeemed = redeem_authorization_code(
        &RedeemAuthorizationCode {
            code_id: code.code_id,
            client_id: client,
            code: CredentialProof::from_bytes(code.code.expose_material().to_vec()),
            pkce_verifier: CredentialProof::from_bytes(VERIFIER.as_bytes().to_vec()),
            redirect_uri: RedirectUri::new(REDIRECT),
        },
        &late,
        &codes,
        BoundReads {
            servers: &servers,
            clients: &clients,
            sessions: &sessions,
        },
        RedemptionParts {
            digest: &Sha256Digest,
            secrets: &mut CountingSecrets::new(),
            allocator: &mut SequentialAllocator::new(),
        },
    );
    assert_eq!(
        redeemed.map(|outcome| outcome.descriptor.expires_at),
        Err(expiry_unbounded()),
        "registry.rs: refused `exactly the request instants after 9999-12-31T23:59:59Z minus \
         max_ttl`"
    );
}

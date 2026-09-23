//! Adversary pass 2 on `story:sts-lifetime-bounds`, at `d57dc0a`; rewritten in I3 correction
//! round 2 (coordinator ruling on G1 and G2) to assert the sentence as corrected.
//!
//! The pass-2 cases asserted the wording `services/sts/src/registry.rs` carried at
//! `d57dc0a` — "a profile admitted here issues a readable expiry for every request before
//! `3000-01-01`" and "refuses as `ExpiryUnbounded` exactly the request instants after
//! `9999-12-31T23:59:59Z` minus `max_ttl`" — and all three were red against it, because the
//! wording was false. The corrected sentence is: under an admitted profile no path refuses
//! for want of a readable expiry from `0000-01-01T00:00:00Z` through `3000-01-01T00:00:00Z`
//! (UTC), and each path refuses exactly when the request instant plus the lifetime *that
//! path* issues leaves `0000-01-01T00:00:00Z` to `9999-12-31T23:59:59Z`. Each case keeps its
//! pass-2 input and pins the line on its own path to the second.
//!
//! - [`an_admitted_profile_is_refused_where_its_expiry_would_fall_before_the_year_zero`] decides the
//!   lower end, which a request instant read with its offset can reach.
//! - [`a_self_contained_issuance_under_a_refused_bound_is_refused_after_9999_minus_the_signer_ttl`] decides
//!   the upper end on the self-contained family, whose lifetime is the signer's.
//! - [`a_redemption_under_a_refused_bound_issues_the_codes_own_expiry`] decides the redemption,
//!   whose expiry is narrowed to the code's and never reaches the upper end.

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

/// A reference issuance under `target` at `at`: the expiry, and the secrets minted.
fn issue_reference(
    servers: &Projection,
    target: ResourceServerId,
    at: &str,
) -> (Result<Timestamp, Denied>, u32) {
    let mut secrets = CountingSecrets::new();
    let issued = issue_reference_credential(
        &IssueReferenceCredential {
            context: context(),
            target,
            requested_scope: scope(),
        },
        &request_at(at),
        servers,
        ReferenceParts {
            digest: &Sha256Digest,
            secrets: &mut secrets,
            allocator: &mut SequentialAllocator::new(),
        },
    );
    (
        issued.map(|outcome| outcome.descriptor.expires_at),
        secrets.minted(),
    )
}

/// A self-contained issuance under `target` at `at`, signed for `ttl_seconds`.
fn issue_self_contained(
    servers: &Projection,
    target: ResourceServerId,
    ttl_seconds: u64,
    at: &str,
) -> Result<Timestamp, Denied> {
    let signer = StaticSigner::new("kid-one", ttl_seconds);
    issue_self_contained_credential(
        &IssueSelfContainedCredential {
            context: context(),
            target,
            requested_scope: scope(),
        },
        &request_at(at),
        servers,
        SelfContainedParts {
            digest: &Sha256Digest,
            allocator: &mut SequentialAllocator::new(),
            signer: &signer,
            issuer: &Issuer::new("https://sts.example"),
        },
    )
    .map(|outcome| outcome.descriptor.expires_at)
}

/// registry.rs, as corrected: the admitted range starts at `0000-01-01T00:00:00Z` in UTC, and
/// a path refuses exactly when request instant plus lifetime falls before it.
/// `0000-01-01T00:00:00+01:00` is a request instant `instant::seconds_of` reads, an hour
/// before the year 0 begins in UTC, so under an admitted `PT1S` it is refused. The line for
/// `PT1S` is one second before `0000-01-01T00:00:00Z`: a request there issues exactly
/// `0000-01-01T00:00:00Z`, and one second earlier is refused.
#[test]
fn an_admitted_profile_is_refused_where_its_expiry_would_fall_before_the_year_zero() {
    let (servers, target) =
        register(profile(CredentialKind::Reference, "PT1S")).expect("PT1S is admitted");

    assert_eq!(
        issue_reference(&servers, target, "0000-01-01T00:00:00+01:00"),
        (Err(expiry_unbounded()), 0),
        "the expiry is -001-12-31T23:00:01Z: refused, nothing minted"
    );
    // -1 s and -2 s from 0000-01-01T00:00:00Z, spelled with a one-minute offset.
    assert_eq!(
        issue_reference(&servers, target, "0000-01-01T00:00:59+00:01"),
        (Ok(Timestamp::new("0000-01-01T00:00:00Z")), 1),
        "the last request instant whose PT1S expiry is readable issues"
    );
    assert_eq!(
        issue_reference(&servers, target, "0000-01-01T00:00:58+00:01"),
        (Err(expiry_unbounded()), 0),
        "one second earlier the expiry is -001-12-31T23:59:59Z: refused, nothing minted"
    );
    assert_eq!(
        issue_reference(&servers, target, "0000-01-01T00:00:00Z"),
        (Ok(Timestamp::new("0000-01-01T00:00:01Z")), 1),
        "the first request instant of the admitted range issues"
    );
}

/// registry.rs, as corrected: the self-contained lifetime is the signer's TTL, not
/// `max_ttl`. Under the refused `P2600000D` record and a one-day signer, the request at
/// `2881-06-10T00:00:00Z` — past the line `max_ttl` would draw — issues a day later, and
/// the line is `9999-12-31T23:59:59Z` minus one day.
#[test]
fn a_self_contained_issuance_under_a_refused_bound_is_refused_after_9999_minus_the_signer_ttl() {
    assert_eq!(
        register(profile(CredentialKind::SelfContained, REFUSED_BOUND)).map(|_| ()),
        Err(Denied::new(
            DenialReason::Denied,
            DenialClause::ProfileUnadmitted
        )),
        "premise: the registration handler refuses this bound"
    );
    let (servers, target) = recorded(profile(CredentialKind::SelfContained, REFUSED_BOUND));

    assert_eq!(
        issue_self_contained(&servers, target, 86_400, "2881-06-10T00:00:00Z"),
        Ok(Timestamp::new("2881-06-11T00:00:00Z")),
        "the lifetime issued is the signer's day, so the max_ttl line does not apply"
    );
    assert_eq!(
        issue_self_contained(&servers, target, 86_400, "9999-12-30T23:59:59Z"),
        Ok(Timestamp::new("9999-12-31T23:59:59Z")),
        "the last request instant whose one-day expiry is readable issues"
    );
    assert_eq!(
        issue_self_contained(&servers, target, 86_400, "9999-12-31T00:00:00Z"),
        Err(expiry_unbounded()),
        "one second later the expiry is 10000-01-01T00:00:00Z: refused"
    );
}

/// registry.rs, as corrected: the redemption's lifetime is the earlier of `max_ttl` and the
/// code's own `expires_at`, and the code's expiry is one the reader has read. Under the
/// refused `P2600000D` record, a redemption at `9000-01-01T00:00:00Z` — far past the line
/// `max_ttl` would draw — issues exactly the code's `9000-01-01T00:05:00Z`.
#[test]
fn a_redemption_under_a_refused_bound_issues_the_codes_own_expiry() {
    const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    const REDIRECT: &str = "https://client.example/callback";
    let client = OAuthClientId::new(uuid(0x0c));
    let session = SessionId::new(uuid(0x5e));
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

    let mut secrets = CountingSecrets::new();
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
            secrets: &mut secrets,
            allocator: &mut SequentialAllocator::new(),
        },
    );
    assert_eq!(
        redeemed.map(|outcome| outcome.descriptor.expires_at),
        Ok(Timestamp::new("9000-01-01T00:05:00Z")),
        "the narrowed expiry is the code's own, whatever the refused max_ttl"
    );
    assert_eq!(secrets.minted(), 1, "the redemption minted its one secret");
}

//! `IssueReferenceCredential` and `IssueSelfContainedCredential`.
//!
//! Both families answer the same questions — is the target registered, enabled and the
//! caller's own, does its profile admit this family, and can the expiry be bounded — and
//! differ in what the holder is handed: a secret this deployment minted and can resolve, or
//! a token a verifier can check without asking. Neither leaves the material behind: the
//! record holds the non-reversible verifier and nothing else, which is
//! `tests/security/cases.json`'s `reference-persistence`.

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair};
use mandate_sts::issue::{
    IssuanceSigner, IssueReferenceCredential, IssueSelfContainedCredential, ReferenceParts,
    SelfContainedParts, Sha256Digest, StaticSigner, issue_reference_credential,
    issue_self_contained_credential,
};
use mandate_sts::registry::{RegisterResourceServer, register_resource_server};
use mandate_sts::{CountingSecrets, RequestContext, SequentialAllocator};
use mandate_token::CredentialProfile;
use mandate_token::projection::{
    AccessCredentialState, CredentialEvent, DenialClause, Projection, RefusedOutcome,
};
use mandate_token::signing_real::{
    AllowedAlgorithms, Clock, RealSigner, SignedCredential, SigningError, SigningKeyMaterial,
    StandardClaims,
};
use mandate_token::verifier::{CredentialDomain, presents, presents_in, verifier_for};
use mandate_types::value::decode_base64;
use mandate_types::{
    Audience, AuthorityScope, CorrelationId, CredentialId, CredentialKind, CredentialProof,
    DenialReason, Duration, Issuer, OrganizationId, PrincipalId, ResourceServerId,
    RevocationGuarantee, SigningAlgorithm, Timestamp, Transient, Uuid, VerifiedContext,
};
use serde_json::Value;

fn uuid(tag: u8) -> Uuid {
    Uuid::from_bytes([tag; 16])
}

fn organization(tag: u8) -> OrganizationId {
    OrganizationId::new(uuid(tag))
}

fn context(organization_id: OrganizationId) -> VerifiedContext {
    VerifiedContext {
        subject: PrincipalId::new(uuid(0x51)),
        actor: Some(PrincipalId::new(uuid(0x52))),
        organization: organization_id,
        audience: Audience::new("mandate"),
        credential: CredentialId::new(uuid(0xcd)),
        delegation: None,
        execution: None,
        correlation: CorrelationId::new("issue"),
    }
}

fn request() -> RequestContext {
    RequestContext {
        correlation: CorrelationId::new("issue"),
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

fn self_contained_profile() -> CredentialProfile {
    CredentialProfile {
        name: "self-contained".to_owned(),
        kind: CredentialKind::SelfContained,
        revocation: RevocationGuarantee::BoundedOffline,
        max_ttl: Duration::new("PT15M"),
        positive_cache_ttl: Duration::new("PT0S"),
        requires_online_authorization: false,
    }
}

/// One registered target, folded, with the identity the registry minted for it.
fn target(
    organization_id: OrganizationId,
    audience: &str,
    profile: CredentialProfile,
) -> (Projection, ResourceServerId) {
    let (held, id, _) = registered_target(organization_id, audience, profile);
    (held, id)
}

/// The same, keeping the registration event: a case that folds an issuance needs the
/// registration in the same log, because the fold reads the guarantee off it.
fn registered_target(
    organization_id: OrganizationId,
    audience: &str,
    profile: CredentialProfile,
) -> (Projection, ResourceServerId, CredentialEvent) {
    let mut allocator = SequentialAllocator::new();
    let outcome = register_resource_server(
        &RegisterResourceServer {
            context: context(organization_id),
            audience: Audience::new(audience),
            profile,
            allowed_exchange_sources: Vec::new(),
        },
        &Projection::default(),
        &mut allocator,
    )
    .expect("a free audience in the caller's own organization");
    (
        Projection::fold(std::slice::from_ref(&outcome.event)).expect("one creation"),
        outcome.resource_server_id,
        outcome.event,
    )
}

fn issuer() -> Issuer {
    Issuer::new("https://sts.example")
}

#[test]
fn a_reference_issuance_returns_the_secret_once_and_records_only_the_verifier() {
    let (held, id, registration) =
        registered_target(organization(10), "api-a", reference_profile());
    let mut secrets = CountingSecrets::new();
    let mut allocator = SequentialAllocator::new();
    let input = IssueReferenceCredential {
        context: context(organization(10)),
        target: id,
        requested_scope: scope(),
    };

    let outcome = issue_reference_credential(
        &input,
        &request(),
        &held,
        ReferenceParts {
            digest: &Sha256Digest,
            secrets: &mut secrets,
            allocator: &mut allocator,
        },
    )
    .expect("a registered, enabled target of the caller's organization");

    assert_eq!(secrets.minted(), 1, "one issuance mints one secret");
    // What the holder receives resolves against what the record keeps, and the record keeps
    // nothing else: the digest is one-way and the event carries no material.
    let recorded = match &outcome.event {
        CredentialEvent::CredentialReferenceIssued {
            reference_verifier, ..
        } => reference_verifier.clone().expect("the declared verifier"),
        other => panic!("the accepted outcome emits the declared event, not {other:?}"),
    };
    assert_eq!(recorded, verifier_for(&Sha256Digest, &outcome.credential));
    assert!(presents(
        &Sha256Digest,
        &recorded,
        &CredentialProof::from_bytes(outcome.credential.expose_material().to_vec())
    ));

    let document = serde_json::to_string(&outcome.event).expect("the event encodes as JSON");
    let material = String::from_utf8(outcome.credential.expose_material().to_vec())
        .expect("this double mints text");
    assert!(
        !document.contains(&material),
        "the emitted event carries the secret: {document}"
    );

    let record = Projection::fold(&[registration, outcome.event])
        .expect("a registration and one issuance")
        .access_credential(&outcome.credential_id)
        .expect("the credential the event created");
    assert_eq!(record.state, AccessCredentialState::Active);
    assert_eq!(record.reference_verifier, Some(recorded));
    assert_eq!(
        record.target, id,
        "the record keeps the registration it was issued under"
    );
    assert_eq!(record.issuing_profile, reference_profile());
}

#[test]
fn the_descriptor_is_the_callers_context_against_the_registered_targets_audience() {
    let (held, id) = target(organization(10), "api-a", reference_profile());
    let mut secrets = CountingSecrets::new();
    let mut allocator = SequentialAllocator::new();

    let outcome = issue_reference_credential(
        &IssueReferenceCredential {
            context: context(organization(10)),
            target: id,
            requested_scope: scope(),
        },
        &request(),
        &held,
        ReferenceParts {
            digest: &Sha256Digest,
            secrets: &mut secrets,
            allocator: &mut allocator,
        },
    )
    .expect("a registered, enabled target of the caller's organization");

    let descriptor = outcome.descriptor;
    assert_eq!(descriptor.kind, CredentialKind::Reference);
    assert_eq!(descriptor.subject, PrincipalId::new(uuid(0x51)));
    assert_eq!(descriptor.actor, Some(PrincipalId::new(uuid(0x52))));
    assert_eq!(descriptor.organization, organization(10));
    assert_eq!(
        descriptor.audience,
        Audience::new("api-a"),
        "the audience is the registration's, never the caller's own context audience"
    );
    assert_eq!(descriptor.scope, scope());
    // The profile's `max_ttl` is `PT1H` and the request is served at midnight.
    assert_eq!(
        descriptor.expires_at,
        Timestamp::new("2026-09-19T01:00:00Z"),
        "the expiry is bounded by the profile the target is registered under"
    );
}

#[test]
fn two_issuances_are_two_credentials_with_two_verifiers() {
    let (held, id) = target(organization(10), "api-a", reference_profile());
    let mut secrets = CountingSecrets::new();
    let mut allocator = SequentialAllocator::new();
    let input = IssueReferenceCredential {
        context: context(organization(10)),
        target: id,
        requested_scope: scope(),
    };

    let first = issue_reference_credential(
        &input,
        &request(),
        &held,
        ReferenceParts {
            digest: &Sha256Digest,
            secrets: &mut secrets,
            allocator: &mut allocator,
        },
    )
    .expect("the first issuance");
    let second = issue_reference_credential(
        &input,
        &request(),
        &held,
        ReferenceParts {
            digest: &Sha256Digest,
            secrets: &mut secrets,
            allocator: &mut allocator,
        },
    )
    .expect("the second issuance");

    assert_ne!(first.credential_id, second.credential_id);
    assert_ne!(
        verifier_for(&Sha256Digest, &first.credential),
        verifier_for(&Sha256Digest, &second.credential)
    );
}

#[test]
fn an_unregistered_disabled_or_foreign_target_is_refused() {
    let (held, id) = target(organization(10), "api-a", reference_profile());
    let mut secrets = CountingSecrets::new();
    let mut allocator = SequentialAllocator::new();

    let unregistered = issue_reference_credential(
        &IssueReferenceCredential {
            context: context(organization(10)),
            target: ResourceServerId::new(uuid(0x99)),
            requested_scope: scope(),
        },
        &request(),
        &held,
        ReferenceParts {
            digest: &Sha256Digest,
            secrets: &mut secrets,
            allocator: &mut allocator,
        },
    )
    .expect_err("no event registered that target");
    assert_eq!(unregistered.clause, DenialClause::TargetUnregistered);
    assert_eq!(unregistered.outcome, RefusedOutcome::Denied);

    let foreign = issue_reference_credential(
        &IssueReferenceCredential {
            context: context(organization(11)),
            target: id,
            requested_scope: scope(),
        },
        &request(),
        &held,
        ReferenceParts {
            digest: &Sha256Digest,
            secrets: &mut secrets,
            allocator: &mut allocator,
        },
    )
    .expect_err("the target is another organization's");
    assert_eq!(foreign.reason, DenialReason::TenantMismatch);
    assert_eq!(foreign.clause, DenialClause::OrganizationMismatch);

    let disabled = Projection::fold(&[
        CredentialEvent::ResourceServerRegistered {
            context: context(organization(10)),
            id,
            audience: Audience::new("api-a"),
            credential_profile: reference_profile(),
            allowed_exchange_sources: Vec::new(),
        },
        CredentialEvent::ResourceServerDisabled {
            context: context(organization(10)),
            id,
        },
    ])
    .expect("a creation and its move");
    let denied = issue_reference_credential(
        &IssueReferenceCredential {
            context: context(organization(10)),
            target: id,
            requested_scope: scope(),
        },
        &request(),
        &disabled,
        ReferenceParts {
            digest: &Sha256Digest,
            secrets: &mut secrets,
            allocator: &mut allocator,
        },
    )
    .expect_err("the target is in its terminal state");
    assert_eq!(denied.clause, DenialClause::TargetDisabled);

    assert_eq!(
        secrets.minted(),
        0,
        "a refusal mints nothing: fail closed, no credential on refusal"
    );
}

/// The two families are not interchangeable: the registration names which one its holders
/// get, and a command that asked for the other is refused rather than served the profile's.
#[test]
fn each_family_is_refused_against_the_other_familys_profile() {
    let (reference, reference_id) = target(organization(10), "api-a", reference_profile());
    let (signed, signed_id) = target(organization(10), "api-b", self_contained_profile());
    let mut secrets = CountingSecrets::new();
    let mut allocator = SequentialAllocator::new();
    let signer = StaticSigner::new("kid-one", 900);

    let denied = issue_reference_credential(
        &IssueReferenceCredential {
            context: context(organization(10)),
            target: signed_id,
            requested_scope: scope(),
        },
        &request(),
        &signed,
        ReferenceParts {
            digest: &Sha256Digest,
            secrets: &mut secrets,
            allocator: &mut allocator,
        },
    )
    .expect_err("the registration issues self-contained credentials");
    assert_eq!(denied.clause, DenialClause::ProfileUnadmitted);

    let denied = issue_self_contained_credential(
        &IssueSelfContainedCredential {
            context: context(organization(10)),
            target: reference_id,
            requested_scope: scope(),
        },
        &request(),
        &reference,
        SelfContainedParts {
            digest: &Sha256Digest,
            allocator: &mut allocator,
            signer: &signer,
            issuer: &issuer(),
        },
    )
    .expect_err("the registration issues reference credentials");
    assert_eq!(denied.clause, DenialClause::ProfileUnadmitted);
}

#[test]
fn a_self_contained_issuance_returns_the_signed_token_and_names_the_key_it_was_signed_under() {
    let (held, id) = target(organization(10), "api-b", self_contained_profile());
    let mut allocator = SequentialAllocator::new();
    let signer = StaticSigner::new("kid-one", 900);

    let outcome = issue_self_contained_credential(
        &IssueSelfContainedCredential {
            context: context(organization(10)),
            target: id,
            requested_scope: scope(),
        },
        &request(),
        &held,
        SelfContainedParts {
            digest: &Sha256Digest,
            allocator: &mut allocator,
            signer: &signer,
            issuer: &issuer(),
        },
    )
    .expect("a registered, enabled target of the caller's organization");

    assert_eq!(outcome.kid.as_deref(), Some("kid-one"));
    assert_eq!(outcome.descriptor.kind, CredentialKind::SelfContained);
    // The signer's TTL is 900 seconds and the request is served at midnight.
    assert_eq!(
        outcome.descriptor.expires_at,
        Timestamp::new("2026-09-19T00:15:00Z")
    );
    let token = String::from_utf8(outcome.credential.expose_material().to_vec())
        .expect("a compact JWS is text");
    assert!(token.contains("kid-one"), "the token was signed: {token}");

    // The record resolves a presented token the same way it resolves a presented secret,
    // which is what makes an introspection of this family answerable at all.
    let recorded = match &outcome.event {
        CredentialEvent::CredentialSelfContainedIssued {
            reference_verifier, ..
        } => reference_verifier.clone().expect("the declared verifier"),
        other => panic!("the accepted outcome emits the declared event, not {other:?}"),
    };
    assert!(presents_in(
        &Sha256Digest,
        CredentialDomain::SelfContainedToken,
        &recorded,
        &CredentialProof::from_bytes(outcome.credential.expose_material().to_vec())
    ));
    // And not in the reference family's domain: the two spaces are disjoint, so a token
    // presented where a secret is expected resolves to nothing rather than to a record.
    assert!(!presents(
        &Sha256Digest,
        &recorded,
        &CredentialProof::from_bytes(outcome.credential.expose_material().to_vec())
    ));
    assert!(
        !serde_json::to_string(&outcome.event)
            .expect("the event encodes as JSON")
            .contains(&token),
        "the emitted event carries the token"
    );
}

/// `profile-offline-bound`: "validity cannot exceed documented TTL/skew bound". The signer's
/// own TTL is what a verifier enforces offline, so a signer configured beyond the profile's
/// `max_ttl` would issue a credential the profile does not describe.
#[test]
fn a_signer_whose_ttl_exceeds_the_profiles_bound_is_refused() {
    let (held, id) = target(organization(10), "api-b", self_contained_profile());
    let mut allocator = SequentialAllocator::new();
    let input = IssueSelfContainedCredential {
        context: context(organization(10)),
        target: id,
        requested_scope: scope(),
    };

    // `PT15M` is the profile's bound.
    let inside = StaticSigner::new("kid-one", 900);
    assert!(
        issue_self_contained_credential(
            &input,
            &request(),
            &held,
            SelfContainedParts {
                digest: &Sha256Digest,
                allocator: &mut allocator,
                signer: &inside,
                issuer: &issuer(),
            },
        )
        .is_ok()
    );

    let beyond = StaticSigner::new("kid-one", 901);
    let denied = issue_self_contained_credential(
        &input,
        &request(),
        &held,
        SelfContainedParts {
            digest: &Sha256Digest,
            allocator: &mut allocator,
            signer: &beyond,
            issuer: &issuer(),
        },
    )
    .expect_err("the signer would outlive the profile's bound");
    assert_eq!(denied.clause, DenialClause::ExpiryUnbounded);
    assert_eq!(denied.outcome, RefusedOutcome::Denied);
}

#[test]
fn a_signer_that_refuses_is_a_denial_and_no_credential() {
    let (held, id) = target(organization(10), "api-b", self_contained_profile());
    let mut allocator = SequentialAllocator::new();
    let signer = RefusingSigner;

    let denied = issue_self_contained_credential(
        &IssueSelfContainedCredential {
            context: context(organization(10)),
            target: id,
            requested_scope: scope(),
        },
        &request(),
        &held,
        SelfContainedParts {
            digest: &Sha256Digest,
            allocator: &mut allocator,
            signer: &signer,
            issuer: &issuer(),
        },
    )
    .expect_err("the signer has no key to sign under");

    assert_eq!(denied.clause, DenialClause::SigningRefused);
    assert_eq!(denied.outcome, RefusedOutcome::Denied);
}

/// A signer with nothing to sign under, which is [`SigningError::NoActiveKey`]'s own
/// meaning: every key has been revoked.
struct RefusingSigner;

impl IssuanceSigner for RefusingSigner {
    fn sign_credential(
        &self,
        _claims: &mandate_token::CredentialDescriptor,
        _standard: &StandardClaims,
    ) -> Result<SignedCredential, SigningError> {
        Err(SigningError::NoActiveKey)
    }

    fn ttl_seconds(&self) -> u64 {
        900
    }
}

#[test]
fn a_request_instant_that_names_no_instant_cannot_bound_an_expiry() {
    let (held, id) = target(organization(10), "api-a", reference_profile());
    let mut secrets = CountingSecrets::new();
    let mut allocator = SequentialAllocator::new();
    let undated = RequestContext {
        at: Timestamp::new("whenever"),
        ..request()
    };

    let denied = issue_reference_credential(
        &IssueReferenceCredential {
            context: context(organization(10)),
            target: id,
            requested_scope: scope(),
        },
        &undated,
        &held,
        ReferenceParts {
            digest: &Sha256Digest,
            secrets: &mut secrets,
            allocator: &mut allocator,
        },
    )
    .expect_err("a reader that cannot be dated cannot bound an expiry");

    assert_eq!(denied.clause, DenialClause::ExpiryUnbounded);
    assert_eq!(secrets.minted(), 0);
}

/// The digest this deployment supplies is SHA-256, and what it returns is a function of the
/// material and nothing else — the property the record depends on, stated where a change to
/// the rendering would be seen.
#[test]
fn the_deployments_digest_is_sha256_rendered_hexadecimal() {
    use mandate_token::verifier::CredentialDigest;

    // The published SHA-256 of the empty input.
    assert_eq!(
        Sha256Digest.digest(b"").as_str(),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        Sha256Digest.digest(b"abc").as_str(),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

// --- the deployment's real signer, end to end ---------------------------------------------

/// A clock pinned to one instant, so the claims a case reads are the claims it can name.
#[derive(Debug, Clone, Copy)]
struct FixedClock(u64);

impl Clock for FixedClock {
    fn now_unix(&self) -> u64 {
        self.0
    }
}

/// The instant the case below signs at: 2026-09-19T00:00:00Z, the same one `request()` names.
///
/// One clock for the signer and the request is the deployment's obligation, and the case is
/// what it looks like when it is kept: [`rendered`] turns the `exp` the signer wrote back
/// into the declared form and it is the `expires_at` the descriptor carries, to the second.
/// A literal that was not this instant would fail there rather than pass quietly.
const SIGNED_AT: u64 = 1_789_776_000;

/// Seconds from the Unix epoch as the contract's `date-time`, in UTC.
///
/// The one reading of a JWT numeric date this case needs, so that the two sides of the skew
/// question — the signer's `exp` and the descriptor's `expires_at` — are compared as
/// instants rather than trusted to agree.
fn rendered(seconds: u64) -> Timestamp {
    let days = i64::try_from(seconds / 86_400).expect("an instant inside the era");
    let rest = seconds % 86_400;
    let shifted = days + 719_468;
    let era = shifted / 146_097;
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    };
    let year = if month <= 2 { year + 1 } else { year };
    Timestamp::new(format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rest / 3600,
        (rest % 3600) / 60,
        rest % 60
    ))
}

/// A P-256 private key, PKCS#8 v1 DER, generated now and never written down.
///
/// The shape `crates/mandate-token/tests/signing_real.rs` uses, for the same reason: "no
/// production private key appears in source or config"
/// (`docs/architecture/runtime-decisions.md` §9). Nothing in this repository holds key
/// material; this exists for the length of the process.
fn ec_pkcs8_der() -> Vec<u8> {
    EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new())
        .expect("P-256 generation")
        .as_ref()
        .to_vec()
}

/// One segment of a compact JWS, as JSON.
///
/// `mandate-sts` has no JWT library — `jsonwebtoken` is not in its dependency ceiling — so
/// the case reads the token the way anything without one would: base64url to base64, decode,
/// parse. It checks no signature: that round trip is
/// `crates/mandate-token/tests/signing_real.rs`, which verifies against the published JWK.
/// What is decided here is what *this* crate put in the claims.
fn segment(token: &str, index: usize) -> Value {
    let part = token
        .split('.')
        .nth(index)
        .unwrap_or_else(|| panic!("a compact JWS has a segment {index}"));
    let mut padded: String = part.replace('-', "+").replace('_', "/");
    while !padded.len().is_multiple_of(4) {
        padded.push('=');
    }
    let decoded = decode_base64(&padded).expect("a JWS segment is base64url");
    serde_json::from_slice(&decoded).expect("a JWS segment is JSON")
}

/// **The deployment's own signer, end to end.**
///
/// `RealSigner` over a key generated at test time is the [`IssuanceSigner`] — through the
/// blanket implementation `src/issue.rs` declares, so what is exercised is the path a
/// deployment takes and not a wrapper written for a case. The credential it returns is a
/// compact JWS whose claims are the standard seven plus the descriptor, the audience is the
/// registered target's, and the lifetime is inside the profile's bound.
#[test]
fn the_real_signer_issues_a_self_contained_credential_whose_claims_are_the_declared_ones() {
    let (held, id) = target(organization(10), "api-b", self_contained_profile());
    let mut allocator = SequentialAllocator::new();
    let material = SigningKeyMaterial::from_der(
        "kid-es256",
        &SigningAlgorithm::new("ES256"),
        &ec_pkcs8_der(),
    )
    .expect("a P-256 key the deployment generated");
    let signer = RealSigner::new(
        AllowedAlgorithms::new(&[SigningAlgorithm::new("ES256")]).expect("an allowlist"),
        material,
        FixedClock(SIGNED_AT),
        // The profile's `max_ttl` is `PT15M`; the overlap must be at least the TTL.
        900,
        3_600,
    )
    .expect("an admitted algorithm and an overlap no shorter than the TTL");

    let outcome = issue_self_contained_credential(
        &IssueSelfContainedCredential {
            context: context(organization(10)),
            target: id,
            requested_scope: scope(),
        },
        &request(),
        &held,
        SelfContainedParts {
            digest: &Sha256Digest,
            allocator: &mut allocator,
            signer: &signer,
            issuer: &issuer(),
        },
    )
    .expect("a registered, enabled target of the caller's organization");

    let token = String::from_utf8(outcome.credential.expose_material().to_vec())
        .expect("a compact JWS is text");
    assert_eq!(
        token.split('.').count(),
        3,
        "a compact JWS has three segments"
    );

    // The header names the key the signer published it under, which is the `kid` the
    // outcome carries for the composition to bind to its `mandate.credential.SigningKey`.
    let header = segment(&token, 0);
    assert_eq!(header["kid"], "kid-es256");
    assert_eq!(header["alg"], "ES256");
    assert_eq!(outcome.kid.as_deref(), Some("kid-es256"));

    // The seven claims the signer owns outright, each with the value this issuance decided.
    let claims = segment(&token, 1);
    assert_eq!(claims["iss"], issuer().as_str());
    assert_eq!(claims["sub"], PrincipalId::new(uuid(0x51)).to_string());
    assert_eq!(
        claims["aud"], "api-b",
        "the audience is the registered target's, never the caller's own context audience"
    );
    assert_eq!(
        claims["jti"],
        outcome.credential_id.to_string(),
        "the credential's own identity, so two credentials over one descriptor are two tokens"
    );
    assert_eq!(claims["iat"], SIGNED_AT);
    assert_eq!(claims["nbf"], SIGNED_AT);
    assert_eq!(claims["exp"], SIGNED_AT + 900);
    for standard in ["iss", "sub", "aud", "exp", "nbf", "iat", "jti"] {
        assert!(
            claims.get(standard).is_some(),
            "the token carries no `{standard}`"
        );
    }

    // The profile's bound, on both readings: the `exp` an offline verifier reads and the
    // `expires_at` the descriptor publishes are one instant, and it is inside `PT15M`.
    assert_eq!(
        outcome.descriptor.expires_at,
        Timestamp::new("2026-09-19T00:15:00Z")
    );
    assert_eq!(
        claims["exp"].as_u64(),
        Some(SIGNED_AT + 900),
        "the signer's TTL is what bounds the credential, and it is the profile's"
    );
    // The skew, measured rather than assumed: the instant an offline verifier reads out of
    // the token is the instant the descriptor publishes. A deployment whose signer and whose
    // request clock disagree fails here, which is what `src/issue.rs` names as its
    // obligation.
    assert_eq!(
        rendered(claims["exp"].as_u64().expect("`exp` is a numeric date")),
        outcome.descriptor.expires_at
    );
    assert_eq!(
        rendered(claims["iat"].as_u64().expect("`iat` is a numeric date")),
        request().at,
        "the signer's clock and the request's instant are one clock"
    );

    // And the descriptor rides alongside, so a verifier reading the token alone learns what
    // the credential asserts.
    assert_eq!(claims["kind"], "SelfContained");
    assert_eq!(claims["organization"], organization(10).to_string());
    assert_eq!(claims["audience"], "api-b");
    assert_eq!(claims["expires_at"], "2026-09-19T00:15:00Z");

    // No key material reaches the log: the event carries the token's digest and nothing else
    // of it.
    assert!(
        !serde_json::to_string(&outcome.event)
            .expect("the event encodes as JSON")
            .contains(&token)
    );
}

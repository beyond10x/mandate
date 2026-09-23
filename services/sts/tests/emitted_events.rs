//! What each handler emits, decided against the contract rather than against this file.
//!
//! Every accepted outcome is put through the three checks
//! `crates/mandate-testkit/src/contract.rs` performs, each reading a generated projection and
//! nothing else:
//!
//! - `assert_event_conforms` validates the emitted payload against
//!   `generated/schema/events/<name>.schema.json`, which closes the key set and decides every
//!   declared lexical form.
//! - `assert_single_emission` reads `generated/ir/system.json`: an accepted outcome emits
//!   exactly the one event the contract declares for it, and an error outcome emits none.
//! - `assert_payload_sources` reads the same file and decides every payload field against the
//!   source the contract declares for it — `input_field` against the command input,
//!   `response_field` against what the handler returned, `generated` for presence.
//!
//! The denied paths are checked the same way and in the same breath: the refusal names the
//! outcome it is ([`RefusedOutcome`]), that outcome is looked up in the IR, and the emission
//! list handed to the harness is empty — so "a denial emits nothing" is decided against the
//! contract's declaration of that outcome and not against a sentence here. Each denied case
//! also folds the log again and asserts the projection is the one it was, which is
//! `mandate.credential.Denied`'s "fail closed; no credential, authority or lifecycle mutation
//! on refusal" in the only form a fold can carry.

use mandate_sts::binding::{RecordedSessions, SessionBinding};
use mandate_sts::code::{
    AuthorizationCodeParts, CodeIssuance, CodeLifetime, IssueAuthorizationCode, RecordedClients,
};
use mandate_sts::exchange::{ExchangeCredential, ExchangeParts, exchange_credential};
use mandate_sts::issue::{
    IssueReferenceCredential, IssueSelfContainedCredential, ReferenceParts, SelfContainedParts,
    Sha256Digest, StaticSigner, issue_reference_credential, issue_self_contained_credential,
};
use mandate_sts::keys::{
    KeyMaterialResolver, RegisterSigningKey, RetireSigningKey, RevokeSigningKey,
    SigningKeyAdministration, retire_signing_key, revoke_signing_key,
};
use mandate_sts::redemption::{
    BoundReads, RedeemAuthorizationCode, RedemptionParts, redeem_authorization_code,
};
use mandate_sts::registry::{
    DisableResourceServer, RegisterResourceServer, disable_resource_server,
    register_resource_server,
};
use mandate_sts::resolve::{
    IntrospectCredential, IntrospectionParts, RevokeAccessCredential, introspect_credential,
    revoke_access_credential,
};
use mandate_sts::store::{AuthorizationCodeEvent, CodeProjection};
use mandate_sts::{
    CountingSecrets, IdentityAllocator, RequestContext, SecretSource, SequentialAllocator,
};
use mandate_testkit::contract::{
    assert_event_conforms, assert_payload_sources, assert_single_emission,
};
use mandate_token::CredentialProfile;
use mandate_token::projection::{CredentialEvent, Denied, Projection};
use mandate_token::signing_real::AllowedAlgorithms;
use mandate_types::{
    Audience, AuthorityScope, AuthorizationCodeId, CorrelationId, CredentialId, CredentialKind,
    CredentialProof, Duration, EpochSnapshotRef, Issuer, KeyReference, OAuthClientId,
    OrganizationId, PkceChallenge, PkceMethod, PrincipalId, RedirectUri, ResourceServerId,
    RevocationGuarantee, SessionId, SigningAlgorithm, SigningKeyId, Timestamp, Transient, Uuid,
    VerifiedContext,
};
use serde::Serialize;
use serde_json::{Value, json};

const REGISTER_SERVER: &str = "mandate.credential.RegisterResourceServer";
const DISABLE_SERVER: &str = "mandate.credential.DisableResourceServer";
const ISSUE_REFERENCE: &str = "mandate.credential.IssueReferenceCredential";
const EXCHANGE: &str = "mandate.credential.ExchangeCredential";
const ISSUE_SELF_CONTAINED: &str = "mandate.credential.IssueSelfContainedCredential";
const INTROSPECT: &str = "mandate.credential.IntrospectCredential";
const REVOKE_CREDENTIAL: &str = "mandate.credential.RevokeAccessCredential";
const REGISTER_KEY: &str = "mandate.credential.RegisterSigningKey";
const RETIRE_KEY: &str = "mandate.credential.RetireSigningKey";
const REVOKE_KEY: &str = "mandate.credential.RevokeSigningKey";
const ISSUE_CODE: &str = "mandate.credential.IssueAuthorizationCode";
const REDEEM_CODE: &str = "mandate.credential.RedeemAuthorizationCode";

/// RFC 7636 appendix B: the example code verifier and the S256 challenge it redeems.
const PKCE_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const PKCE_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

fn uuid(tag: u8) -> Uuid {
    Uuid::from_bytes([tag; 16])
}

fn organization(tag: u8) -> OrganizationId {
    OrganizationId::new(uuid(tag))
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
        correlation: CorrelationId::new("emitted-events"),
    }
}

fn request() -> RequestContext {
    RequestContext {
        correlation: CorrelationId::new("emitted-events"),
        at: Timestamp::new("2026-09-19T00:00:00Z"),
        epochs: Some(EpochSnapshotRef::new(uuid(0x60))),
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

fn encoded<T: Serialize>(value: &T) -> Value {
    serde_json::to_value(value).expect("a declared value encodes as JSON")
}

/// One accepted outcome, through all three checks.
///
/// `response` is built from what the handler returned, never from the event: the whole point
/// of the source check is that the two agree.
fn accepted(command: &str, input: &Value, response: Option<&Value>, event: &CredentialEvent) {
    let payload = encoded(event);
    let name = event.ess_name();
    assert_single_emission(command, "accepted", &[(name, &payload)]);
    assert_event_conforms(name, &payload);
    assert_payload_sources(command, input, response, name, &payload);
}

/// The same three checks, for an event the code store declares rather than the credential
/// fold. `AuthorizationCodeEvent` carries the same payloads under its own `ess_name`, so the
/// harness reads the same generated schema and the same IR node.
fn accepted_code(
    command: &str,
    input: &Value,
    response: Option<&Value>,
    event: &AuthorizationCodeEvent,
) {
    let payload = encoded(event);
    let name = event.ess_name();
    assert_single_emission(command, "accepted", &[(name, &payload)]);
    assert_event_conforms(name, &payload);
    assert_payload_sources(command, input, response, name, &payload);
}

/// One refused outcome: the outcome the refusal names is declared by the contract, and it
/// emitted nothing.
fn refused(command: &str, denied: &Denied) {
    assert_single_emission(command, denied.outcome.ir_name(), &[]);
}

/// The material this deployment resolves, by reference.
struct ResolvableKeys;

impl KeyMaterialResolver for ResolvableKeys {
    fn thumbprint(&self, reference: &KeyReference) -> Option<String> {
        match reference.as_str() {
            "kms://one" => Some("thumb-one".to_owned()),
            "kms://two" => Some("thumb-two".to_owned()),
            _ => None,
        }
    }
}

fn admitted() -> AllowedAlgorithms {
    AllowedAlgorithms::new(&[SigningAlgorithm::new("RS256")]).expect("a configured allowlist")
}

fn registration(
    organization_id: OrganizationId,
    audience: &str,
    profile: CredentialProfile,
) -> RegisterResourceServer {
    RegisterResourceServer {
        context: context(organization_id),
        audience: Audience::new(audience),
        profile,
        allowed_exchange_sources: Vec::new(),
    }
}

/// One registered target through the real handler, with its log and identity.
fn registered(
    organization_id: OrganizationId,
    audience: &str,
    profile: CredentialProfile,
) -> (Projection, Vec<CredentialEvent>, ResourceServerId) {
    let mut allocator = SequentialAllocator::new();
    let outcome = register_resource_server(
        &registration(organization_id, audience, profile),
        &Projection::default(),
        &mut allocator,
    )
    .expect("a free audience in the caller's own organization");
    let log = vec![outcome.event];
    (
        Projection::fold(&log).expect("one creation"),
        log,
        outcome.resource_server_id,
    )
}

#[test]
fn register_resource_server_emits_exactly_the_declared_event() {
    let mut allocator = SequentialAllocator::new();
    let input = registration(organization(10), "api-a", reference_profile());

    let outcome = register_resource_server(&input, &Projection::default(), &mut allocator)
        .expect("a free audience in the caller's own organization");

    accepted(
        REGISTER_SERVER,
        &encoded(&input),
        Some(&json!({"resource_server_id": encoded(&outcome.resource_server_id)})),
        &outcome.event,
    );
}

#[test]
fn a_refused_registration_emits_nothing_and_leaves_the_fold_unchanged() {
    let (held, log, _) = registered(organization(10), "api-a", reference_profile());
    let mut allocator = SequentialAllocator::new();

    let denied = register_resource_server(
        &registration(organization(10), "api-a", reference_profile()),
        &held,
        &mut allocator,
    )
    .expect_err("the audience is registered in this organization");

    refused(REGISTER_SERVER, &denied);
    assert_eq!(
        Projection::fold(&log).expect("the same log"),
        held,
        "a refusal writes no event, so the fold is the one it was"
    );
}

#[test]
fn disable_resource_server_emits_exactly_the_declared_event() {
    let (held, _, id) = registered(organization(10), "api-a", reference_profile());
    let input = DisableResourceServer {
        id,
        context: context(organization(10)),
    };

    let event = disable_resource_server(&input, &held).expect("an enabled registration");

    accepted(DISABLE_SERVER, &encoded(&input), None, &event);
}

#[test]
fn a_refused_disablement_emits_nothing_through_the_outcome_it_names() {
    let (held, log, id) = registered(organization(10), "api-a", reference_profile());

    // The external denial.
    let denied = disable_resource_server(
        &DisableResourceServer {
            id,
            context: context(organization(11)),
        },
        &held,
    )
    .expect_err("the registration is another organization's");
    refused(DISABLE_SERVER, &denied);

    // The wrong-state branch, which the contract renders differently.
    let mut log = log;
    log.push(
        disable_resource_server(
            &DisableResourceServer {
                id,
                context: context(organization(10)),
            },
            &held,
        )
        .expect("the first disablement"),
    );
    let held = Projection::fold(&log).expect("a creation and its move");
    let denied = disable_resource_server(
        &DisableResourceServer {
            id,
            context: context(organization(10)),
        },
        &held,
    )
    .expect_err("`disable` starts from `Enabled` alone");
    refused(DISABLE_SERVER, &denied);
    assert_eq!(Projection::fold(&log).expect("the same log"), held);
}

#[test]
fn issue_reference_credential_emits_exactly_the_declared_event() {
    let (held, _, id) = registered(organization(10), "api-a", reference_profile());
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

    accepted(
        ISSUE_REFERENCE,
        &encoded(&input),
        Some(&json!({
            "credential_id": encoded(&outcome.credential_id),
            "descriptor": encoded(&outcome.descriptor),
            "epochs": encoded(&outcome.epochs),
        })),
        &outcome.event,
    );
}

/// The same command with the optional the response declares absent: the contract's
/// optional-to-optional mapping, which is the one shape a source check can get wrong in both
/// directions.
#[test]
fn issue_reference_credential_without_an_epoch_snapshot_emits_the_declared_event() {
    let (held, _, id) = registered(organization(10), "api-a", reference_profile());
    let mut secrets = CountingSecrets::new();
    let mut allocator = SequentialAllocator::new();
    let input = IssueReferenceCredential {
        context: context(organization(10)),
        target: id,
        requested_scope: scope(),
    };
    let undated = RequestContext {
        epochs: None,
        ..request()
    };

    let outcome = issue_reference_credential(
        &input,
        &undated,
        &held,
        ReferenceParts {
            digest: &Sha256Digest,
            secrets: &mut secrets,
            allocator: &mut allocator,
        },
    )
    .expect("a registered, enabled target of the caller's organization");

    assert_eq!(outcome.epochs, None);
    accepted(
        ISSUE_REFERENCE,
        &encoded(&input),
        Some(&json!({
            "credential_id": encoded(&outcome.credential_id),
            "descriptor": encoded(&outcome.descriptor),
        })),
        &outcome.event,
    );
}

#[test]
fn a_refused_reference_issuance_emits_nothing_and_leaves_the_fold_unchanged() {
    let (held, log, _) = registered(organization(10), "api-a", reference_profile());
    let mut secrets = CountingSecrets::new();
    let mut allocator = SequentialAllocator::new();

    let denied = issue_reference_credential(
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

    refused(ISSUE_REFERENCE, &denied);
    assert_eq!(Projection::fold(&log).expect("the same log"), held);
}

#[test]
fn issue_self_contained_credential_emits_exactly_the_declared_event() {
    let (held, _, id) = registered(organization(10), "api-b", self_contained_profile());
    let mut allocator = SequentialAllocator::new();
    let signer = StaticSigner::new("kid-one", 900);
    let input = IssueSelfContainedCredential {
        context: context(organization(10)),
        target: id,
        requested_scope: scope(),
    };

    let outcome = issue_self_contained_credential(
        &input,
        &request(),
        &held,
        SelfContainedParts {
            digest: &Sha256Digest,
            allocator: &mut allocator,
            signer: &signer,
            issuer: &Issuer::new("https://sts.example"),
        },
    )
    .expect("a registered, enabled target of the caller's organization");

    accepted(
        ISSUE_SELF_CONTAINED,
        &encoded(&input),
        Some(&json!({
            "credential_id": encoded(&outcome.credential_id),
            "descriptor": encoded(&outcome.descriptor),
            "epochs": encoded(&outcome.epochs),
        })),
        &outcome.event,
    );
}

#[test]
fn a_refused_self_contained_issuance_emits_nothing_and_leaves_the_fold_unchanged() {
    let (held, log, id) = registered(organization(10), "api-b", self_contained_profile());
    let mut allocator = SequentialAllocator::new();
    // The signer would outlive the profile's bound.
    let signer = StaticSigner::new("kid-one", 3_600);

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
            issuer: &Issuer::new("https://sts.example"),
        },
    )
    .expect_err("the signer's lifetime is outside the profile's bound");

    refused(ISSUE_SELF_CONTAINED, &denied);
    assert_eq!(Projection::fold(&log).expect("the same log"), held);
}

/// One registered target, one caller credential and one credential to introspect.
fn introspectable() -> (
    Projection,
    Vec<CredentialEvent>,
    CredentialProof,
    CredentialProof,
) {
    let (held, mut log, id) = registered(organization(10), "api-a", reference_profile());
    let mut secrets = CountingSecrets::new();
    let mut allocator = SequentialAllocator::new();
    let issue =
        |held: &Projection, secrets: &mut CountingSecrets, allocator: &mut SequentialAllocator| {
            issue_reference_credential(
                &IssueReferenceCredential {
                    context: context(organization(10)),
                    target: id,
                    requested_scope: scope(),
                },
                &request(),
                held,
                ReferenceParts {
                    digest: &Sha256Digest,
                    secrets,
                    allocator,
                },
            )
            .expect("a registered, enabled target of the caller's organization")
        };
    let caller = issue(&held, &mut secrets, &mut allocator);
    log.push(caller.event);
    let held = Projection::fold(&log).expect("one issuance");
    let presented = issue(&held, &mut secrets, &mut allocator);
    log.push(presented.event);
    let held = Projection::fold(&log).expect("two issuances");
    (
        held,
        log,
        CredentialProof::from_bytes(caller.credential.expose_material().to_vec()),
        CredentialProof::from_bytes(presented.credential.expose_material().to_vec()),
    )
}

#[test]
fn an_active_introspection_emits_exactly_the_declared_event() {
    let (held, _, caller, presented) = introspectable();
    let input = IntrospectCredential {
        caller_proof: caller,
        credential_proof: presented,
    };

    let outcome = introspect_credential(
        &input,
        &request(),
        &held,
        IntrospectionParts {
            digest: &Sha256Digest,
            resolution: &held,
        },
    )
    .expect("an authorized introspection");

    accepted(
        INTROSPECT,
        &encoded(&input),
        Some(&json!({
            "active": outcome.active,
            "descriptor": encoded(&outcome.descriptor),
            "credential_id": encoded(&outcome.credential_id),
        })),
        &outcome.event,
    );
}

/// The inactive answer, whose two optionals are absent on both sides: the contract's
/// optional-to-optional mapping again, and the form the summary insists on.
#[test]
fn an_inactive_introspection_emits_exactly_the_declared_event() {
    let (held, _, caller, _) = introspectable();
    let input = IntrospectCredential {
        caller_proof: caller,
        credential_proof: CredentialProof::from_bytes(b"a-proof-from-another-deployment".to_vec()),
    };

    let outcome = introspect_credential(
        &input,
        &request(),
        &held,
        IntrospectionParts {
            digest: &Sha256Digest,
            resolution: &held,
        },
    )
    .expect("a well-formed proof is an accepted answer");

    assert!(!outcome.active);
    accepted(
        INTROSPECT,
        &encoded(&input),
        Some(&json!({"active": outcome.active})),
        &outcome.event,
    );
}

/// The same inactive answer for a credential this deployment **revoked** — the corpus's
/// `reference-revoked`, through the contract's own harness.
///
/// The three inactive answers are "one answer here and not three" (`credential.yaml`), and
/// the way to show that is to put each of them through the schema and the payload sources
/// rather than only the one that resolves to nothing.
#[test]
fn a_revoked_credentials_introspection_emits_exactly_the_declared_event() {
    let (held, mut log, caller, presented) = introspectable();
    let id = held
        .credentials()
        .iter()
        .find(|credential| {
            credential
                .reference_verifier
                .as_ref()
                .is_some_and(|recorded| {
                    *recorded == mandate_token::verifier::verifier_for(&Sha256Digest, &presented)
                })
        })
        .expect("the credential the issuance created")
        .id;
    log.push(
        revoke_access_credential(
            &RevokeAccessCredential {
                id,
                context: context(organization(10)),
            },
            &held,
        )
        .expect("an active credential of the caller's own organization"),
    );
    let held = Projection::fold(&log).expect("the revocation");
    let input = IntrospectCredential {
        caller_proof: caller,
        credential_proof: presented,
    };

    let outcome = introspect_credential(
        &input,
        &request(),
        &held,
        IntrospectionParts {
            digest: &Sha256Digest,
            resolution: &held,
        },
    )
    .expect("a revoked credential is an accepted answer");

    assert!(!outcome.active);
    accepted(
        INTROSPECT,
        &encoded(&input),
        Some(&json!({"active": outcome.active})),
        &outcome.event,
    );
}

/// And for a credential whose **expiry has passed** — the corpus's `reference-expired`.
///
/// The credential is issued a day earlier, so its hour is gone by the time the caller —
/// whose own credential is not — presents it at the request instant.
#[test]
fn an_expired_credentials_introspection_emits_exactly_the_declared_event() {
    let (held, mut log, caller, _) = introspectable();
    let target = held
        .registered(&organization(10), &Audience::new("api-a"))
        .expect("the registration")
        .id;
    let mut secrets = CountingSecrets::new();
    let mut allocator = SequentialAllocator::new();
    for _ in 0..8 {
        let _ = secrets.next_secret();
        let _ = allocator.next_credential_id();
    }
    let stale = issue_reference_credential(
        &IssueReferenceCredential {
            context: context(organization(10)),
            target,
            requested_scope: scope(),
        },
        &RequestContext {
            at: Timestamp::new("2026-09-18T00:00:00Z"),
            ..request()
        },
        &held,
        ReferenceParts {
            digest: &Sha256Digest,
            secrets: &mut secrets,
            allocator: &mut allocator,
        },
    )
    .expect("a registered, enabled target of the caller's organization");
    let presented = CredentialProof::from_bytes(stale.credential.expose_material().to_vec());
    log.push(stale.event);
    let held = Projection::fold(&log).expect("a third issuance");
    let input = IntrospectCredential {
        caller_proof: caller,
        credential_proof: presented,
    };

    let outcome = introspect_credential(
        &input,
        &request(),
        &held,
        IntrospectionParts {
            digest: &Sha256Digest,
            resolution: &held,
        },
    )
    .expect("an expired credential is an accepted answer");

    assert!(!outcome.active);
    accepted(
        INTROSPECT,
        &encoded(&input),
        Some(&json!({"active": outcome.active})),
        &outcome.event,
    );
}

#[test]
fn a_refused_introspection_emits_nothing_and_leaves_the_fold_unchanged() {
    let (held, log, _, presented) = introspectable();

    let denied = introspect_credential(
        &IntrospectCredential {
            caller_proof: CredentialProof::from_bytes(b"not-a-credential".to_vec()),
            credential_proof: presented,
        },
        &request(),
        &held,
        IntrospectionParts {
            digest: &Sha256Digest,
            resolution: &held,
        },
    )
    .expect_err("the caller's own proof resolves to nothing");

    refused(INTROSPECT, &denied);
    assert_eq!(Projection::fold(&log).expect("the same log"), held);
}

#[test]
fn revoke_access_credential_emits_exactly_the_declared_event() {
    let (held, _, _, presented) = introspectable();
    let id = held
        .credentials()
        .iter()
        .find(|credential| {
            credential
                .reference_verifier
                .as_ref()
                .is_some_and(|recorded| {
                    *recorded == mandate_token::verifier::verifier_for(&Sha256Digest, &presented)
                })
        })
        .expect("the credential the issuance created")
        .id;
    let input = RevokeAccessCredential {
        id,
        context: context(organization(10)),
    };

    let event = revoke_access_credential(&input, &held).expect("an active credential");

    accepted(REVOKE_CREDENTIAL, &encoded(&input), None, &event);
}

#[test]
fn a_refused_revocation_emits_nothing_through_the_outcome_it_names() {
    let (held, log, _, _) = introspectable();
    let id = held.credentials()[0].id;

    let denied = revoke_access_credential(
        &RevokeAccessCredential {
            id,
            context: context(organization(11)),
        },
        &held,
    )
    .expect_err("the credential is another organization's");
    refused(REVOKE_CREDENTIAL, &denied);

    let mut log = log;
    log.push(
        revoke_access_credential(
            &RevokeAccessCredential {
                id,
                context: context(organization(10)),
            },
            &held,
        )
        .expect("the first revocation"),
    );
    let held = Projection::fold(&log).expect("the revocation");
    let denied = revoke_access_credential(
        &RevokeAccessCredential {
            id,
            context: context(organization(10)),
        },
        &held,
    )
    .expect_err("`revoke` starts from `Active` alone");
    refused(REVOKE_CREDENTIAL, &denied);
    assert_eq!(Projection::fold(&log).expect("the same log"), held);
}

fn key_registration(reference: &str) -> RegisterSigningKey {
    RegisterSigningKey {
        context: context(organization(10)),
        key_reference: KeyReference::new(reference),
        algorithm: SigningAlgorithm::new("RS256"),
        not_before: Timestamp::new("2026-09-19T00:00:00Z"),
        expires_at: Timestamp::new("2026-12-31T00:00:00Z"),
    }
}

#[test]
fn register_signing_key_emits_exactly_the_declared_event() {
    let mut allocator = SequentialAllocator::new();
    let input = key_registration("kms://one");

    let outcome = SigningKeyAdministration::new(admitted())
        .register(
            &input,
            &Projection::default(),
            &ResolvableKeys,
            &mut allocator,
        )
        .expect("an admitted algorithm, a resolvable reference and an ordered window");

    accepted(
        REGISTER_KEY,
        &encoded(&input),
        Some(&json!({
            "id": encoded(&outcome.id),
            "thumbprint": outcome.thumbprint,
        })),
        &outcome.event,
    );
}

#[test]
fn a_refused_key_registration_emits_nothing_and_leaves_the_fold_unchanged() {
    let mut allocator = SequentialAllocator::new();
    let administration = SigningKeyAdministration::new(admitted());
    let first = administration
        .register(
            &key_registration("kms://one"),
            &Projection::default(),
            &ResolvableKeys,
            &mut allocator,
        )
        .expect("the first registration");
    let log = vec![first.event];
    let held = Projection::fold(&log).expect("one creation");

    let denied = administration
        .register(
            &key_registration("kms://one"),
            &held,
            &ResolvableKeys,
            &mut allocator,
        )
        .expect_err("the reference is already recorded");

    refused(REGISTER_KEY, &denied);
    assert_eq!(Projection::fold(&log).expect("the same log"), held);
}

/// Two recorded keys, so a retirement has a replacement to overlap with.
fn two_keys() -> (Projection, Vec<CredentialEvent>, SigningKeyId) {
    let mut allocator = SequentialAllocator::new();
    let administration = SigningKeyAdministration::new(admitted());
    let first = administration
        .register(
            &key_registration("kms://one"),
            &Projection::default(),
            &ResolvableKeys,
            &mut allocator,
        )
        .expect("the first registration");
    let held = Projection::fold(std::slice::from_ref(&first.event)).expect("one creation");
    let second = administration
        .register(
            &key_registration("kms://two"),
            &held,
            &ResolvableKeys,
            &mut allocator,
        )
        .expect("the second registration");
    let log = vec![first.event, second.event];
    (
        Projection::fold(&log).expect("two creations"),
        log,
        first.id,
    )
}

#[test]
fn retire_signing_key_emits_exactly_the_declared_event() {
    let (held, _, id) = two_keys();
    let input = RetireSigningKey {
        id,
        context: context(organization(10)),
    };

    let event = retire_signing_key(&input, &held, &request()).expect("a published replacement");

    accepted(RETIRE_KEY, &encoded(&input), None, &event);
}

#[test]
fn a_refused_retirement_emits_nothing_through_the_outcome_it_names() {
    let (held, log, id) = two_keys();

    let mut log = log;
    log.push(
        retire_signing_key(
            &RetireSigningKey {
                id,
                context: context(organization(10)),
            },
            &held,
            &request(),
        )
        .expect("the first retirement"),
    );
    let held = Projection::fold(&log).expect("two creations and a move");

    let denied = retire_signing_key(
        &RetireSigningKey {
            id,
            context: context(organization(10)),
        },
        &held,
        &request(),
    )
    .expect_err("`retire` starts from `Recorded` alone");

    refused(RETIRE_KEY, &denied);
    assert_eq!(Projection::fold(&log).expect("the same log"), held);
}

#[test]
fn revoke_signing_key_emits_exactly_the_declared_event() {
    let (held, _, id) = two_keys();
    let input = RevokeSigningKey {
        id,
        context: context(organization(10)),
    };

    let event = revoke_signing_key(&input, &held).expect("a recorded key");

    accepted(REVOKE_KEY, &encoded(&input), None, &event);
}

#[test]
fn a_refused_key_revocation_emits_nothing_through_the_outcome_it_names() {
    let (held, log, id) = two_keys();

    let unknown = revoke_signing_key(
        &RevokeSigningKey {
            id: SigningKeyId::new(uuid(0x99)),
            context: context(organization(10)),
        },
        &held,
    )
    .expect_err("no event recorded it");
    refused(REVOKE_KEY, &unknown);

    let mut log = log;
    log.push(
        revoke_signing_key(
            &RevokeSigningKey {
                id,
                context: context(organization(10)),
            },
            &held,
        )
        .expect("the first revocation"),
    );
    let held = Projection::fold(&log).expect("two creations and a move");
    let denied = revoke_signing_key(
        &RevokeSigningKey {
            id,
            context: context(organization(10)),
        },
        &held,
    )
    .expect_err("`revoke` starts from neither terminal state twice");

    refused(REVOKE_KEY, &denied);
    assert_eq!(Projection::fold(&log).expect("the same log"), held);
}

// --- the authorization-code transaction -------------------------------------------------

fn oauth_client() -> OAuthClientId {
    OAuthClientId::new(uuid(0x0c))
}

fn oauth_session() -> SessionId {
    SessionId::new(uuid(0x5e))
}

fn code_clients() -> RecordedClients {
    RecordedClients::new()
        .enabled(oauth_client(), organization(10))
        .redirect(
            oauth_client(),
            RedirectUri::new("https://client.example/callback"),
        )
}

fn code_sessions(epochs: Option<EpochSnapshotRef>) -> RecordedSessions {
    let sessions = RecordedSessions::new().session(SessionBinding {
        id: oauth_session(),
        subject: PrincipalId::new(uuid(0x51)),
        organization: organization(10),
        epochs,
        expires_at: Timestamp::new("2026-09-19T12:00:00Z"),
        revoked: false,
    });
    match epochs {
        Some(snapshot) => sessions.current(snapshot),
        None => sessions,
    }
}

fn code_input(target: ResourceServerId) -> IssueAuthorizationCode {
    IssueAuthorizationCode {
        context: context(organization(10)),
        client_id: oauth_client(),
        session_id: oauth_session(),
        target,
        requested_scope: scope(),
        challenge: PkceChallenge::new(PKCE_CHALLENGE),
        method: PkceMethod::S256,
        redirect_uri: RedirectUri::new("https://client.example/callback"),
        expires_at: Timestamp::new("2026-09-19T00:05:00Z"),
    }
}

/// One code, issued through the real handler, with the code log it created and the proof of
/// holding it.
fn issued_code(
    held: &Projection,
    target: ResourceServerId,
) -> (
    Vec<AuthorizationCodeEvent>,
    AuthorizationCodeId,
    CredentialProof,
) {
    let mut secrets = CountingSecrets::new();
    let mut allocator = SequentialAllocator::new();
    let outcome = CodeIssuance::new(CodeLifetime::new(Duration::new("PT5M")))
        .issue(
            &code_input(target),
            &request(),
            held,
            &code_clients(),
            AuthorizationCodeParts {
                digest: &Sha256Digest,
                secrets: &mut secrets,
                allocator: &mut allocator,
            },
        )
        .expect("a registered enabled target and client");
    let proof = CredentialProof::from_bytes(outcome.code.expose_material().to_vec());
    (vec![outcome.event], outcome.code_id, proof)
}

fn redemption(code_id: AuthorizationCodeId, proof: &CredentialProof) -> RedeemAuthorizationCode {
    RedeemAuthorizationCode {
        code_id,
        client_id: oauth_client(),
        code: CredentialProof::from_bytes(proof.expose_material().to_vec()),
        pkce_verifier: CredentialProof::from_bytes(PKCE_VERIFIER.as_bytes().to_vec()),
        redirect_uri: RedirectUri::new("https://client.example/callback"),
    }
}

#[test]
fn issue_authorization_code_emits_exactly_the_declared_event() {
    let (held, _, id) = registered(organization(10), "api-a", reference_profile());
    let mut secrets = CountingSecrets::new();
    let mut allocator = SequentialAllocator::new();
    let input = code_input(id);

    let outcome = CodeIssuance::new(CodeLifetime::new(Duration::new("PT5M")))
        .issue(
            &input,
            &request(),
            &held,
            &code_clients(),
            AuthorizationCodeParts {
                digest: &Sha256Digest,
                secrets: &mut secrets,
                allocator: &mut allocator,
            },
        )
        .expect("a registered enabled target and client of the caller's organization");

    accepted_code(
        ISSUE_CODE,
        &encoded(&input),
        Some(&json!({ "code_id": encoded(&outcome.code_id) })),
        &outcome.event,
    );
}

#[test]
fn a_refused_code_issuance_emits_nothing_and_leaves_both_folds_unchanged() {
    let (held, log, id) = registered(organization(10), "api-a", reference_profile());
    let (code_log, _, _) = issued_code(&held, id);
    let codes = CodeProjection::fold(&code_log).expect("one creation");
    let mut secrets = CountingSecrets::new();
    let mut allocator = SequentialAllocator::new();

    let denied = CodeIssuance::new(CodeLifetime::new(Duration::new("PT5M")))
        .issue(
            &IssueAuthorizationCode {
                target: ResourceServerId::new(uuid(0x99)),
                ..code_input(id)
            },
            &request(),
            &held,
            &code_clients(),
            AuthorizationCodeParts {
                digest: &Sha256Digest,
                secrets: &mut secrets,
                allocator: &mut allocator,
            },
        )
        .expect_err("no event registered that target");

    refused(ISSUE_CODE, &denied);
    assert_eq!(Projection::fold(&log).expect("the same log"), held);
    assert_eq!(
        CodeProjection::fold(&code_log).expect("the same log"),
        codes
    );
}

#[test]
fn redeem_authorization_code_emits_exactly_the_declared_event() {
    let (held, _, id) = registered(organization(10), "api-a", reference_profile());
    let (code_log, code_id, proof) = issued_code(&held, id);
    let codes = CodeProjection::fold(&code_log).expect("one creation");
    let mut secrets = CountingSecrets::new();
    let mut allocator = SequentialAllocator::new();
    let input = redemption(code_id, &proof);
    let sessions = code_sessions(Some(EpochSnapshotRef::new(uuid(0x60))));
    let clients = code_clients();

    let outcome = redeem_authorization_code(
        &input,
        &request(),
        &codes,
        BoundReads {
            servers: &held,
            clients: &clients,
            sessions: &sessions,
        },
        RedemptionParts {
            digest: &Sha256Digest,
            secrets: &mut secrets,
            allocator: &mut allocator,
        },
    )
    .expect("the matching verifier, client and redirect");

    accepted_code(
        REDEEM_CODE,
        &encoded(&input),
        Some(&json!({
            "credential_id": encoded(&outcome.credential_id),
            "descriptor": encoded(&outcome.descriptor),
            "epochs": encoded(&outcome.epochs),
            "target": encoded(&outcome.target),
        })),
        &outcome.event,
    );
}

/// The same command with the optional the response declares absent: the contract's
/// optional-to-optional mapping, which is the one shape a source check can get wrong in both
/// directions. A session that names no snapshot binds no epoch.
#[test]
fn redeem_authorization_code_without_an_epoch_snapshot_emits_the_declared_event() {
    let (held, _, id) = registered(organization(10), "api-a", reference_profile());
    let (code_log, code_id, proof) = issued_code(&held, id);
    let codes = CodeProjection::fold(&code_log).expect("one creation");
    let mut secrets = CountingSecrets::new();
    let mut allocator = SequentialAllocator::new();
    let input = redemption(code_id, &proof);
    let sessions = code_sessions(None);
    let clients = code_clients();

    let outcome = redeem_authorization_code(
        &input,
        &request(),
        &codes,
        BoundReads {
            servers: &held,
            clients: &clients,
            sessions: &sessions,
        },
        RedemptionParts {
            digest: &Sha256Digest,
            secrets: &mut secrets,
            allocator: &mut allocator,
        },
    )
    .expect("a live session that names no snapshot");

    assert_eq!(outcome.epochs, None);
    accepted_code(
        REDEEM_CODE,
        &encoded(&input),
        Some(&json!({
            "credential_id": encoded(&outcome.credential_id),
            "descriptor": encoded(&outcome.descriptor),
            "target": encoded(&outcome.target),
        })),
        &outcome.event,
    );
}

/// The `AccessCredential` the redemption seeds is materialized by the `mandate-token` fold
/// from the same payload, which is the other half of what the event is for.
#[test]
fn the_redeemed_event_seeds_the_credential_record_in_the_credential_log() {
    let (held, log, id) = registered(organization(10), "api-a", reference_profile());
    let (code_log, code_id, proof) = issued_code(&held, id);
    let codes = CodeProjection::fold(&code_log).expect("one creation");
    let mut secrets = CountingSecrets::new();
    let mut allocator = SequentialAllocator::new();
    let sessions = code_sessions(Some(EpochSnapshotRef::new(uuid(0x60))));
    let clients = code_clients();

    let outcome = redeem_authorization_code(
        &redemption(code_id, &proof),
        &request(),
        &codes,
        BoundReads {
            servers: &held,
            clients: &clients,
            sessions: &sessions,
        },
        RedemptionParts {
            digest: &Sha256Digest,
            secrets: &mut secrets,
            allocator: &mut allocator,
        },
    )
    .expect("a fresh code");

    let mut log = log;
    log.push(
        outcome
            .event
            .credential_event()
            .expect("the redemption seeds a credential"),
    );
    let rebuilt = Projection::fold(&log).expect("the registration and the redemption");
    assert_eq!(rebuilt.credentials().len(), 1);
    assert_eq!(
        rebuilt
            .access_credential(&outcome.credential_id)
            .map(|record| record.descriptor),
        Some(outcome.descriptor)
    );
}

/// Every denied path of the redemption emits nothing, through the outcome the refusal names
/// — including the `wrong-state` the contract renders differently — and leaves both folds
/// exactly as they were.
#[test]
fn every_refused_redemption_emits_nothing_through_the_outcome_it_names() {
    let (held, log, id) = registered(organization(10), "api-a", reference_profile());
    let (code_log, code_id, proof) = issued_code(&held, id);
    let codes = CodeProjection::fold(&code_log).expect("one creation");
    let sessions = code_sessions(Some(EpochSnapshotRef::new(uuid(0x60))));
    let clients = code_clients();

    let refuse = |input: &RedeemAuthorizationCode, codes: &CodeProjection| {
        let mut secrets = CountingSecrets::new();
        let mut allocator = SequentialAllocator::new();
        redeem_authorization_code(
            input,
            &request(),
            codes,
            BoundReads {
                servers: &held,
                clients: &clients,
                sessions: &sessions,
            },
            RedemptionParts {
                digest: &Sha256Digest,
                secrets: &mut secrets,
                allocator: &mut allocator,
            },
        )
    };

    // The external denial: a proof that resolves to no code.
    let denied = refuse(
        &RedeemAuthorizationCode {
            code: CredentialProof::from_bytes(b"not-the-code".to_vec()),
            ..redemption(code_id, &proof)
        },
        &codes,
    )
    .expect_err("the proof is not the one the record's verifier came from");
    refused(REDEEM_CODE, &denied);

    // The wrong-state branch, which the contract renders differently.
    let accepted_once = refuse(&redemption(code_id, &proof), &codes).expect("the first");
    let mut code_log = code_log;
    code_log.push(accepted_once.event);
    let consumed = CodeProjection::fold(&code_log).expect("a creation and its move");
    let denied = refuse(&redemption(code_id, &proof), &consumed)
        .expect_err("`consume` starts from `Issued` alone");
    refused(REDEEM_CODE, &denied);

    assert_eq!(Projection::fold(&log).expect("the same log"), held);
    assert_eq!(
        CodeProjection::fold(&code_log).expect("the same log"),
        consumed
    );
}

// --- ExchangeCredential ------------------------------------------------------------------

/// A source `S`, a target `T` admitting it, and one reference credential for `S`, through
/// the real handlers: the log, the fold, the subject credential and the target.
fn exchangeable() -> (
    Projection,
    Vec<CredentialEvent>,
    mandate_types::CredentialSecret,
    ResourceServerId,
    SequentialAllocator,
) {
    let mut allocator = SequentialAllocator::new();
    let mut held = Projection::default();
    let mut log = Vec::new();
    let source = register_resource_server(
        &registration(organization(10), "api-s", reference_profile()),
        &held,
        &mut allocator,
    )
    .expect("a free audience");
    held.apply(&source.event).expect("a readable registration");
    log.push(source.event);
    let target = register_resource_server(
        &RegisterResourceServer {
            allowed_exchange_sources: vec![source.resource_server_id],
            ..registration(organization(10), "platform-api", reference_profile())
        },
        &held,
        &mut allocator,
    )
    .expect("a free audience admitting an enabled source");
    held.apply(&target.event).expect("a readable registration");
    log.push(target.event);
    let issued = issue_reference_credential(
        &IssueReferenceCredential {
            context: context(organization(10)),
            target: source.resource_server_id,
            requested_scope: scope(),
        },
        &request(),
        &held,
        ReferenceParts {
            digest: &Sha256Digest,
            secrets: &mut CountingSecrets::new(),
            allocator: &mut allocator,
        },
    )
    .expect("an issuance for the source");
    held.apply(&issued.event).expect("a readable issuance");
    log.push(issued.event);
    (
        held,
        log,
        issued.credential,
        target.resource_server_id,
        allocator,
    )
}

#[test]
fn exchange_credential_emits_exactly_the_declared_event() {
    let (held, _, subject, target, mut allocator) = exchangeable();
    let input = ExchangeCredential {
        subject_proof: CredentialProof::from_bytes(subject.expose_bytes().to_vec()),
        actor_proof: None,
        target,
        requested_scope: scope(),
        delegation_id: None,
    };
    let outcome = exchange_credential(
        &input,
        &request(),
        &held,
        ExchangeParts {
            digest: &Sha256Digest,
            resolution: &held,
            secrets: &mut CountingSecrets::new(),
            allocator: &mut allocator,
        },
    )
    .expect("the target admits the source");
    assert!(
        outcome.epochs.is_some(),
        "the subject credential's snapshot travels"
    );
    accepted(
        EXCHANGE,
        &encoded(&input),
        Some(&json!({
            "credential_id": encoded(&outcome.credential_id),
            "descriptor": encoded(&outcome.descriptor),
            "epochs": encoded(&outcome.epochs),
        })),
        &outcome.event,
    );
}

/// The declared `denied` outcome emits nothing. What the refusal carries beside it is the
/// `TokenExchangeDenied` record, which no outcome emits and which is decided against its
/// own generated payload here.
#[test]
fn a_refused_exchange_emits_nothing_through_its_outcome_and_its_record_conforms() {
    let (held, log, subject, _, mut allocator) = exchangeable();
    let refused_exchange = exchange_credential(
        &ExchangeCredential {
            subject_proof: CredentialProof::from_bytes(subject.expose_bytes().to_vec()),
            actor_proof: None,
            target: ResourceServerId::new(uuid(0x99)),
            requested_scope: scope(),
            delegation_id: None,
        },
        &request(),
        &held,
        ExchangeParts {
            digest: &Sha256Digest,
            resolution: &held,
            secrets: &mut CountingSecrets::new(),
            allocator: &mut allocator,
        },
    )
    .expect_err("no event registered that target");
    refused(EXCHANGE, &refused_exchange.denied);
    let record = encoded(&refused_exchange.event);
    assert_eq!(
        refused_exchange.event.ess_name(),
        "mandate.credential.TokenExchangeDenied"
    );
    assert_event_conforms(refused_exchange.event.ess_name(), &record);
    assert_eq!(Projection::fold(&log).expect("the same log"), held);
}

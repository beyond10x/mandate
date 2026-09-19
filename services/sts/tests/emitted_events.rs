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

use mandate_sts::issue::{
    IssueReferenceCredential, IssueSelfContainedCredential, ReferenceParts, SelfContainedParts,
    Sha256Digest, StaticSigner, issue_reference_credential, issue_self_contained_credential,
};
use mandate_sts::keys::{
    KeyMaterialResolver, RegisterSigningKey, RetireSigningKey, RevokeSigningKey,
    SigningKeyAdministration, retire_signing_key, revoke_signing_key,
};
use mandate_sts::registry::{
    DisableResourceServer, RegisterResourceServer, disable_resource_server,
    register_resource_server,
};
use mandate_sts::resolve::{
    IntrospectCredential, IntrospectionParts, RevokeAccessCredential, introspect_credential,
    revoke_access_credential,
};
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
    Audience, AuthorityScope, CorrelationId, CredentialId, CredentialKind, CredentialProof,
    Duration, EpochSnapshotRef, Issuer, KeyReference, OrganizationId, PrincipalId,
    ResourceServerId, RevocationGuarantee, SigningAlgorithm, SigningKeyId, Timestamp, Transient,
    Uuid, VerifiedContext,
};
use serde::Serialize;
use serde_json::{Value, json};

const REGISTER_SERVER: &str = "mandate.credential.RegisterResourceServer";
const DISABLE_SERVER: &str = "mandate.credential.DisableResourceServer";
const ISSUE_REFERENCE: &str = "mandate.credential.IssueReferenceCredential";
const ISSUE_SELF_CONTAINED: &str = "mandate.credential.IssueSelfContainedCredential";
const INTROSPECT: &str = "mandate.credential.IntrospectCredential";
const REVOKE_CREDENTIAL: &str = "mandate.credential.RevokeAccessCredential";
const REGISTER_KEY: &str = "mandate.credential.RegisterSigningKey";
const RETIRE_KEY: &str = "mandate.credential.RetireSigningKey";
const REVOKE_KEY: &str = "mandate.credential.RevokeSigningKey";

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

//! `RegisterSigningKey`, `RetireSigningKey` and `RevokeSigningKey`.
//!
//! The three commands of the key record's lifecycle, which wave B's contract round added a
//! creator to: before `RegisterSigningKey` the contract declared a key that could be retired
//! and revoked and never recorded, so rotation — which "registers the successor and retires
//! the predecessor" — had nothing to register.
//!
//! Two things are decided here that nothing else can decide:
//!
//! - the entity invariant `window.not_before < window.expires_at`. Under ESS 0.59.0 the
//!   synthesizer builds an ordered window, and the contract's own accepted scenario is still
//!   refused before the window is read: it names the algorithm `"algorithm"`, which no
//!   deployment admits. These cases are the check, and they decide the window as *instants*:
//!   a byte comparison of the two declared forms is not their chronological order.
//! - that one piece of key material is never recorded under two identities, which is what
//!   makes a revocation record mean something after a restart.

use std::cell::Cell;
use std::rc::Rc;

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_FIXED, ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, UnparsedPublicKey,
};
use mandate_sts::keys::{
    KeyMaterialResolver, KeyProvider, RecordedSigner, RegisterSigningKey, RetireSigningKey,
    RevokeSigningKey, SigningKeyAdministration, admitted_for_verification, issuing_key,
    retire_signing_key, revoke_signing_key, signing_admitted,
};
use mandate_sts::{IdentityAllocator, RequestContext, SequentialAllocator};
use mandate_token::projection::{
    CredentialEvent, DenialClause, Projection, RefusedOutcome, SigningKeyState,
};
use mandate_token::signing_real::{
    AllowedAlgorithms, Clock, CredentialSigner, SigningError, SigningKeyMaterial, StandardClaims,
};
use mandate_types::{
    Audience, CorrelationId, CredentialId, DenialReason, Issuer, KeyReference, OrganizationId,
    PrincipalId, SigningAlgorithm, SigningKeyId, SigningKeyWindow, Timestamp, Uuid,
    VerifiedContext,
};
use serde_json::Value;

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
        correlation: CorrelationId::new("keys"),
    }
}

fn request() -> RequestContext {
    request_at("2026-09-19T00:00:00Z")
}

fn request_at(at: &str) -> RequestContext {
    RequestContext {
        correlation: CorrelationId::new("keys"),
        at: Timestamp::new(at),
        epochs: None,
    }
}

/// The deployment's configured allowlist. The names are the deployment's, not this crate's:
/// `services/sts/src` names none.
fn admitted() -> AllowedAlgorithms {
    AllowedAlgorithms::new(&[SigningAlgorithm::new("RS256")]).expect("a configured allowlist")
}

/// The material this deployment can resolve, by reference.
struct ResolvableKeys {
    held: Vec<(KeyReference, String)>,
}

impl ResolvableKeys {
    fn holding(references: &[(&str, &str)]) -> Self {
        Self {
            held: references
                .iter()
                .map(|(reference, thumbprint)| {
                    (KeyReference::new(*reference), (*thumbprint).to_owned())
                })
                .collect(),
        }
    }
}

impl KeyMaterialResolver for ResolvableKeys {
    fn thumbprint(&self, reference: &KeyReference) -> Option<String> {
        self.held
            .iter()
            .find(|(held, _)| held == reference)
            .map(|(_, thumbprint)| thumbprint.clone())
    }
}

fn registration(reference: &str, not_before: &str, expires_at: &str) -> RegisterSigningKey {
    RegisterSigningKey {
        context: context(),
        key_reference: KeyReference::new(reference),
        algorithm: SigningAlgorithm::new("RS256"),
        window: SigningKeyWindow {
            not_before: Timestamp::new(not_before),
            expires_at: Timestamp::new(expires_at),
        },
    }
}

fn material() -> ResolvableKeys {
    ResolvableKeys::holding(&[
        ("kms://one", "thumb-one"),
        ("kms://two", "thumb-two"),
        ("kms://one-again", "thumb-one"),
    ])
}

/// One registered key, folded.
fn recorded(
    reference: &str,
    held: &Projection,
    allocator: &mut SequentialAllocator,
) -> (CredentialEvent, SigningKeyId) {
    let outcome = SigningKeyAdministration::new(admitted())
        .register(
            &registration(reference, "2026-09-19T00:00:00Z", "2026-12-31T00:00:00Z"),
            held,
            &material(),
            allocator,
        )
        .expect("an admitted algorithm, a resolvable reference and an ordered window");
    (outcome.event, outcome.id)
}

#[test]
fn a_registration_responds_with_the_identity_and_the_thumbprint_it_resolved() {
    let mut allocator = SequentialAllocator::new();

    let outcome = SigningKeyAdministration::new(admitted())
        .register(
            &registration("kms://one", "2026-09-19T00:00:00Z", "2026-12-31T00:00:00Z"),
            &Projection::default(),
            &material(),
            &mut allocator,
        )
        .expect("an admitted algorithm, a resolvable reference and an ordered window");

    assert_eq!(outcome.thumbprint, "thumb-one");
    assert_eq!(
        outcome.event,
        CredentialEvent::SigningKeyRegistered {
            context: context(),
            id: outcome.id,
            key_reference: KeyReference::new("kms://one"),
            thumbprint: "thumb-one".to_owned(),
            algorithm: SigningAlgorithm::new("RS256"),
            window: SigningKeyWindow {
                not_before: Timestamp::new("2026-09-19T00:00:00Z"),
                expires_at: Timestamp::new("2026-12-31T00:00:00Z"),
            },
        }
    );

    let record = Projection::fold(&[outcome.event])
        .expect("one creation")
        .signing_key(&outcome.id)
        .expect("the key the event created");
    assert_eq!(record.state, SigningKeyState::Recorded);
    assert_eq!(record.thumbprint, "thumb-one");
}

/// The entity invariant. `not_before == expires_at` is the window ESS's synthesizer builds
/// for the accepted scenario, and it is refused here: a key that is never valid signs
/// nothing and verifies nothing.
#[test]
fn a_window_that_is_not_ordered_is_refused() {
    let mut allocator = SequentialAllocator::new();
    let administration = SigningKeyAdministration::new(admitted());

    for (not_before, expires_at) in [
        // Equal: the synthesized accepted scenario's own input.
        ("2026-09-19T00:00:00Z", "2026-09-19T00:00:00Z"),
        // Reversed.
        ("2026-12-31T00:00:00Z", "2026-09-19T00:00:00Z"),
        // Not a window at all: a value that names no instant cannot be shown to be before
        // another, and a comparison that cannot be made fails closed.
        ("whenever", "2026-12-31T00:00:00Z"),
        ("2026-09-19T00:00:00Z", "the end of time"),
    ] {
        let denied = administration
            .register(
                &registration("kms://one", not_before, expires_at),
                &Projection::default(),
                &material(),
                &mut allocator,
            )
            .err()
            .unwrap_or_else(|| panic!("{not_before} .. {expires_at} was admitted"));
        assert_eq!(denied.clause, DenialClause::KeyWindowNotOrdered);
        assert_eq!(denied.outcome, RefusedOutcome::Denied);
    }
}

/// The window is decided as instants and not as text: `02:00+03:00` is `23:00Z` the day
/// before, which is earlier than `00:30Z` — and sorts after it byte for byte.
#[test]
fn an_ordered_window_whose_text_sorts_the_other_way_is_admitted() {
    let mut allocator = SequentialAllocator::new();
    let not_before = "2026-09-19T02:00:00+03:00";
    let expires_at = "2026-09-19T00:30:00Z";
    assert!(
        not_before > expires_at,
        "the case is only worth making while the text sorts the other way"
    );

    let outcome = SigningKeyAdministration::new(admitted())
        .register(
            &registration("kms://one", not_before, expires_at),
            &Projection::default(),
            &material(),
            &mut allocator,
        )
        .expect("the window is ordered as instants");

    assert_eq!(outcome.thumbprint, "thumb-one");
}

#[test]
fn an_algorithm_outside_the_deployments_allowlist_is_refused() {
    let mut allocator = SequentialAllocator::new();
    let administration = SigningKeyAdministration::new(admitted());

    for algorithm in [
        // Admitted by the crate's table, not configured by this deployment.
        "ES256", // Admitted by nothing.
        "HS256", // A token needs a signature.
        "none",
    ] {
        let denied = administration
            .register(
                &RegisterSigningKey {
                    algorithm: SigningAlgorithm::new(algorithm),
                    ..registration("kms://one", "2026-09-19T00:00:00Z", "2026-12-31T00:00:00Z")
                },
                &Projection::default(),
                &material(),
                &mut allocator,
            )
            .err()
            .unwrap_or_else(|| panic!("{algorithm} was admitted"));
        assert_eq!(denied.clause, DenialClause::AlgorithmUnadmitted);
        assert_eq!(denied.outcome, RefusedOutcome::Denied);
    }
}

#[test]
fn an_unresolvable_key_reference_is_refused() {
    let mut allocator = SequentialAllocator::new();

    let denied = SigningKeyAdministration::new(admitted())
        .register(
            &registration(
                "kms://absent",
                "2026-09-19T00:00:00Z",
                "2026-12-31T00:00:00Z",
            ),
            &Projection::default(),
            &material(),
            &mut allocator,
        )
        .expect_err("the deployment resolves no material for that reference");

    assert_eq!(denied.clause, DenialClause::KeyReferenceUnresolvable);
}

/// "A key reference ... already held by a recorded key is refused in every state that key
/// can be in, including Retired and Revoked."
#[test]
fn a_key_reference_already_recorded_is_refused_in_every_state() {
    for terminal in [None, Some(false), Some(true)] {
        let mut allocator = SequentialAllocator::new();
        let (event, id) = recorded("kms://one", &Projection::default(), &mut allocator);
        let mut log = vec![event];
        match terminal {
            None => {}
            Some(false) => log.push(CredentialEvent::SigningKeyRetired {
                context: context(),
                id,
            }),
            Some(true) => log.push(CredentialEvent::SigningKeyRevoked {
                context: context(),
                id,
            }),
        }
        // A retirement needs an overlapping replacement, which the fold does not enforce —
        // it records what happened. The event is applied directly here for that reason.
        let held = Projection::fold(&log).expect("a creation and at most one move");

        let denied = SigningKeyAdministration::new(admitted())
            .register(
                &registration("kms://one", "2026-09-19T00:00:00Z", "2026-12-31T00:00:00Z"),
                &held,
                &material(),
                &mut allocator,
            )
            .expect_err("the reference is already recorded");

        assert_eq!(denied.clause, DenialClause::KeyReferenceRecorded);
    }
}

/// The other half: the same *material* under a new reference, which is what an operator
/// working through an incident will actually produce.
#[test]
fn the_same_material_under_a_second_reference_is_refused() {
    let mut allocator = SequentialAllocator::new();
    let (event, _) = recorded("kms://one", &Projection::default(), &mut allocator);
    let held = Projection::fold(&[event]).expect("one creation");

    let denied = SigningKeyAdministration::new(admitted())
        .register(
            &registration(
                "kms://one-again",
                "2026-09-19T00:00:00Z",
                "2026-12-31T00:00:00Z",
            ),
            &held,
            &material(),
            &mut allocator,
        )
        .expect_err("that material is already recorded, under another reference");

    assert_eq!(denied.clause, DenialClause::KeyMaterialRecorded);
}

/// Rotation: the successor is registered, then the predecessor is retired. A retirement with
/// no overlapping replacement is refused, which is why the two commands are in that order.
#[test]
fn a_retirement_needs_an_overlapping_replacement() {
    let mut allocator = SequentialAllocator::new();
    let (first, predecessor) = recorded("kms://one", &Projection::default(), &mut allocator);
    let held = Projection::fold(std::slice::from_ref(&first)).expect("one creation");

    let denied = retire_signing_key(
        &RetireSigningKey {
            id: predecessor,
            context: context(),
        },
        &held,
        &request(),
    )
    .expect_err("nothing else is published for continued verification");
    assert_eq!(denied.clause, DenialClause::NoReplacementKey);
    assert_eq!(denied.outcome, RefusedOutcome::Denied);

    let (second, _) = recorded("kms://two", &held, &mut allocator);
    let held = Projection::fold(&[first, second]).expect("two creations");

    let event = retire_signing_key(
        &RetireSigningKey {
            id: predecessor,
            context: context(),
        },
        &held,
        &request(),
    )
    .expect("the successor is published");
    assert_eq!(
        event,
        CredentialEvent::SigningKeyRetired {
            context: context(),
            id: predecessor,
        }
    );
}

/// A replacement outside its own validity window is not a replacement: nothing it signs is
/// admitted yet, and nothing it could verify was signed under it.
#[test]
fn a_replacement_outside_its_window_is_not_one() {
    let mut allocator = SequentialAllocator::new();
    let (first, predecessor) = recorded("kms://one", &Projection::default(), &mut allocator);
    let held = Projection::fold(std::slice::from_ref(&first)).expect("one creation");
    let successor = SigningKeyAdministration::new(admitted())
        .register(
            &registration("kms://two", "2027-01-01T00:00:00Z", "2027-06-30T00:00:00Z"),
            &held,
            &material(),
            &mut allocator,
        )
        .expect("a future window is a registerable one");
    let held = Projection::fold(&[first, successor.event]).expect("two creations");

    let denied = retire_signing_key(
        &RetireSigningKey {
            id: predecessor,
            context: context(),
        },
        &held,
        &request(),
    )
    .expect_err("the successor is not published yet");

    assert_eq!(denied.clause, DenialClause::NoReplacementKey);
}

#[test]
fn retiring_a_key_that_is_not_recorded_is_the_wrong_state_outcome() {
    let mut allocator = SequentialAllocator::new();
    let (first, predecessor) = recorded("kms://one", &Projection::default(), &mut allocator);
    let held = Projection::fold(std::slice::from_ref(&first)).expect("one creation");
    let (second, _) = recorded("kms://two", &held, &mut allocator);
    let held = Projection::fold(&[first.clone(), second.clone()]).expect("two creations");
    let retired = retire_signing_key(
        &RetireSigningKey {
            id: predecessor,
            context: context(),
        },
        &held,
        &request(),
    )
    .expect("the first retirement");
    let held = Projection::fold(&[first, second, retired]).expect("two creations and a move");

    let denied = retire_signing_key(
        &RetireSigningKey {
            id: predecessor,
            context: context(),
        },
        &held,
        &request(),
    )
    .expect_err("`retire` starts from `Recorded` alone");

    assert_eq!(denied.outcome, RefusedOutcome::WrongState);
    assert_eq!(denied.clause, DenialClause::KeyNotRecorded);
}

/// The emergency path starts from both non-terminal states and needs no replacement: a
/// compromised key is not published for anything.
#[test]
fn revocation_starts_from_recorded_and_from_retired() {
    let mut allocator = SequentialAllocator::new();
    let (first, predecessor) = recorded("kms://one", &Projection::default(), &mut allocator);
    let held = Projection::fold(std::slice::from_ref(&first)).expect("one creation");

    let event = revoke_signing_key(
        &RevokeSigningKey {
            id: predecessor,
            context: context(),
        },
        &held,
    )
    .expect("the emergency path needs no replacement");
    assert_eq!(
        event,
        CredentialEvent::SigningKeyRevoked {
            context: context(),
            id: predecessor,
        }
    );

    let (second, successor) = recorded("kms://two", &held, &mut allocator);
    let held = Projection::fold(&[first.clone(), second.clone()]).expect("two creations");
    let retired = retire_signing_key(
        &RetireSigningKey {
            id: predecessor,
            context: context(),
        },
        &held,
        &request(),
    )
    .expect("the retirement");
    let held = Projection::fold(&[first.clone(), second.clone(), retired.clone()])
        .expect("two creations and a move");

    assert!(
        revoke_signing_key(
            &RevokeSigningKey {
                id: predecessor,
                context: context(),
            },
            &held,
        )
        .is_ok(),
        "a retired key is revocable: `revoke` starts from `Recorded` and `Retired`"
    );
    let _ = successor;

    let revoked = revoke_signing_key(
        &RevokeSigningKey {
            id: predecessor,
            context: context(),
        },
        &held,
    )
    .expect("the first revocation");
    let held =
        Projection::fold(&[first, second, retired, revoked]).expect("two creations and two moves");

    let denied = revoke_signing_key(
        &RevokeSigningKey {
            id: predecessor,
            context: context(),
        },
        &held,
    )
    .expect_err("`revoke` starts from neither terminal state twice");
    assert_eq!(denied.outcome, RefusedOutcome::WrongState);
    assert_eq!(denied.clause, DenialClause::KeyNotRecorded);
}

#[test]
fn a_key_no_event_recorded_is_unresolved_for_both_moves() {
    let absent = SigningKeyId::new(uuid(0x99));

    let retired = retire_signing_key(
        &RetireSigningKey {
            id: absent,
            context: context(),
        },
        &Projection::default(),
        &request(),
    )
    .expect_err("no event recorded it");
    assert_eq!(retired.clause, DenialClause::KeyUnknown);
    assert_eq!(retired.reason, DenialReason::Denied);

    let revoked = revoke_signing_key(
        &RevokeSigningKey {
            id: absent,
            context: context(),
        },
        &Projection::default(),
    )
    .expect_err("no event recorded it");
    assert_eq!(revoked.clause, DenialClause::KeyUnknown);
}

/// A retirement decided against a reader that cannot be dated cannot show a replacement is
/// published, so it fails closed rather than retiring the key that is still signing.
#[test]
fn a_retirement_that_cannot_be_dated_is_refused() {
    let mut allocator = SequentialAllocator::new();
    let (first, predecessor) = recorded("kms://one", &Projection::default(), &mut allocator);
    let held = Projection::fold(std::slice::from_ref(&first)).expect("one creation");
    let (second, _) = recorded("kms://two", &held, &mut allocator);
    let held = Projection::fold(&[first, second]).expect("two creations");

    let denied = retire_signing_key(
        &RetireSigningKey {
            id: predecessor,
            context: context(),
        },
        &held,
        &request_at("whenever"),
    )
    .expect_err("a reader that cannot be dated cannot certify a replacement");

    assert_eq!(denied.reason, DenialReason::Unavailable);
    assert_eq!(denied.clause, DenialClause::NoReplacementKey);
}

/// The identities are minted by the allocator, from the response, and two registrations are
/// two keys.
#[test]
fn two_registrations_are_two_keys() {
    let mut allocator = SequentialAllocator::new();
    let (first, one) = recorded("kms://one", &Projection::default(), &mut allocator);
    let held = Projection::fold(std::slice::from_ref(&first)).expect("one creation");
    let (second, two) = recorded("kms://two", &held, &mut allocator);

    assert_ne!(one, two);
    assert_eq!(
        Projection::fold(&[first, second])
            .expect("two creations")
            .signing_keys()
            .len(),
        2
    );
    let _ = allocator.next_signing_key_id();
}

/// **What a key may do, in each state, at each instant.**
///
/// The two admissions are different questions and the contract says so:
/// `RetireSigningKey` — "a retired key signs nothing further; it remains admitted for
/// verifying credentials already issued under it until they expire"; `RevokeSigningKey` —
/// "a revoked key is admitted for neither issuance nor verification".
#[test]
fn signing_and_verification_are_admitted_in_the_states_the_contract_names() {
    let mut allocator = SequentialAllocator::new();
    let (registered, id) = recorded("kms://one", &Projection::default(), &mut allocator);
    let now = 1_789_776_000; // 2026-09-19T00:00:00Z, inside the key's window.

    let held = Projection::fold(std::slice::from_ref(&registered)).expect("one creation");
    let key = held.signing_key(&id).expect("the recorded key");
    assert!(signing_admitted(&key, now, &held));
    assert!(admitted_for_verification(&key, now, &held));

    // Retired: verification only, which is the whole of the rotation overlap.
    let retired = Projection::fold(&[
        registered.clone(),
        CredentialEvent::SigningKeyRetired {
            context: context(),
            id,
        },
    ])
    .expect("a creation and its move");
    let key = retired.signing_key(&id).expect("the retired key");
    assert!(!signing_admitted(&key, now, &retired));
    assert!(admitted_for_verification(&key, now, &retired));

    // Revoked: neither.
    let revoked = Projection::fold(&[
        registered,
        CredentialEvent::SigningKeyRevoked {
            context: context(),
            id,
        },
    ])
    .expect("a creation and its move");
    let key = revoked.signing_key(&id).expect("the revoked key");
    assert!(!signing_admitted(&key, now, &revoked));
    assert!(!admitted_for_verification(&key, now, &revoked));
}

/// Outside its own window a key does neither, at either end.
#[test]
fn a_key_outside_its_window_is_admitted_for_nothing() {
    let mut allocator = SequentialAllocator::new();
    let (registered, id) = recorded("kms://one", &Projection::default(), &mut allocator);
    let held = Projection::fold(std::slice::from_ref(&registered)).expect("one creation");
    let key = held.signing_key(&id).expect("the recorded key");

    // The window is 2026-09-19T00:00:00Z .. 2026-12-31T00:00:00Z.
    for (now, admitted, what) in [
        (1_789_775_999_i64, false, "one second before `not_before`"),
        (1_789_776_000, true, "at `not_before`"),
        (1_798_675_199, true, "one second before `expires_at`"),
        (1_798_675_200, false, "at `expires_at`"),
    ] {
        assert_eq!(
            signing_admitted(&key, now, &held),
            admitted,
            "signing {what}"
        );
        assert_eq!(
            admitted_for_verification(&key, now, &held),
            admitted,
            "verification {what}"
        );
    }
}

/// **A key that lost an index is admitted for neither.**
///
/// The write path refuses a second registration on one `key_reference`, and a pair of racing
/// writers can append one anyway — which the fold records rather than refusing the whole log
/// (`crates/mandate-token/tests/adversary_profiles_2.rs`). What keeps the material from
/// coming back under the second identity is this: the loser holds no index, so it signs
/// nothing and verifies nothing, whatever state it is in.
#[test]
fn a_key_that_holds_no_index_is_admitted_for_neither() {
    let mut allocator = SequentialAllocator::new();
    let (first, holder) = recorded("kms://one", &Projection::default(), &mut allocator);
    // The second writer's append: its own aggregate, a reference that was free when it read.
    let held = Projection::fold(&[
        first,
        CredentialEvent::SigningKeyRegistered {
            context: context(),
            id: SigningKeyId::new(uuid(0xf1)),
            key_reference: KeyReference::new("kms://one"),
            thumbprint: "thumb-two".to_owned(),
            algorithm: SigningAlgorithm::new("RS256"),
            window: SigningKeyWindow {
                not_before: Timestamp::new("2026-09-19T00:00:00Z"),
                expires_at: Timestamp::new("2026-12-31T00:00:00Z"),
            },
        },
    ])
    .expect("a duplicated index is a view, not a refusal");
    let now = 1_789_776_000;

    let loser = held
        .signing_key(&SigningKeyId::new(uuid(0xf1)))
        .expect("the second record exists");
    assert!(!signing_admitted(&loser, now, &held));
    assert!(!admitted_for_verification(&loser, now, &held));

    // And the holder is unaffected: the index is where it was.
    let key = held.signing_key(&holder).expect("the first record");
    assert!(signing_admitted(&key, now, &held));
    assert!(admitted_for_verification(&key, now, &held));

    // A retirement of the holder is refused, because the loser is no replacement.
    let denied = retire_signing_key(
        &RetireSigningKey {
            id: holder,
            context: context(),
        },
        &held,
        &request(),
    )
    .expect_err("a key that holds no index is not a published replacement");
    assert_eq!(denied.clause, DenialClause::NoReplacementKey);
}

// --- The signer the records drive: rotation and revocation over a published key set.
//
// `oidc-signed-tokens-and-key-rotation.md`, keys and JWKS half. Every key here is generated
// at test time; no private key byte is written down, and none leaves this process.

/// `2026-09-19T00:00:00Z`, the instant every key below opens at.
const OPENS: i64 = 1_789_776_000;
const TTL: u64 = 600;
const OVERLAP: u64 = 900;

/// A clock a case advances.
#[derive(Clone)]
struct Advancing(Rc<Cell<u64>>);

impl Clock for Advancing {
    fn now_unix(&self) -> u64 {
        self.0.get()
    }
}

fn es256() -> SigningAlgorithm {
    SigningAlgorithm::new("ES256")
}

/// Mounted material, by reference: PKCS#8 generated now.
struct Mounted(Vec<(KeyReference, Vec<u8>)>);

impl Mounted {
    fn with(references: &[&str]) -> Self {
        Self(
            references
                .iter()
                .map(|reference| {
                    let der = EcdsaKeyPair::generate_pkcs8(
                        &ECDSA_P256_SHA256_FIXED_SIGNING,
                        &SystemRandom::new(),
                    )
                    .expect("P-256 generation");
                    (KeyReference::new(*reference), der.as_ref().to_vec())
                })
                .collect(),
        )
    }
}

impl KeyProvider for Mounted {
    fn load(
        &self,
        reference: &KeyReference,
        kid: &str,
        algorithm: &SigningAlgorithm,
    ) -> Option<SigningKeyMaterial> {
        let (_, der) = self.0.iter().find(|(held, _)| held == reference)?;
        SigningKeyMaterial::from_der(kid, algorithm, der).ok()
    }
}

impl KeyMaterialResolver for Mounted {
    fn thumbprint(&self, reference: &KeyReference) -> Option<String> {
        self.load(reference, "thumbprint", &es256())
            .map(|material| material.thumbprint())
    }
}

fn register(
    reference: &str,
    held: &mut Vec<CredentialEvent>,
    mounted: &Mounted,
    allocator: &mut SequentialAllocator,
) -> SigningKeyId {
    let projection = Projection::fold(held).expect("a foldable history");
    let outcome = SigningKeyAdministration::new(
        AllowedAlgorithms::new(&[es256()]).expect("an admitted allowlist"),
    )
    .register(
        &RegisterSigningKey {
            context: context(),
            key_reference: KeyReference::new(reference),
            algorithm: es256(),
            window: SigningKeyWindow {
                not_before: Timestamp::new("2026-09-19T00:00:00Z"),
                expires_at: Timestamp::new("2026-12-31T00:00:00Z"),
            },
        },
        &projection,
        mounted,
        allocator,
    )
    .expect("a resolvable, unrecorded key");
    held.push(outcome.event);
    outcome.id
}

fn signer(clock: &Advancing) -> RecordedSigner<Advancing> {
    RecordedSigner::new(
        AllowedAlgorithms::new(&[es256()]).expect("an admitted allowlist"),
        clock.clone(),
        TTL,
        OVERLAP,
    )
    .expect("an overlap no shorter than the TTL")
}

fn sign(signer: &RecordedSigner<Advancing>, token_id: &str) -> (String, String) {
    let signed = signer
        .signer()
        .expect("a signer holding a key")
        .sign(
            &serde_json::json!({"scope": "document.read"}),
            &StandardClaims {
                issuer: Issuer::new("https://mandate.example"),
                subject: PrincipalId::new(uuid(0x51)),
                audience: Audience::new("api-a"),
                token_id: token_id.to_owned(),
            },
        )
        .expect("a token");
    (signed.token, signed.kid)
}

fn decode(text: &str) -> Vec<u8> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut bits = 0u32;
    let mut held = 0u32;
    let mut out = Vec::new();
    for byte in text.bytes() {
        let value = ALPHABET
            .iter()
            .position(|candidate| *candidate == byte)
            .expect("base64url");
        bits = (bits << 6) | u32::try_from(value).expect("six bits");
        held += 6;
        if held >= 8 {
            held -= 8;
            out.push(u8::try_from((bits >> held) & 0xff).expect("one byte"));
        }
    }
    out
}

fn member<'a>(key: &'a Value, name: &str) -> &'a str {
    key[name].as_str().unwrap_or_default()
}

/// Whether `token` verifies under a key of `published`, found by its header's `kid`.
fn verifies(token: &str, published: &[Value]) -> bool {
    let mut parts = token.split('.');
    let (Some(header), Some(claims), Some(signature)) = (parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    let header: Value = serde_json::from_slice(&decode(header)).expect("a JSON header");
    let Some(key) = published.iter().find(|key| key["kid"] == header["kid"]) else {
        return false;
    };
    let mut point = vec![0x04];
    point.extend(decode(member(key, "x")));
    point.extend(decode(member(key, "y")));
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, point)
        .verify(
            format!(
                "{header}.{claims}",
                header = token.split('.').next().unwrap_or_default()
            )
            .as_bytes(),
            &decode(signature),
        )
        .is_ok()
}

fn kids(published: &[Value]) -> Vec<String> {
    published
        .iter()
        .map(|key| member(key, "kid").to_owned())
        .collect()
}

#[test]
fn rotation_keeps_old_tokens_valid() {
    let clock = Advancing(Rc::new(Cell::new(
        u64::try_from(OPENS).expect("positive") + 60,
    )));
    let mounted = Mounted::with(&["secret/signing/first", "secret/signing/second"]);
    let mut allocator = SequentialAllocator::new();
    let mut history = Vec::new();
    let mut signer = signer(&clock);

    let first = register(
        "secret/signing/first",
        &mut history,
        &mounted,
        &mut allocator,
    );
    let now = || i64::try_from(clock.0.get()).expect("an instant");
    let folded = |history: &[CredentialEvent]| Projection::fold(history).expect("folds");
    signer
        .sync(&folded(&history), &mounted, now())
        .expect("the first key installs");
    let (old_token, old_kid) = sign(&signer, "before-rotation");
    assert_eq!(
        old_kid,
        first.to_string(),
        "the kid is the record's identity"
    );

    // The next key is mounted and registered: it opens with the first, and is newer by
    // registration, so issuance moves to it.
    clock.0.set(clock.0.get() + 60);
    let second = register(
        "secret/signing/second",
        &mut history,
        &mounted,
        &mut allocator,
    );
    assert_eq!(
        issuing_key(&folded(&history), now()).map(|key| key.id),
        Some(second)
    );
    signer
        .sync(&folded(&history), &mounted, now())
        .expect("the rotation installs");

    let (new_token, new_kid) = sign(&signer, "after-rotation");
    assert_eq!(new_kid, second.to_string(), "new tokens carry the new kid");
    let published = signer.published_keys(&folded(&history), now());
    assert_eq!(
        kids(&published),
        vec![second.to_string(), first.to_string()],
        "the key set lists both"
    );
    assert!(
        verifies(&old_token, &published),
        "a token signed by the previous key verifies"
    );
    assert!(verifies(&new_token, &published));

    // Until the overlap ends, and not after.
    clock.0.set(clock.0.get() + OVERLAP);
    let published = signer.published_keys(&folded(&history), now());
    assert!(verifies(&old_token, &published), "inside the overlap");
    clock.0.set(clock.0.get() + 2);
    let published = signer.published_keys(&folded(&history), now());
    assert_eq!(kids(&published), vec![second.to_string()]);
    assert!(!verifies(&old_token, &published), "the overlap has ended");
}

#[test]
fn revocation_removes_key_at_once() {
    let clock = Advancing(Rc::new(Cell::new(
        u64::try_from(OPENS).expect("positive") + 60,
    )));
    let mounted = Mounted::with(&["secret/signing/first", "secret/signing/second"]);
    let mut allocator = SequentialAllocator::new();
    let mut history = Vec::new();
    let mut signer = signer(&clock);
    let now = || i64::try_from(clock.0.get()).expect("an instant");
    let folded = |history: &[CredentialEvent]| Projection::fold(history).expect("folds");

    let first = register(
        "secret/signing/first",
        &mut history,
        &mounted,
        &mut allocator,
    );
    signer
        .sync(&folded(&history), &mounted, now())
        .expect("the first key installs");
    let second = register(
        "secret/signing/second",
        &mut history,
        &mounted,
        &mut allocator,
    );
    signer
        .sync(&folded(&history), &mounted, now())
        .expect("the rotation installs");
    let (token, _) = sign(&signer, "under-the-second");
    assert_eq!(
        kids(&signer.published_keys(&folded(&history), now())),
        vec![second.to_string(), first.to_string()]
    );

    // The emergency path: the active key is revoked. The very next read of the key set
    // no longer carries it — no clock advance, no overlap.
    let revoked = revoke_signing_key(
        &RevokeSigningKey {
            id: second,
            context: context(),
        },
        &folded(&history),
    )
    .expect("a recorded key can be revoked");
    history.push(revoked);
    let published = signer.published_keys(&folded(&history), now());
    assert_eq!(
        kids(&published),
        vec![first.to_string()],
        "gone on the next read"
    );
    assert!(!verifies(&token, &published));

    // And the signer follows: it signs under nothing the records do not admit.
    signer
        .sync(&folded(&history), &mounted, now())
        .expect("the revocation applies");
    let (after, kid) = sign(&signer, "after-revocation");
    assert_eq!(
        kid,
        first.to_string(),
        "issuance falls back to the key the records still admit"
    );
    let held = signer.signer().expect("a signer");
    assert_eq!(
        held.revoked()
            .iter()
            .map(|key| key.kid.clone())
            .collect::<Vec<_>>(),
        vec![second.to_string()],
        "the revoked key is refused for good"
    );
    let published = signer.published_keys(&folded(&history), now());
    assert_eq!(kids(&published), vec![first.to_string()]);
    assert!(verifies(&after, &published));
    assert!(!verifies(&token, &published));
    assert!(signer.ready(&folded(&history), now()));
}

#[test]
fn a_signer_built_after_a_restart_refuses_revoked_material() {
    let clock = Advancing(Rc::new(Cell::new(
        u64::try_from(OPENS).expect("positive") + 60,
    )));
    let mounted = Mounted::with(&["secret/signing/first", "secret/signing/second"]);
    let mut allocator = SequentialAllocator::new();
    let mut history = Vec::new();
    let now = || i64::try_from(clock.0.get()).expect("an instant");
    let first = register(
        "secret/signing/first",
        &mut history,
        &mounted,
        &mut allocator,
    );
    let second = register(
        "secret/signing/second",
        &mut history,
        &mounted,
        &mut allocator,
    );
    history.push(
        revoke_signing_key(
            &RevokeSigningKey {
                id: first,
                context: context(),
            },
            &Projection::fold(&history).expect("folds"),
        )
        .expect("revocable"),
    );

    // A fresh process over the same records: the signer is rehydrated with the
    // revocation, so the revoked material is refused under any `kid`.
    let mut restarted = signer(&clock);
    let projection = Projection::fold(&history).expect("folds");
    restarted
        .sync(&projection, &mounted, now())
        .expect("the surviving key installs");
    let held = restarted.signer().expect("a signer");
    assert_eq!(held.active_kid(), Some(second.to_string().as_str()));
    assert_eq!(
        held.revoked()
            .iter()
            .map(|key| key.kid.clone())
            .collect::<Vec<_>>(),
        vec![first.to_string()]
    );
    let mut probe = held.clone();
    let again = mounted
        .load(
            &KeyReference::new("secret/signing/first"),
            "a-new-name",
            &es256(),
        )
        .expect("material");
    assert!(matches!(
        probe.rotate(again),
        Err(SigningError::RevokedKey(_))
    ));
    assert!(restarted.ready(&projection, now()));
}

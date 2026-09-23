//! Adversary pass 2 — `story:sts-refusal-draws-nothing`, against the correction that made
//! a reservation hold (`5f28245`).
//!
//! - [`a_release_after_an_overtaking_draw_leaves_the_released_identity_a_gap`] — the trait
//!   says a release "leaves the allocator where it was before the reservation"
//!   (`services/sts/src/lib.rs:204-205`) and gives the identity back "as if it had never been
//!   reserved" (`lib.rs:218-219`). `SequentialAllocator::next_credential_id` skips the held
//!   ordinal (`lib.rs:291-294`) and the release does not undo the skip (`lib.rs:323-325`),
//!   so the released identity is never handed out and the sequence is not the one an
//!   allocator that was never reserved would produce. Ruled by the coordinator after
//!   correction round 2: restoring is unsatisfiable, the released id stays a gap; pins it.
//! - [`a_draw_with_the_last_ordinal_held_exhausts_as_a_plain_allocator_does`] — the skip
//!   added a second increment (`lib.rs:293`); with 254 drawn and 255 held, the next draw
//!   overflows `u8`. Ruled by the coordinator after correction round 2: that draw asks for
//!   identity 256, the plain allocator's own exhaustion point; pins that it panics alike.
//! - [`a_signer_that_unwinds_leaves_its_reservation_held`] — the only reserve site
//!   (`services/sts/src/issue.rs:429-445`) ends the reservation on `Ok` and on `Err`, but not
//!   on an unwind out of `sign_credential`; the next issuance through the same allocator then
//!   panics in `reserve_credential_id` (`lib.rs:302-306`). Ruled decided behaviour by the
//!   coordinator (correction round 2, F3); pins it.
//! - [`a_second_issuance_after_a_refusal_and_an_acceptance_signs_distinct_identities`] —
//!   refuse, accept, accept through one allocator: every signed `jti` distinct. Green probe.

use std::cell::Cell;
use std::panic::{AssertUnwindSafe, catch_unwind};

use mandate_sts::issue::{
    IssuanceSigner, IssueSelfContainedCredential, SelfContainedParts, Sha256Digest,
    issue_self_contained_credential,
};
use mandate_sts::registry::{RegisterResourceServer, register_resource_server};
use mandate_sts::{IdentityAllocator, RequestContext, SequentialAllocator};
use mandate_token::projection::Projection;
use mandate_token::signing_real::{SignedCredential, SigningError, StandardClaims};
use mandate_token::{CredentialDescriptor, CredentialProfile};
use mandate_types::{
    Audience, AuthorityScope, CorrelationId, CredentialId, CredentialKind, Duration,
    EpochSnapshotRef, Issuer, OrganizationId, PrincipalId, ResourceServerId, RevocationGuarantee,
    Timestamp, Uuid, VerifiedContext,
};

fn uuid(tag: u8) -> Uuid {
    Uuid::from_bytes([tag; 16])
}

/// The message a caught panic carries, whichever of the two payload types it has.
fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    payload
        .downcast_ref::<&str>()
        .map(|message| (*message).to_owned())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_default()
}

/// **A release after a draw overtook the reservation leaves the released identity a gap:
/// the draws go on past it, it is never handed out, and nothing is handed out twice.**
///
/// Built: `issue_self_contained_credential` holds `&mut` from reserve to release, so nothing
/// in-process draws between them.
///
/// Decided (coordinator ruling after correction round 2): a released id after an overtaking
/// draw stays a gap. Restoring the allocator is unsatisfiable together with
/// `adversary_draws_nothing_1::a_reservation_a_draw_overtook_is_not_signed_into_a_second_credential`,
/// and `IdentityAllocator::release_credential_id` says so.
#[test]
fn a_release_after_an_overtaking_draw_leaves_the_released_identity_a_gap() {
    let mut never_reserved = SequentialAllocator::new();
    let one = never_reserved.next_credential_id();
    let two = never_reserved.next_credential_id();
    let three = never_reserved.next_credential_id();
    let four = never_reserved.next_credential_id();

    let mut allocator = SequentialAllocator::new();
    let reserved = allocator.reserve_credential_id();
    let first = allocator.next_credential_id();
    allocator.release_credential_id(reserved);
    let second = allocator.next_credential_id();
    let third = allocator.next_credential_id();

    assert_eq!(reserved, one, "the reservation holds #1");
    assert_eq!(
        (first, second, third),
        (two, three, four),
        "the draws go on past the released #1: #2 overtook it, then #3 and #4"
    );
    assert!(
        ![first, second, third].contains(&reserved),
        "the released identity {reserved} was handed out"
    );
}

/// **With 254 drawn and 255 held, the next draw exhausts exactly where, and exactly as, a
/// plain allocator whose 255 ordinals are all drawn does.**
///
/// Built: needs a draw while a reservation is held, which no caller makes.
///
/// Decided (coordinator ruling after correction round 2): a held ordinal is in use, so this
/// draw asks for identity 256 of a fixture that has 255 — the plain allocator's own
/// exhaustion point, with its own panic.
#[test]
fn a_draw_with_the_last_ordinal_held_exhausts_as_a_plain_allocator_does() {
    let mut plain = SequentialAllocator::new();
    for _ in 0..255 {
        plain.next_credential_id();
    }
    let plain_exhausted = catch_unwind(AssertUnwindSafe(|| plain.next_credential_id()))
        .expect_err("a plain allocator with all 255 ordinals drawn is exhausted");

    let mut allocator = SequentialAllocator::new();
    for _ in 0..254 {
        allocator.next_credential_id();
    }
    let reserved = allocator.reserve_credential_id();
    let held_exhausted = catch_unwind(AssertUnwindSafe(|| allocator.next_credential_id()))
        .expect_err("with 254 drawn and 255 held, all 255 ordinals are in use");

    let mut last = SequentialAllocator::new();
    for _ in 0..254 {
        last.next_credential_id();
    }
    assert_eq!(
        reserved,
        last.next_credential_id(),
        "the reservation holds ordinal 255"
    );
    assert_eq!(
        panic_message(held_exhausted.as_ref()),
        "attempt to add with overflow",
        "the draw with the last ordinal held exhausts with the plain draw's own panic"
    );
    assert_eq!(
        panic_message(held_exhausted.as_ref()),
        panic_message(plain_exhausted.as_ref()),
        "the two exhaustions panic alike"
    );
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
        correlation: CorrelationId::new("adversary-draws-2"),
    }
}

fn request() -> RequestContext {
    RequestContext {
        correlation: CorrelationId::new("adversary-draws-2"),
        at: Timestamp::new("2026-09-19T00:00:00Z"),
        epochs: Some(EpochSnapshotRef::new(uuid(0x60))),
    }
}

fn servers() -> (Projection, ResourceServerId) {
    let outcome = register_resource_server(
        &RegisterResourceServer {
            context: context(),
            audience: Audience::new("api-a"),
            profile: CredentialProfile {
                name: "self-contained".to_owned(),
                kind: CredentialKind::SelfContained,
                revocation: RevocationGuarantee::BoundedOffline,
                max_ttl: Duration::new("PT15M"),
                positive_cache_ttl: Duration::new("PT0S"),
                requires_online_authorization: false,
            },
            allowed_exchange_sources: Vec::new(),
        },
        &Projection::default(),
        &mut SequentialAllocator::new(),
    )
    .expect("a free audience in the caller's own organization");
    let id = outcome.resource_server_id;
    (
        Projection::fold(&[outcome.event]).expect("one creation"),
        id,
    )
}

/// A signer that refuses, unwinds, or signs, as told, and remembers every `jti` it signed.
struct Scripted {
    mode: Cell<u8>,
    signed: std::cell::RefCell<Vec<String>>,
}

const REFUSE: u8 = 0;
const UNWIND: u8 = 1;
const SIGN: u8 = 2;

impl IssuanceSigner for Scripted {
    fn ttl_seconds(&self) -> u64 {
        600
    }

    fn sign_credential(
        &self,
        _descriptor: &CredentialDescriptor,
        claims: &StandardClaims,
    ) -> Result<SignedCredential, SigningError> {
        match self.mode.get() {
            REFUSE => Err(SigningError::NoActiveKey),
            UNWIND => panic!("the signer's backend panicked"),
            _ => {
                self.signed.borrow_mut().push(claims.token_id.clone());
                Ok(SignedCredential {
                    token: format!("token-{}", claims.token_id),
                    kid: "kid-1".to_owned(),
                })
            }
        }
    }
}

fn issue(
    allocator: &mut SequentialAllocator,
    servers: &Projection,
    target: ResourceServerId,
    signer: &Scripted,
) -> bool {
    issue_self_contained_credential(
        &IssueSelfContainedCredential {
            context: context(),
            target,
            requested_scope: AuthorityScope {
                actions: Vec::new(),
                resources: Vec::new(),
                space: None,
            },
        },
        &request(),
        servers,
        SelfContainedParts {
            digest: &Sha256Digest,
            allocator,
            signer,
            issuer: &Issuer::new("https://sts.example"),
        },
    )
    .is_ok()
}

/// **A signer that unwinds leaves its reservation held, and the next reservation through
/// the same allocator is refused.**
///
/// Built: nothing in the tree catches an unwind out of an issuance and reuses the allocator.
///
/// Decided behaviour, not a defect (coordinator, correction round 2, F3): no guard ends a
/// reservation on an unwind, because nothing in the tree catches one and the deployment's
/// allocator keeps no state; `IdentityAllocator::reserve_credential_id` and
/// `issue_self_contained_credential` say so. This pins it.
#[test]
fn a_signer_that_unwinds_leaves_its_reservation_held() {
    let (servers, target) = servers();
    let mut allocator = SequentialAllocator::new();
    let signer = Scripted {
        mode: Cell::new(UNWIND),
        signed: std::cell::RefCell::new(Vec::new()),
    };
    let unwound = catch_unwind(AssertUnwindSafe(|| {
        issue(&mut allocator, &servers, target, &signer)
    }));
    assert!(unwound.is_err(), "the scripted signer unwinds");

    signer.mode.set(SIGN);
    let next = catch_unwind(AssertUnwindSafe(|| {
        issue(&mut allocator, &servers, target, &signer)
    }));
    let payload = next.expect_err(
        "the issuance after an unwound signer reserves again while the unwound reservation is \
         still held, and the fixture refuses a second reservation",
    );
    let message = payload
        .downcast_ref::<&str>()
        .map(|message| (*message).to_owned())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_default();
    assert_eq!(
        message, "a credential identity is already reserved",
        "the next reservation is refused by the one the unwind left held"
    );
    assert!(
        signer.signed.borrow().is_empty(),
        "nothing was signed after the unwind"
    );
}

/// **Refuse, accept, accept through one allocator: every signed identity is distinct.**
#[test]
fn a_second_issuance_after_a_refusal_and_an_acceptance_signs_distinct_identities() {
    let (servers, target) = servers();
    let mut allocator = SequentialAllocator::new();
    let signer = Scripted {
        mode: Cell::new(REFUSE),
        signed: std::cell::RefCell::new(Vec::new()),
    };
    assert!(!issue(&mut allocator, &servers, target, &signer));
    signer.mode.set(SIGN);
    assert!(issue(&mut allocator, &servers, target, &signer));
    assert!(issue(&mut allocator, &servers, target, &signer));
    let drawn = allocator.next_credential_id().to_string();

    let mut all = signer.signed.borrow().clone();
    all.push(drawn);
    let mut unique = all.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(unique.len(), all.len(), "{all:?}");
    assert_eq!(
        all[0],
        SequentialAllocator::new().next_credential_id().to_string(),
        "the refusal consumed an identity"
    );
}

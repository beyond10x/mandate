//! Adversary pass 2 — `story:sts-refusal-draws-nothing`, against the correction that made
//! a reservation hold (`5f28245`).
//!
//! - [`a_release_after_an_overtaking_draw_leaves_the_allocator_where_it_was`] — the trait
//!   says a release "leaves the allocator where it was before the reservation"
//!   (`services/sts/src/lib.rs:204-205`) and gives the identity back "as if it had never been
//!   reserved" (`lib.rs:218-219`). `SequentialAllocator::next_credential_id` skips the held
//!   ordinal (`lib.rs:291-294`) and the release does not undo the skip (`lib.rs:323-325`),
//!   so the released identity is never handed out and the sequence is not the one an
//!   allocator that was never reserved would produce.
//! - [`a_draw_that_skips_the_last_ordinal_does_not_overflow`] — the skip adds a second
//!   increment (`lib.rs:293`); with 254 drawn and 255 held, the next draw overflows `u8`,
//!   where the same draw without the reservation returns ordinal 255.
//! - [`a_signer_that_unwinds_leaves_no_reservation_behind`] — the only reserve site
//!   (`services/sts/src/issue.rs:429-445`) ends the reservation on `Ok` and on `Err`, but not
//!   on an unwind out of `sign_credential`; the next issuance through the same allocator then
//!   panics in `reserve_credential_id` (`lib.rs:302-306`).
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

/// **A release after a draw overtook the reservation leaves the allocator where it was.**
///
/// Built: `issue_self_contained_credential` holds `&mut` from reserve to release, so nothing
/// in-process draws between them.
#[test]
fn a_release_after_an_overtaking_draw_leaves_the_allocator_where_it_was() {
    let mut never_reserved = SequentialAllocator::new();
    let expected = (
        never_reserved.next_credential_id(),
        never_reserved.next_credential_id(),
    );

    let mut allocator = SequentialAllocator::new();
    let reserved = allocator.reserve_credential_id();
    let first = allocator.next_credential_id();
    allocator.release_credential_id(reserved);
    let second = allocator.next_credential_id();

    assert_eq!(
        (first, second),
        expected,
        "the released identity {reserved} was never handed out: the skip the reservation \
         caused survived the release"
    );
}

/// **The skip past a held ordinal does not overflow at the last ordinal.**
///
/// Built: needs a draw while a reservation is held, which no caller makes.
#[test]
fn a_draw_that_skips_the_last_ordinal_does_not_overflow() {
    let mut allocator = SequentialAllocator::new();
    for _ in 0..254 {
        allocator.next_credential_id();
    }
    let reserved = allocator.reserve_credential_id();
    let drawn = catch_unwind(AssertUnwindSafe(|| allocator.next_credential_id()));

    assert!(
        drawn.is_ok(),
        "with 254 drawn and ordinal 255 held ({reserved}), the draw that skips it panicked"
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

/// **An issuance after a signer unwound is not refused by a reservation nobody holds.**
///
/// Built: nothing in the tree catches an unwind out of an issuance and reuses the allocator.
#[test]
fn a_signer_that_unwinds_leaves_no_reservation_behind() {
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
    assert!(
        matches!(next, Ok(true)),
        "the issuance after an unwound signer panicked on the reservation the unwind left held"
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

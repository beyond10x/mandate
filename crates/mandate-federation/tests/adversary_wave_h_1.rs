//! Adversary pass 1 against `story:link-absent-discriminates` (`e9f69cf`).
//!
//! The unit's claim is that `ProvisionExternalPrincipal` now refuses `ExternalKeyExists`
//! for a key **any** record holds in any lifecycle state, and that the mechanism — the
//! key's holder being the smallest `Linked` record on it, falling back to the smallest
//! record in any state — leaves `authenticate_federation`, `LinkConflict` and
//! `Projection::conflicts` bit-for-bit unchanged.
//!
//! Two attacks on that. The first held. The second did not, and the correction it forced
//! moved both halves of that mechanism out of `Projection` and into `LinkStore` itself:
//! an implementor answers `LinkStore::records_on_key` and this crate derives the holder
//! and the key-is-held decision from it. The second case below asserts the contract that
//! replaced the hole it found; the first is unchanged.

use mandate_federation::authenticate::{
    AuthenticateFederation, ProvisionExternalPrincipal, authenticate_federation,
    provision_external_principal,
};
use mandate_federation::link::{LinkExternalPrincipal, link_external_principal};
use mandate_federation::record::{
    ExternalKey, ExternalPrincipal, FederationEvent, LinkState, Projection,
};
use mandate_federation::verifier::{ConstructedVerifier, VerifiedProof};
use mandate_federation::{
    DenialClause, LinkResolution, LinkStore, PrincipalState, PrincipalStore, RecordedPrincipals,
    RecordingSessionIssuer, RequestContext, SequentialAllocator,
};
use mandate_model::TenantResolutionRule;
use mandate_types::value::Uuid;
use mandate_types::{
    Audience, ClientId, CorrelationId, CredentialId, CredentialProof, DenialReason,
    ExternalLinkMethod, ExternalPrincipalId, ExternalSubject, FederationConnectionId, Issuer,
    OrganizationId, PrincipalId, SigningAlgorithm, Timestamp, VerifiedContext,
};

const ISSUER: &str = "https://idp.example/one";
const CLIENT: &str = "configured-client";
const SUBJECT: &str = "subject-one";

fn uuid(tag: u8) -> Uuid {
    Uuid::from_bytes([tag; 16])
}

fn organization(tag: u8) -> OrganizationId {
    OrganizationId::new(uuid(tag))
}

fn connection(tag: u8) -> FederationConnectionId {
    FederationConnectionId::new(uuid(tag))
}

fn principal(tag: u8) -> PrincipalId {
    PrincipalId::new(uuid(tag))
}

fn external_principal(tag: u8) -> ExternalPrincipalId {
    ExternalPrincipalId::new(uuid(tag))
}

fn linked_at() -> Timestamp {
    Timestamp::new("2026-09-18T00:00:00Z")
}

fn context(organization_id: OrganizationId) -> VerifiedContext {
    VerifiedContext {
        subject: principal(0x51),
        actor: None,
        organization: organization_id,
        audience: Audience::new("mandate"),
        credential: CredentialId::new(uuid(0xcd)),
        delegation: None,
        execution: None,
        correlation: CorrelationId::new("adversary-wave-h-1"),
    }
}

fn unconditional(organization_id: OrganizationId) -> TenantResolutionRule {
    TenantResolutionRule {
        configured_organization: organization_id,
        verified_claim_name: None,
        verified_claim_value: None,
    }
}

fn request() -> RequestContext {
    RequestContext {
        audience: Audience::new("mandate"),
        correlation: CorrelationId::new("adversary-wave-h-1"),
        credential: CredentialId::new(uuid(0xcd)),
        at: linked_at(),
    }
}

fn presented() -> CredentialProof {
    CredentialProof::from_bytes(b"proof-material-marker".to_vec())
}

fn admitting() -> ConstructedVerifier {
    ConstructedVerifier::admitting(
        &[SigningAlgorithm::new("configured-by-deployment")],
        VerifiedProof::new(
            Issuer::new(ISSUER),
            ExternalSubject::new(SUBJECT),
            ClientId::new(CLIENT),
        ),
    )
    .expect("a non-empty allowlist is admitted")
}

fn created() -> FederationEvent {
    FederationEvent::FederationConnectionCreated {
        context: context(organization(10)),
        connection_id: connection(1),
        issuer: Issuer::new(ISSUER),
        client_id: ClientId::new(CLIENT),
        tenant_resolution: unconditional(organization(10)),
        jit_provisioning: true,
    }
}

fn linked(id: ExternalPrincipalId, principal_id: PrincipalId) -> FederationEvent {
    FederationEvent::ExternalPrincipalLinked {
        context: context(organization(10)),
        connection_id: connection(1),
        principal_id,
        external_principal_id: id,
        subject: ExternalSubject::new(SUBJECT),
        link_method: ExternalLinkMethod::Administrator,
        linked_at: linked_at(),
    }
}

fn unlinked(id: ExternalPrincipalId) -> FederationEvent {
    FederationEvent::ExternalPrincipalUnlinked {
        context: context(organization(10)),
        id,
    }
}

fn key() -> ExternalKey {
    ExternalKey {
        organization_id: organization(10),
        issuer: Issuer::new(ISSUER),
        subject: ExternalSubject::new(SUBJECT),
    }
}

/// The three records the cases build on one key, smallest identity first.
const RECORDS: [(u8, u8); 3] = [(0x71, 0x21), (0x72, 0x22), (0x73, 0x23)];

/// Every mix of lifecycle states on one key answers the same way in every append order,
/// and `authenticate_federation`, `LinkConflict` and `conflicts()` answer what they
/// answered before the fallback existed.
///
/// `e9f69cf` says ordering is the fault line: deleting the `Linked` filter from
/// `Projection::link` outright made a key with a smaller revoked record and a larger
/// linked one resolve to the revoked one, so `authenticate_federation` denied
/// `LinkAbsent` to a validly linked principal and `LinkConflict` stopped firing.
/// `tests/replay.rs` covers exactly two records with exactly one unlink, in the two
/// interleavings of one race. This case covers all eight state masks over three records
/// on one key, in eight append orders each, and pins the four answers against a reference
/// that is stated, not read off the implementation:
///
/// - the key resolves to the smallest `Linked` record on it, and to the smallest record
///   of any state only when the key has no `Linked` one;
/// - `authenticate_federation` issues a session exactly when the key has a `Linked`
///   record, for that record's principal, and denies `LinkAbsent` otherwise;
/// - `link_external_principal` refuses `LinkConflict` exactly when the key has a `Linked`
///   record;
/// - `conflicts()` is every `Linked` record on the key but the smallest;
/// - `provision_external_principal` refuses `ExternalKeyExists` in every one of them,
///   because every one of them has a record on the key.
#[test]
fn every_state_mask_and_append_order_on_one_key_answers_alike() {
    let verifier = admitting();

    for mask in 0_u8..8 {
        let live_ids: Vec<ExternalPrincipalId> = RECORDS
            .iter()
            .enumerate()
            .filter(|(index, _)| mask & (1 << index) == 0)
            .map(|(_, (id, _))| external_principal(*id))
            .collect();

        // The reference: stated by the story, not read off `Projection::link`.
        let holder = live_ids
            .first()
            .copied()
            .or_else(|| RECORDS.first().map(|(id, _)| external_principal(*id)));
        let session_principal = live_ids.first().map(|id| {
            let tag = RECORDS
                .iter()
                .find(|(record, _)| external_principal(*record) == *id)
                .expect("the identity is one of the three")
                .1;
            principal(tag)
        });
        let expected_conflicts: Vec<ExternalPrincipalId> =
            live_ids.iter().skip(1).copied().collect();

        for order in orders(mask) {
            let mut log = vec![created()];
            log.extend(order.clone());
            let projection = Projection::fold(&log).unwrap_or_else(|error| {
                panic!("mask {mask:#05b}: a log the handlers accepted rebuilds: {error:?}")
            });

            assert_eq!(
                projection.link(&key()).map(|held| held.id),
                holder,
                "mask {mask:#05b}: the key resolves to the smallest `Linked` record, and \
                 to the smallest record of any state only when it has none"
            );

            let principals = RecordedPrincipals::over(projection.clone())
                .with_principal(principal(0x21), organization(10), PrincipalState::Active)
                .with_principal(principal(0x22), organization(10), PrincipalState::Active)
                .with_principal(principal(0x23), organization(10), PrincipalState::Active)
                .with_principal(principal(0x24), organization(10), PrincipalState::Active);
            let mut sessions = RecordingSessionIssuer::new();
            let authenticated = authenticate_federation(
                &AuthenticateFederation {
                    connection_id: connection(1),
                    proof: presented(),
                },
                &request(),
                &verifier,
                &principals,
                &principals,
                &mut sessions,
            );
            match (session_principal, authenticated) {
                (Some(expected), Ok(login)) => assert_eq!(
                    login.principal_id, expected,
                    "mask {mask:#05b}: the session is issued for the record that holds the key"
                ),
                (None, Err(denied)) => {
                    assert_eq!(denied.reason, DenialReason::Denied, "mask {mask:#05b}");
                    assert_eq!(
                        denied.clause,
                        DenialClause::LinkAbsent,
                        "mask {mask:#05b}: no `Linked` record on the key"
                    );
                    assert!(
                        sessions.issued().is_empty(),
                        "mask {mask:#05b}: no session was issued"
                    );
                }
                (expected, actual) => panic!(
                    "mask {mask:#05b}: authenticate_federation answered {actual:?} where the \
                     key's `Linked` holder is {expected:?}"
                ),
            }

            let mut allocator = SequentialAllocator::new();
            let relinked = link_external_principal(
                &LinkExternalPrincipal {
                    context: context(organization(10)),
                    connection_id: connection(1),
                    external_subject: ExternalSubject::new(SUBJECT),
                    principal_id: principal(0x24),
                    method: ExternalLinkMethod::Administrator,
                },
                &request(),
                &principals,
                &principals,
                &mut allocator,
            );
            match (session_principal.is_some(), relinked) {
                (true, Err(denied)) => assert_eq!(
                    denied.clause,
                    DenialClause::LinkConflict,
                    "mask {mask:#05b}: a `Linked` record on the key is a conflicting link"
                ),
                (false, Ok(_)) => {}
                (conflicting, actual) => panic!(
                    "mask {mask:#05b}: link_external_principal answered {actual:?} where the \
                     key holds a `Linked` record: {conflicting}"
                ),
            }

            let mut conflicts: Vec<ExternalPrincipalId> = projection
                .conflicts()
                .iter()
                .map(|conflict| conflict.external_principal_id)
                .collect();
            conflicts.sort_unstable();
            assert_eq!(
                conflicts, expected_conflicts,
                "mask {mask:#05b}: the conflicts are every `Linked` record but the smallest"
            );

            let mut allocator = SequentialAllocator::new();
            let provisioned = provision_external_principal(
                &ProvisionExternalPrincipal {
                    connection_id: connection(1),
                    proof: presented(),
                },
                &request(),
                &verifier,
                &projection,
                &projection,
                &mut allocator,
            );
            let refused = match provisioned {
                Ok(minted) => panic!(
                    "mask {mask:#05b}: three records hold this key, so provisioning creates \
                     nothing: {minted:?}"
                ),
                Err(refused) => refused,
            };
            assert_eq!(refused.reason, DenialReason::Denied, "mask {mask:#05b}");
            assert_eq!(
                refused.clause,
                DenialClause::ExternalKeyExists,
                "mask {mask:#05b}: a key three records hold is not free to create one on"
            );
        }
    }
}

/// Every append order this case drives for one state mask.
///
/// Each of the six permutations of the three link events with the unlinks appended after
/// them, plus two interleavings in which each unlink immediately follows its own link —
/// which is the order two writers racing one key actually produce, and the order
/// `tests/replay.rs` builds for two records.
fn orders(mask: u8) -> Vec<Vec<FederationEvent>> {
    let permutations = [
        [0_usize, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ];
    let mut orders = Vec::new();
    for permutation in permutations {
        let mut trailing = Vec::new();
        for index in permutation {
            let (id, principal_tag) = RECORDS[index];
            trailing.push(linked(external_principal(id), principal(principal_tag)));
        }
        for index in permutation {
            let (id, _) = RECORDS[index];
            if mask & (1 << index) != 0 {
                trailing.push(unlinked(external_principal(id)));
            }
        }
        orders.push(trailing);

        let mut immediate = Vec::new();
        for index in permutation {
            let (id, principal_tag) = RECORDS[index];
            immediate.push(linked(external_principal(id), principal(principal_tag)));
            if mask & (1 << index) != 0 {
                immediate.push(unlinked(external_principal(id)));
            }
        }
        orders.push(immediate);
    }
    orders
}

/// A record in whatever state, as an implementor supplies it to the port.
fn record(
    id: ExternalPrincipalId,
    principal_id: PrincipalId,
    state: LinkState,
) -> ExternalPrincipal {
    ExternalPrincipal {
        id,
        organization_id: organization(10),
        subject: ExternalSubject::new(SUBJECT),
        principal_id,
        connection_id: connection(1),
        link_method: ExternalLinkMethod::ConfiguredFederation,
        linked_at: linked_at(),
        state,
    }
}

/// `provision_external_principal`'s `ExternalKeyExists` guard rests on a property
/// `LinkStore` **requires** of every implementation.
///
/// **This case's premise was overturned by the correction pass 1 opened, and the finding
/// it was filed for stands.** As written it asserted that the guard rests on a property
/// the port does not require. The story this unit realizes says why the fix had to be in
/// the crate at all: the control-plane adapter "closed it for itself ... That fix is one
/// composition's. The overload is in the crate, so **every future composition inherits
/// it**, and no check in an adapter can stop the next one." What had landed was a
/// state-blind *read* — `links.link(&resolved.key).is_some()` — over a port that was not
/// state-blind, whose contract stated one requirement on an implementor and one
/// consequence:
///
/// > An implementation may return a row in any lifecycle state, and an implementation
/// > that can return a `Linked` row for the key returns one.
/// >
/// > An implementation that hides `Unlinked` rows from this port therefore reports a
/// > revoked key as free, and every composition over it inherits that.
///
/// The second sentence named the defect and did not forbid it, so a store returning the
/// smallest `Linked` row and nothing else satisfied the contract to the letter and
/// provisioned around a revocation. The state-blindness was `Projection`'s, not the
/// command's and not the port's.
///
/// **It is the port's now.** `LinkStore` asks an implementor for one thing — every record
/// on the key, in every lifecycle state — and this crate derives from it both the record
/// that *holds* the key and whether the key is held at all. So this case asserts the
/// contract rather than the hole, and asserts more of it than it did:
///
/// 1. a store answering the port's one required read is refused `ExternalKeyExists` for a
///    key whose every record is revoked — the original assertion, now true;
/// 2. a store that *also* resolves the key from an index of its own, hiding the revoked
///    record the way the store that broke this case as filed did, is refused all the same.
///    Pass 2 showed why "the guard does not read `link`" was not enough on its own — `link`
///    was a defaulted trait method, so a store could write it — and the correction moved it
///    to [`mandate_federation::LinkResolution`], blanket-implemented over every
///    `LinkStore`. The store below can therefore only carry its index as an *inherent*
///    method, which no command can reach;
/// 3. the other half of the same class, which the case as filed did not reach: the record
///    that holds the key is the port's rule too. A conforming store is never asked for it
///    and cannot answer it, so no implementation can answer the smallest `Unlinked` record
///    while the key still has a `Linked` one — which would deny `LinkAbsent` to a validly
///    linked caller.
#[test]
fn the_port_requires_the_state_blind_read_the_provisioning_guard_depends_on() {
    /// A `LinkStore` that answers the port's one required read and nothing else.
    struct Conforming(Vec<ExternalPrincipal>);

    impl LinkStore for Conforming {
        fn records_on_key(&self, _key: &ExternalKey) -> Vec<ExternalPrincipal> {
            self.0.clone()
        }
    }

    impl PrincipalStore for Conforming {
        fn organization_of(&self, _principal_id: &PrincipalId) -> Option<OrganizationId> {
            Some(organization(10))
        }
    }

    /// The store that broke this case as filed: it answers the required read honestly and
    /// resolves the key from an index of its own that hides a revoked record.
    ///
    /// **The index is an inherent method, because it can no longer be anything else.** As
    /// filed this store overrode `LinkStore::link`; `LinkResolution::link` replaced it, and
    /// a blanket implementation leaves an implementor nowhere to put a second answer that a
    /// command could reach. What survives is a method on the type, which nothing but this
    /// case ever calls — and the case calls it, so the difference between the two answers
    /// is on the record rather than assumed away.
    struct HidesTheRevokedRecordFromLink(Vec<ExternalPrincipal>);

    impl HidesTheRevokedRecordFromLink {
        fn own_index(&self, _key: &ExternalKey) -> Option<ExternalPrincipal> {
            self.0
                .iter()
                .filter(|row| row.state == LinkState::Linked)
                .min_by_key(|row| row.id)
                .cloned()
        }
    }

    impl LinkStore for HidesTheRevokedRecordFromLink {
        fn records_on_key(&self, _key: &ExternalKey) -> Vec<ExternalPrincipal> {
            self.0.clone()
        }
    }

    let projection = Projection::fold(&[created()]).expect("one connection");
    let revoked = vec![record(
        external_principal(0x71),
        principal(0x21),
        LinkState::Unlinked,
    )];

    // 1. The conforming store: a key whose every record is revoked is not free.
    let conforming = Conforming(revoked.clone());
    let mut allocator = SequentialAllocator::new();
    let refused = match provision_external_principal(
        &ProvisionExternalPrincipal {
            connection_id: connection(1),
            proof: presented(),
        },
        &request(),
        &admitting(),
        &projection,
        &conforming,
        &mut allocator,
    ) {
        Ok(provisioned) => panic!(
            "a record holds this key and its link was revoked, so the key is not free to \
             create a record on. The command minted {:?} for the subject whose link was \
             revoked: {provisioned:?}",
            provisioned.principal_id
        ),
        Err(refused) => refused,
    };
    assert_eq!(refused.reason, DenialReason::Denied);
    assert_eq!(refused.clause, DenialClause::ExternalKeyExists);

    // 2. The store whose own index hides the revoked record — the original attack — is
    //    refused identically. The index disagrees with the crate and reaches no command.
    let hiding = HidesTheRevokedRecordFromLink(revoked.clone());
    assert!(
        hiding.own_index(&key()).is_none(),
        "the premise of the attack: this store's own index answers nothing for a key its \
         own records hold"
    );
    assert_eq!(
        LinkResolution::link(&hiding, &key()).map(|held| held.id),
        Some(external_principal(0x71)),
        "and the answer every command reads is the crate's, not the store's: the revoked \
         record is on the key and is what the key resolves to while nothing else is"
    );
    let mut allocator = SequentialAllocator::new();
    let refused = match provision_external_principal(
        &ProvisionExternalPrincipal {
            connection_id: connection(1),
            proof: presented(),
        },
        &request(),
        &admitting(),
        &projection,
        &hiding,
        &mut allocator,
    ) {
        Ok(provisioned) => panic!(
            "hiding the revoked record from `link` no longer hides it from the guard, \
             which reads the port's required `records_on_key`. The command minted {:?}: \
             {provisioned:?}",
            provisioned.principal_id
        ),
        Err(refused) => refused,
    };
    assert_eq!(refused.reason, DenialReason::Denied);
    assert_eq!(refused.clause, DenialClause::ExternalKeyExists);

    // 3. And the holder rule is the port's: the conforming store writes no preference and
    //    gets the `Linked` record, not the smaller revoked one.
    let mixed = Conforming(vec![
        record(
            external_principal(0x71),
            principal(0x21),
            LinkState::Unlinked,
        ),
        record(external_principal(0x72), principal(0x22), LinkState::Linked),
    ]);
    assert_eq!(
        mixed.link(&key()).map(|held| held.id),
        Some(external_principal(0x72)),
        "the smaller record is revoked, so the `Linked` one holds the key — a rule the \
         implementor did not write and cannot get wrong by saying nothing"
    );
    let mut sessions = RecordingSessionIssuer::new();
    let login = authenticate_federation(
        &AuthenticateFederation {
            connection_id: connection(1),
            proof: presented(),
        },
        &request(),
        &admitting(),
        &projection,
        &mixed,
        &mut sessions,
    )
    .expect("the key has a `Linked` record, so the login resolves it");
    assert_eq!(
        login.principal_id,
        principal(0x22),
        "the session is for the principal the `Linked` record names"
    );

    let mut allocator = SequentialAllocator::new();
    let refused = match provision_external_principal(
        &ProvisionExternalPrincipal {
            connection_id: connection(1),
            proof: presented(),
        },
        &request(),
        &admitting(),
        &projection,
        &mixed,
        &mut allocator,
    ) {
        Ok(provisioned) => panic!("two records hold this key: {provisioned:?}"),
        Err(refused) => refused,
    };
    assert_eq!(refused.clause, DenialClause::ExternalKeyExists);
}

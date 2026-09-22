//! Adversary pass 2 against `story:link-absent-discriminates` (`8b7a6e0`, the correction).
//!
//! The correction's first claim is that the guarantee moved **into the port**: `LinkStore`
//! has one required read, `records_on_key`, and this crate derives `link` from it, so that
//! a command's correctness stops being a property of whichever implementation it was
//! handed. `crates/mandate-federation/src/lib.rs` states it twice —
//!
//! > A port with one method per question is a port whose implementations can disagree with
//! > each other, and a command whose correctness is then a property of the implementation
//! > it happened to be handed rather than of the port. So [`LinkStore::records_on_key`] is
//! > the only method an implementor writes, and [`LinkStore::link`] is computed from it
//! > here.
//!
//! — `crates/mandate-federation/src/record.rs` a third time ("no other implementation of
//! the port can resolve one key differently"), and the unit's own case at
//! `crates/mandate-federation/tests/adversary_wave_h_1.rs` a fourth:
//!
//! > A conforming store is never asked for it, so no implementation can answer the
//! > smallest `Unlinked` record while the key still has a `Linked` one — which would deny
//! > `LinkAbsent` to a validly linked caller.
//!
//! Both cases below assert those sentences against the code that was shipped with them.
//! Both were red. The correction they forced is in `crates/mandate-federation/src/lib.rs`:
//! `link` and `key_is_held` left `LinkStore`, where they were defaulted methods an
//! implementor could write, for `LinkResolution`, a trait implemented once and blanket over
//! every `LinkStore` — which is the difference between a derivation and a suggestion — and
//! the derivation now drops a record that is not on the key it was asked about. The cases
//! stand as filed and assert the sentences; what changed is that they hold.

use mandate_federation::authenticate::{
    AuthenticateFederation, ProvisionExternalPrincipal, authenticate_federation,
    provision_external_principal,
};
use mandate_federation::record::{
    ExternalKey, ExternalPrincipal, FederationEvent, LinkState, Projection,
};
use mandate_federation::verifier::{ConstructedVerifier, VerifiedProof};
use mandate_federation::{
    DenialClause, LinkResolution, LinkStore, RecordingSessionIssuer, RequestContext,
    SequentialAllocator,
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
        correlation: CorrelationId::new("adversary-wave-h-2"),
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
        correlation: CorrelationId::new("adversary-wave-h-2"),
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

/// The key every login below resolves to.
fn key() -> ExternalKey {
    ExternalKey {
        organization_id: organization(10),
        issuer: Issuer::new(ISSUER),
        subject: ExternalSubject::new(SUBJECT),
    }
}

/// A record on [`key`], in whatever state the case builds.
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

/// The holder rule is the port's: **no implementation can decide one key differently.**
///
/// `src/lib.rs`: "`LinkStore::records_on_key` is the only method an implementor writes, and
/// `LinkStore::link` is computed from it here." `src/record.rs`: "no other implementation of
/// the port can resolve one key differently." `tests/adversary_wave_h_1.rs`: "A conforming
/// store is never asked for it, so no implementation can answer the smallest `Unlinked`
/// record while the key still has a `Linked` one — which would deny `LinkAbsent` to a
/// validly linked caller."
///
/// The store below writes the port's one required read **honestly** — both records on the
/// key, in the states they are in, which is everything the contract asks of it — and
/// additionally supplies `link`. That was not a hostile answer to a read it was asked for:
/// `link` was a defaulted method on a public trait, so it was a method an implementor was
/// free to write, and the obvious reason to write it is the one every read model has —
/// answering the key from an index instead of materializing every record on it. The rule it
/// gets wrong was the one the four sentences above say it cannot get wrong.
///
/// **The correction this case forced is the one the sentences needed.** `link` and
/// `key_is_held` moved to [`mandate_federation::LinkResolution`], a trait with a blanket
/// implementation over every [`LinkStore`], so `impl LinkResolution for IndexedByKey` is a
/// conflicting implementation and does not compile: there is nowhere left for a second
/// answer a command can reach. The index survives here as an inherent method, which is what
/// an implementor may still write and what no command will ever call — and this case calls
/// it, so the disagreement is measured rather than assumed away.
///
/// So this case asserts the sentences: the store's own index answers the revoked record,
/// the crate answers the `Linked` one, and the validly linked caller authenticates.
#[test]
fn no_implementation_of_the_port_can_resolve_one_key_differently() {
    /// A `LinkStore` that answers `records_on_key` completely and truthfully, and resolves
    /// the key from its own index rather than from that answer.
    struct IndexedByKey(Vec<ExternalPrincipal>);

    impl IndexedByKey {
        /// What this store would answer if it could answer the key at all.
        fn own_index(&self, _key: &ExternalKey) -> Option<ExternalPrincipal> {
            self.0.iter().min_by_key(|record| record.id).cloned()
        }
    }

    impl LinkStore for IndexedByKey {
        fn records_on_key(&self, _key: &ExternalKey) -> Vec<ExternalPrincipal> {
            self.0.clone()
        }
    }

    let projection = Projection::fold(&[created()]).expect("one connection");
    // The smaller record is revoked; the larger is the live link of principal 0x22.
    let store = IndexedByKey(vec![
        record(
            external_principal(0x71),
            principal(0x21),
            LinkState::Unlinked,
        ),
        record(external_principal(0x72), principal(0x22), LinkState::Linked),
    ]);

    // The premise, and the half of the correction that does hold: the store answers the
    // port's one required read with every record on the key, so the key is not free.
    assert_eq!(
        store.records_on_key(&key()).len(),
        2,
        "the premise: this store hides nothing from the port's one required read"
    );
    let mut allocator = SequentialAllocator::new();
    let refused = provision_external_principal(
        &ProvisionExternalPrincipal {
            connection_id: connection(1),
            proof: presented(),
        },
        &request(),
        &admitting(),
        &projection,
        &store,
        &mut allocator,
    )
    .expect_err("two records hold this key, so it is not free to create a record on");
    assert_eq!(refused.reason, DenialReason::Denied);
    assert_eq!(refused.clause, DenialClause::ExternalKeyExists);

    // And the claim under attack. The store's own index answers the smaller, revoked
    // record; the crate's derivation answers the `Linked` one; and a command reads the
    // crate's, because `LinkResolution` is blanket-implemented and this store has no way to
    // supply the other answer to it.
    assert_eq!(
        store.own_index(&key()).map(|held| held.id),
        Some(external_principal(0x71)),
        "the premise: this store's own index resolves the key to the revoked record"
    );
    assert_eq!(
        LinkResolution::link(&store, &key()).map(|held| held.id),
        Some(external_principal(0x72)),
        "and the crate resolves it to the `Linked` one, from the records the store answered"
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
        &store,
        &mut sessions,
    )
    .expect(
        "the key has a `Linked` record, and `src/lib.rs` says the record that holds a key is \
         computed by this crate from `records_on_key` and not answered by an implementor — \
         so no implementation can answer the smallest `Unlinked` record while the key still \
         has a `Linked` one, and no implementation can deny `LinkAbsent` to a validly linked \
         caller",
    );
    assert_eq!(
        login.principal_id,
        principal(0x22),
        "the session is for the principal the `Linked` record names"
    );
}

/// `records_on_key` answers "every record on this **exact** key", and this crate derives
/// every command's decision from that answer without checking the key on any of it.
///
/// `src/lib.rs` moved the derivation into the crate so that a command's correctness would
/// stop being "a property of the implementation it happened to be handed". Two of the
/// key's three components — `organization_id` and `subject` — are carried on every
/// `ExternalPrincipal` the port returns, so the derivation can check what it was handed and
/// does not. The store below answers one record that is on a different organization's key
/// entirely; the login is for organization 10, and the record is organization 20's.
///
/// A store that answers records off-key is a broken store, and nothing in this repository
/// is one. What the case measures is what the crate does when handed one: it issues a
/// session in the resolved organization for the foreign record's principal, rather than
/// refusing `LinkAbsent` for a key that has no record on it.
#[test]
fn a_record_the_store_answers_for_another_key_does_not_resolve_this_one() {
    /// A `LinkStore` whose index is keyed on something other than the whole key, so it
    /// answers a record that is not on the key it was asked about.
    struct AnswersAForeignRecord(ExternalPrincipal);

    impl LinkStore for AnswersAForeignRecord {
        fn records_on_key(&self, _key: &ExternalKey) -> Vec<ExternalPrincipal> {
            vec![self.0.clone()]
        }
    }

    let projection = Projection::fold(&[created()]).expect("one connection");
    let foreign = ExternalPrincipal {
        id: external_principal(0x91),
        organization_id: organization(20),
        subject: ExternalSubject::new("somebody-else"),
        principal_id: principal(0x99),
        connection_id: connection(2),
        link_method: ExternalLinkMethod::Administrator,
        linked_at: linked_at(),
        state: LinkState::Linked,
    };
    assert_ne!(
        foreign.organization_id,
        key().organization_id,
        "the premise: the record is on another organization's key"
    );
    assert_ne!(
        foreign.subject,
        key().subject,
        "the premise: the record is on another subject's key"
    );

    let store = AnswersAForeignRecord(foreign);
    let mut sessions = RecordingSessionIssuer::new();
    let outcome = authenticate_federation(
        &AuthenticateFederation {
            connection_id: connection(1),
            proof: presented(),
        },
        &request(),
        &admitting(),
        &projection,
        &store,
        &mut sessions,
    );

    let denied = match outcome {
        Ok(login) => panic!(
            "`LinkStore::records_on_key` answers \"every record on this exact key\", and this \
             crate derives the holder from that answer rather than asking an implementor for \
             it — so a record on organization {:?}'s key for subject `somebody-else` is not a \
             record on organization {:?}'s key for subject `{SUBJECT}`, and the login has no \
             linked principal. It was issued a session in organization {:?} for principal \
             {:?} instead: {login:?}",
            organization(20),
            organization(10),
            login.organization_id,
            login.principal_id,
        ),
        Err(denied) => denied,
    };
    assert_eq!(denied.reason, DenialReason::Denied);
    assert_eq!(denied.clause, DenialClause::LinkAbsent);
    assert!(sessions.issued().is_empty(), "no session was issued");
}

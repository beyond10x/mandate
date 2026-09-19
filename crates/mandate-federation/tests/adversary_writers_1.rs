//! Adversary pass over the realization round of `story:declared-writers`, unit A4
//! (`oauth-client-fold`).
//!
//! Three lines of attack, and what each one is:
//!
//! * **The repo-wide redelivery rule, against the new creation arm.**
//!   `crates/mandate-model/src/tenancy.rs` states it for all six of its creating events:
//!   "A creation is insert-if-absent: the first one for an identity is the one that
//!   stands. A creation names the first event of a record, so a redelivered creation —
//!   which the kit's at-least-once delivery admits, and which no `decide_*` path emits —
//!   must write nothing rather than return a record from a terminal state to its initial
//!   one." `crates/mandate-model/src/graph.rs` keeps it for `ResourceRegistered`, and
//!   `crates/mandate-federation/src/record.rs`'s own `record_link` keeps it for the two
//!   link-creating events, in the same file as the arm under attack: "a redelivered
//!   creation — which the kit's at-least-once delivery admits — writes nothing". The new
//!   `OAuthClientRegistered` arm is the only creation arm in the workspace that answers a
//!   redelivery with a hard `FoldError`, which makes the whole domain's log unreadable.
//!
//! * **The module the unit left behind.** `crates/mandate-federation/src/publicclient.rs`
//!   still tells its reader that no declared event creates an `OAuthClient` and that the
//!   fold answers `None` for every client. The unit's Scope names `src/publicclient.rs:14`
//!   as a site to rewrite; the diff does not touch the file.
//!
//! * **Two probes that held**, kept so a reader can see what was attacked and did not
//!   break: the disabled client at authorization, driven through both real handlers and
//!   the crate's own fold, and two organizations registering one redirect set.

use mandate_federation::disable::{DisableOAuthClient, disable_oauth_client};
use mandate_federation::publicclient::registered_public_client;
use mandate_federation::record::{OAuthClient, OAuthClientState, Projection};
use mandate_federation::register_client::{
    ConfiguredAdmission, OAuthClientRegistered, RegisterOAuthClient, register_o_auth_client,
};
use mandate_federation::{DenialClause, SequentialAllocator};
use mandate_types::value::Uuid;
use mandate_types::{
    Audience, CorrelationId, CredentialId, OrganizationId, PkceMethod, PrincipalId, RedirectUri,
    VerifiedContext,
};

const REDIRECT: &str = "https://app.example/callback";

fn uuid(tag: u8) -> Uuid {
    Uuid::from_bytes([tag; 16])
}

fn organization(tag: u8) -> OrganizationId {
    OrganizationId::new(uuid(tag))
}

fn administrator() -> PrincipalId {
    PrincipalId::new(uuid(0x51))
}

fn context(organization_id: OrganizationId) -> VerifiedContext {
    VerifiedContext {
        subject: administrator(),
        actor: None,
        organization: organization_id,
        audience: Audience::new("mandate"),
        credential: CredentialId::new(uuid(0xcd)),
        delegation: None,
        execution: None,
        correlation: CorrelationId::new("adversary-writers-1"),
    }
}

/// An admission that admits the administrator, the named organizations and the one
/// redirect URI in each of them.
fn admission(organizations: &[OrganizationId]) -> ConfiguredAdmission {
    organizations.iter().fold(
        ConfiguredAdmission::new().with_administrator(administrator()),
        |admission, organization_id| {
            admission
                .with_organization(*organization_id)
                .with_redirect_uri(*organization_id, RedirectUri::new(REDIRECT))
        },
    )
}

/// One accepted `mandate.federation.RegisterOAuthClient`, through the real handler.
fn registered(
    organization_id: OrganizationId,
    allocator: &mut SequentialAllocator,
) -> OAuthClientRegistered {
    register_o_auth_client(
        &RegisterOAuthClient {
            context: context(organization_id),
            public: true,
            redirect_uris: vec![RedirectUri::new(REDIRECT)],
            pkce_method: PkceMethod::S256,
        },
        &admission(&[organization_id]),
        allocator,
    )
    .expect("an administrator of an admitted organization registering an admitted redirect")
}

/// A redelivered creation must write nothing, not make the log unreadable.
///
/// The event is the *same* accepted event twice — the shape at-least-once delivery
/// produces, and the only shape a repeat of this event can take: the client identity is
/// minted per record by `IdentityAllocator::next_o_auth_client_id`, exactly as a link's
/// is, so two accepted `RegisterOAuthClient` commands never name one identity.
/// `FoldError::OAuthClientExists`'s own documentation gives "two accepted commands that
/// cannot both be true" as the reason it differs from `record_link`, and that is the one
/// case this identity cannot be in.
///
/// The cost of the refusal is not the client: `Projection::fold` returns `Err` for the
/// whole log, so one redelivered registration makes every connection, link and client in
/// that domain's log unreadable.
#[test]
fn a_redelivered_client_registration_leaves_the_log_readable() {
    let mut allocator = SequentialAllocator::new();
    let outcome = registered(organization(10), &mut allocator);

    let once = Projection::fold(std::slice::from_ref(&outcome.event)).expect("one creation");
    let twice = Projection::fold(&[outcome.event.clone(), outcome.event])
        .expect("a redelivered creation writes nothing rather than failing the fold");

    assert_eq!(
        twice, once,
        "insert-if-absent: the first creation of an identity is the one that stands"
    );
}

/// The exact property `crates/mandate-model/tests/replay.rs`
/// `a_redelivered_creation_after_a_terminal_state_writes_nothing` decides for the six
/// `mandate.tenancy` creating events, asked of this one.
///
/// Register, disable, and let the registration arrive a second time. The record must stay
/// in the terminal `Disabled` state and the log must stay readable.
#[test]
fn a_redelivered_registration_after_a_disable_leaves_the_record_disabled() {
    let mut allocator = SequentialAllocator::new();
    let outcome = registered(organization(10), &mut allocator);
    let live = Projection::fold(std::slice::from_ref(&outcome.event)).expect("one creation");

    let disabled = disable_oauth_client(
        &DisableOAuthClient {
            context: context(organization(10)),
            id: outcome.id,
        },
        &live,
    )
    .expect("a recorded client of this tenant");

    let replayed = Projection::fold(&[outcome.event.clone(), disabled, outcome.event])
        .expect("a redelivered creation after a terminal state writes nothing");

    assert_eq!(
        replayed.clients(),
        [OAuthClient {
            id: outcome.id,
            organization_id: organization(10),
            public: true,
            redirect_uris: vec![RedirectUri::new(REDIRECT)],
            pkce_method: PkceMethod::S256,
            state: OAuthClientState::Disabled,
        }],
        "a redelivered creation does not return the record to its initial state"
    );
}

/// The module that still says no event creates an `OAuthClient`.
///
/// `crates/mandate-federation/src/publicclient.rs` is the file `AuthorizePublicClient`
/// reads the client through. Its module documentation states that "No declared event
/// creates a `mandate.federation.OAuthClient`" and that "this port answers `None` for
/// every client until `story:declared-writers` declares the creating command", and
/// `RecordedClients` states that "neither read model has a contract event that creates its
/// record yet". All three were true before this unit and none is true after it: the same
/// unit added `mandate.federation.RegisterOAuthClient`, the creation arm and a case
/// (`tests/publicclient.rs`) that resolves a registered client through this very port.
///
/// The source is read rather than the rendered documentation because that is what a reader
/// of this crate opens, and it is the only surface on which this statement exists.
#[test]
fn the_public_client_module_does_not_say_no_event_creates_a_client() {
    const MODULE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/src/publicclient.rs");

    let source = std::fs::read_to_string(MODULE).expect("the module is readable");
    let prose: String = source
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim_start();
            trimmed
                .strip_prefix("//!")
                .or_else(|| trimmed.strip_prefix("///"))
        })
        .collect::<Vec<_>>()
        .join(" ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");

    for stale in [
        "No declared event creates a `mandate.federation.OAuthClient`",
        "this port answers `None` for every client until `story:declared-writers` declares \
         the creating command",
        "neither read model has a contract event that creates its record yet",
    ] {
        assert!(
            !prose.contains(stale),
            "src/publicclient.rs still tells its reader \"{stale}\", which \
             `mandate.federation.RegisterOAuthClient` and the creation arm this unit added \
             made false"
        );
    }
}

/// Probe, and it holds: a client disabled after registration is refused at authorization,
/// decided against the crate's own fold rather than the `pub` double.
#[test]
fn probe_a_disabled_registered_client_is_refused_at_authorization() {
    let mut allocator = SequentialAllocator::new();
    let outcome = registered(organization(10), &mut allocator);
    let live = Projection::fold(std::slice::from_ref(&outcome.event)).expect("one creation");

    let disabled = disable_oauth_client(
        &DisableOAuthClient {
            context: context(organization(10)),
            id: outcome.id,
        },
        &live,
    )
    .expect("a recorded client of this tenant");
    let after = Projection::fold(&[outcome.event, disabled]).expect("the log rebuilds");

    let denied = registered_public_client(
        &after,
        &outcome.id,
        &RedirectUri::new(REDIRECT),
        &organization(10),
    )
    .expect_err("the client is in the terminal Disabled state");

    assert_eq!(denied.clause, DenialClause::ClientDisabled);
}

/// Probe, and it holds: two organizations register the same redirect set under one
/// allocator, and neither client is resolvable under the other's organization.
#[test]
fn probe_two_organizations_register_one_redirect_set_without_crossing() {
    let mut allocator = SequentialAllocator::new();
    let first = registered(organization(10), &mut allocator);
    let second = registered(organization(11), &mut allocator);

    assert_ne!(first.id, second.id, "one allocator mints one identity once");
    assert_eq!(first.organization_id, organization(10));
    assert_eq!(second.organization_id, organization(11));

    let fold = Projection::fold(&[first.event, second.event]).expect("two creations");

    for (outcome, own, other) in [
        (&first.id, organization(10), organization(11)),
        (&second.id, organization(11), organization(10)),
    ] {
        registered_public_client(&fold, outcome, &RedirectUri::new(REDIRECT), &own)
            .expect("the client resolves under the organization it was bound to");

        let denied = registered_public_client(&fold, outcome, &RedirectUri::new(REDIRECT), &other)
            .expect_err("a client is not resolvable under another organization");

        assert_eq!(denied.clause, DenialClause::OrganizationMismatch);
    }
}

//! The record half of the ten `mandate.tenancy` commands.
//!
//! Every rule asserted here is read off `systems/mandate/domains/tenancy.yaml` as it
//! stands on this branch: five entities and ten commands. The fold decides what the
//! record admits; whether a caller holds the authority a command names is
//! `mandate-authz`'s and is never decided here.

use mandate_model::tenancy::{
    MembershipAuthority, OrganizationMembershipState, OrganizationState, SpaceState,
    TeamMembershipState, TeamState, Tenancy,
};
use mandate_types::{
    Audience, CorrelationId, CredentialId, DenialReason, MembershipContributionId, OrganizationId,
    OrganizationMembershipId, PrincipalId, SpaceId, TeamId, TeamMembershipId, VerifiedContext,
};

fn uuid(tag: u16) -> String {
    format!("1b4e28ba-2fa1-4d8e-b1b0-8c1d4e5f{tag:04x}")
}

fn organization(tag: u16) -> OrganizationId {
    OrganizationId::parse(&uuid(tag)).expect("organization identity")
}

fn membership(tag: u16) -> OrganizationMembershipId {
    OrganizationMembershipId::parse(&uuid(tag)).expect("membership identity")
}

fn principal(tag: u16) -> PrincipalId {
    PrincipalId::parse(&uuid(tag)).expect("principal identity")
}

fn team(tag: u16) -> TeamId {
    TeamId::parse(&uuid(tag)).expect("team identity")
}

fn team_membership(tag: u16) -> TeamMembershipId {
    TeamMembershipId::parse(&uuid(tag)).expect("team membership identity")
}

fn space(tag: u16) -> SpaceId {
    SpaceId::parse(&uuid(tag)).expect("space identity")
}

fn contribution(tag: u16) -> MembershipContributionId {
    MembershipContributionId::parse(&uuid(tag)).expect("contribution identity")
}

fn context(organization: OrganizationId, subject: PrincipalId) -> VerifiedContext {
    VerifiedContext {
        subject,
        actor: None,
        organization,
        audience: Audience::new("mandate"),
        credential: CredentialId::parse(&uuid(0xffff)).expect("credential identity"),
        delegation: None,
        execution: None,
        correlation: CorrelationId::new("correlation"),
    }
}

/// The platform administrator's verified context.
///
/// `CreateOrganization` and `CloseOrganization` are platform-scoped and
/// `AddOrganizationMembership` has a platform path, so the organization this names is the
/// administrator's own and never the one being written. Every one of the three declares a
/// `mandate.core.VerifiedContext` in its payload, so every one of them takes one.
fn platform() -> VerifiedContext {
    context(organization(0xfff0), principal(0xfff1))
}

/// A refusal writes nothing.
///
/// `tenancy.yaml` gives each command one `denied` clause carrying one
/// `mandate_types::DenialReason`, and `src/tenancy.rs` decides before it applies. So
/// every denied path has the same two observable halves: the declared reason, and a
/// projection identical to the one the decision was read from. Cloning first is what
/// makes the second half an assertion rather than a claim.
macro_rules! refuses {
    ($fold:expr, $decided:expr, $why:literal) => {{
        let before = $fold.clone();
        let denial = $decided.expect_err($why);
        assert_eq!(denial.reason, DenialReason::Denied, $why);
        assert_eq!(
            $fold, before,
            concat!("a refused command changed the projection: ", $why)
        );
    }};
}

/// `tenancy.yaml`, CreateOrganization: "It is created empty, and no membership, team,
/// space or grant exists inside it until that record's own command writes one.
/// AddOrganizationMembership is the one command that can name this organization rather
/// than the caller's own".
#[test]
fn an_organization_is_created_empty_and_takes_its_first_member_through_the_platform_path() {
    let mut tenancy = Tenancy::new();
    let acme = organization(1);
    let other = organization(2);
    tenancy
        .create_organization(&platform(), acme, "Acme")
        .expect("acme");
    tenancy
        .create_organization(&platform(), other, "Other")
        .expect("other");

    assert_eq!(
        tenancy.organization(acme).expect("acme resolves").state,
        OrganizationState::Recorded
    );
    assert!(
        tenancy.members_of(acme).is_empty(),
        "a created organization holds no member"
    );

    let administrator = context(other, principal(10));
    let denial = tenancy
        .may_add_organization_membership(
            &administrator,
            MembershipAuthority::VerifiedOrganization,
            acme,
            principal(11),
        )
        .expect_err("a tenant caller cannot name an organization other than the verified one");
    assert_eq!(denial.reason, DenialReason::Denied);
    assert!(tenancy.organization_membership(membership(20)).is_none());
    assert!(tenancy.members_of(acme).is_empty());

    tenancy
        .may_add_organization_membership(
            &administrator,
            MembershipAuthority::PlatformOrganizationAdministration,
            acme,
            principal(11),
        )
        .expect("the platform path admits the first membership");
    tenancy
        .add_organization_membership(
            &platform(),
            MembershipAuthority::PlatformOrganizationAdministration,
            membership(20),
            acme,
            principal(11),
        )
        .expect("the platform path seeds the first membership");
    assert_eq!(tenancy.members_of(acme), vec![principal(11)]);
    assert_eq!(
        tenancy
            .organization_membership(membership(20))
            .expect("membership resolves")
            .state,
        OrganizationMembershipState::Active
    );
}

/// `tenancy.yaml`, AddOrganizationMembership: "membership carries no authority by
/// itself, which stays with grants and relationships". The story's required observation:
/// "principals join multiple orgs without a global role".
#[test]
fn a_principal_joins_two_organizations_and_no_record_carries_a_global_role() {
    let mut tenancy = Tenancy::new();
    let acme = organization(1);
    let other = organization(2);
    let joiner = principal(11);
    tenancy
        .create_organization(&platform(), acme, "Acme")
        .expect("acme");
    tenancy
        .create_organization(&platform(), other, "Other")
        .expect("other");

    for (identity, target) in [(membership(20), acme), (membership(21), other)] {
        tenancy
            .may_add_organization_membership(
                &context(target, principal(10)),
                MembershipAuthority::PlatformOrganizationAdministration,
                target,
                joiner,
            )
            .expect("the platform path admits the membership");
        tenancy
            .add_organization_membership(
                &platform(),
                MembershipAuthority::PlatformOrganizationAdministration,
                identity,
                target,
                joiner,
            )
            .expect("membership is recorded");
    }

    assert_eq!(tenancy.organizations_of(joiner), vec![acme, other]);
    assert!(tenancy.is_member(acme, joiner));
    assert!(tenancy.is_member(other, joiner));

    let encoded = serde_json::to_string(
        tenancy
            .organization_membership(membership(20))
            .expect("membership resolves"),
    )
    .expect("encode");
    let value: serde_json::Value = serde_json::from_str(&encoded).expect("decode");
    let mut keys: Vec<&str> = value
        .as_object()
        .expect("an object")
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(keys, ["id", "organization_id", "principal_id", "state"]);
    assert!(
        !encoded.contains("role"),
        "no membership record carries a role: {encoded}"
    );
}

/// `tenancy.yaml`, CreateTeam and CreateSpace: the display name is admitted "in the
/// verified organization", and the record resolves from that context rather than from a
/// supplied selector.
#[test]
fn a_team_and_a_space_take_their_organization_from_the_verified_context() {
    let mut tenancy = Tenancy::new();
    let acme = organization(1);
    let other = organization(2);
    tenancy
        .create_organization(&platform(), acme, "Acme")
        .expect("acme");
    tenancy
        .create_organization(&platform(), other, "Other")
        .expect("other");
    let caller = context(acme, principal(10));

    tenancy
        .create_team(&caller, team(30), "Platform")
        .expect("team");
    tenancy
        .create_space(&caller, space(40), "Production")
        .expect("space");
    assert_eq!(
        tenancy
            .team(team(30))
            .expect("team resolves")
            .organization_id,
        acme
    );
    assert_eq!(
        tenancy
            .space(space(40))
            .expect("space resolves")
            .organization_id,
        acme
    );

    let outsider = context(other, principal(12));
    assert_eq!(
        tenancy
            .retire_team(&outsider, team(30))
            .expect_err("a team outside the verified organization is not retired")
            .reason,
        DenialReason::Denied
    );
    assert_eq!(
        tenancy
            .retire_space(&outsider, space(40))
            .expect_err("a space outside the verified organization is not retired")
            .reason,
        DenialReason::Denied
    );
    assert_eq!(
        tenancy.team(team(30)).expect("team resolves").state,
        TeamState::Recorded
    );
    assert_eq!(
        tenancy.space(space(40)).expect("space resolves").state,
        SpaceState::Recorded
    );
}

/// A record in another organization refuses exactly as one that was never recorded does.
/// `tenancy.yaml` covers both in one denied clause per command and carries one error, so
/// a distinguishable refusal would publish cross-tenant existence.
#[test]
fn a_record_in_another_organization_refuses_exactly_as_an_unrecorded_one_does() {
    let mut tenancy = Tenancy::new();
    let acme = organization(1);
    let other = organization(2);
    tenancy
        .create_organization(&platform(), acme, "Acme")
        .expect("acme");
    tenancy
        .create_organization(&platform(), other, "Other")
        .expect("other");
    tenancy
        .create_team(&context(acme, principal(10)), team(30), "Platform")
        .expect("team");

    let outsider = context(other, principal(12));
    let elsewhere = tenancy
        .retire_team(&outsider, team(30))
        .expect_err("a team in another organization");
    let unrecorded = tenancy
        .retire_team(&outsider, team(31))
        .expect_err("a team that was never recorded");
    assert_eq!(elsewhere, unrecorded);
}

/// `tenancy.yaml`, AddTeamMembership denied: "the principal is not a member of that
/// organization, the principal is already a member of that team".
#[test]
fn team_membership_requires_organization_membership_first_and_is_recorded_once() {
    let mut tenancy = Tenancy::new();
    let acme = organization(1);
    let joiner = principal(11);
    tenancy
        .create_organization(&platform(), acme, "Acme")
        .expect("acme");
    let caller = context(acme, principal(10));
    tenancy
        .create_team(&caller, team(30), "Platform")
        .expect("team");

    assert_eq!(
        tenancy
            .add_team_membership(
                &caller,
                team_membership(50),
                team(30),
                joiner,
                contribution(60)
            )
            .expect_err("the principal is not a member of the organization")
            .reason,
        DenialReason::Denied
    );
    assert!(tenancy.team_membership(team_membership(50)).is_none());

    tenancy
        .add_organization_membership(
            &platform(),
            MembershipAuthority::PlatformOrganizationAdministration,
            membership(20),
            acme,
            joiner,
        )
        .expect("organization membership");
    tenancy
        .add_team_membership(
            &caller,
            team_membership(50),
            team(30),
            joiner,
            contribution(60),
        )
        .expect("team membership");
    assert_eq!(
        tenancy
            .team_membership(team_membership(50))
            .expect("team membership resolves")
            .state,
        TeamMembershipState::Recorded
    );

    assert_eq!(
        tenancy
            .add_team_membership(
                &caller,
                team_membership(51),
                team(30),
                joiner,
                contribution(61)
            )
            .expect_err("the principal is already a member of that team")
            .reason,
        DenialReason::Denied
    );
    assert!(tenancy.team_membership(team_membership(51)).is_none());
}

/// `tenancy.yaml:1`: "Lifecycle is immutable-with-status: nothing is destroyed, and
/// every change is a new recorded state". Every closure, retirement and removal moves a
/// state and keeps its record; a terminal state does not move twice.
#[test]
fn every_closure_retirement_and_removal_keeps_its_record_and_only_moves_a_state() {
    let mut tenancy = Tenancy::new();
    let acme = organization(1);
    let joiner = principal(11);
    tenancy
        .create_organization(&platform(), acme, "Acme")
        .expect("acme");
    let caller = context(acme, principal(10));
    tenancy
        .add_organization_membership(
            &platform(),
            MembershipAuthority::PlatformOrganizationAdministration,
            membership(20),
            acme,
            joiner,
        )
        .expect("organization membership");
    tenancy
        .create_team(&caller, team(30), "Platform")
        .expect("team");
    tenancy
        .add_team_membership(
            &caller,
            team_membership(50),
            team(30),
            joiner,
            contribution(60),
        )
        .expect("team membership");
    tenancy
        .create_space(&caller, space(40), "Production")
        .expect("space");
    let recorded = tenancy.record_count();
    assert_eq!(recorded, 5);

    tenancy
        .remove_team_membership(&caller, team_membership(50))
        .expect("team membership removed");
    tenancy
        .retire_team(&caller, team(30))
        .expect("team retired");
    tenancy
        .retire_space(&caller, space(40))
        .expect("space retired");
    tenancy
        .remove_organization_membership(&caller, membership(20))
        .expect("membership removed");
    tenancy
        .close_organization(&platform(), acme)
        .expect("organization closed");

    assert_eq!(tenancy.record_count(), recorded, "no record was destroyed");
    assert_eq!(
        tenancy.organization(acme).expect("acme resolves").state,
        OrganizationState::Closed
    );
    assert_eq!(
        tenancy
            .organization_membership(membership(20))
            .expect("membership resolves")
            .state,
        OrganizationMembershipState::Removed
    );
    assert_eq!(
        tenancy.team(team(30)).expect("team resolves").state,
        TeamState::Retired
    );
    assert_eq!(
        tenancy
            .team_membership(team_membership(50))
            .expect("team membership resolves")
            .state,
        TeamMembershipState::Removed
    );
    assert_eq!(
        tenancy.space(space(40)).expect("space resolves").state,
        SpaceState::Retired
    );
    assert!(
        tenancy.members_of(acme).is_empty(),
        "a removed membership stops resolving as one"
    );
    assert!(tenancy.organizations_of(joiner).is_empty());

    assert_eq!(
        tenancy
            .close_organization(&platform(), acme)
            .expect_err("a terminal state does not move twice")
            .reason,
        DenialReason::Denied
    );
}

/// `tenancy.yaml`, CloseOrganization: "The tenant stops admitting authority and nothing
/// it owns is destroyed."
#[test]
fn a_closed_organization_admits_no_new_membership_team_or_space() {
    let mut tenancy = Tenancy::new();
    let acme = organization(1);
    tenancy
        .create_organization(&platform(), acme, "Acme")
        .expect("acme");
    let caller = context(acme, principal(10));
    tenancy
        .create_team(&caller, team(30), "Platform")
        .expect("team");
    tenancy
        .close_organization(&platform(), acme)
        .expect("closed");
    assert!(!tenancy.admits(acme));

    assert_eq!(
        tenancy
            .may_add_organization_membership(
                &caller,
                MembershipAuthority::PlatformOrganizationAdministration,
                acme,
                principal(11),
            )
            .expect_err("a closed organization admits no membership")
            .reason,
        DenialReason::Denied
    );
    assert_eq!(
        tenancy
            .create_team(&caller, team(31), "Later")
            .expect_err("a closed organization admits no team")
            .reason,
        DenialReason::Denied
    );
    assert_eq!(
        tenancy
            .create_space(&caller, space(40), "Later")
            .expect_err("a closed organization admits no space")
            .reason,
        DenialReason::Denied
    );
    assert_eq!(
        tenancy.record_count(),
        2,
        "nothing was written and nothing lost"
    );
    assert_eq!(
        tenancy.team(team(30)).expect("team resolves").state,
        TeamState::Recorded,
        "the records inside a closed organization are preserved"
    );
}

/// An identity already recorded is never overwritten: the second write is refused and
/// the first record stands.
#[test]
fn a_recorded_identity_is_never_overwritten_by_a_second_write() {
    let mut tenancy = Tenancy::new();
    let acme = organization(1);
    tenancy
        .create_organization(&platform(), acme, "Acme")
        .expect("acme");
    assert_eq!(
        tenancy
            .create_organization(&platform(), acme, "Impostor")
            .expect_err("the identity is already recorded")
            .reason,
        DenialReason::Denied
    );
    assert_eq!(
        tenancy
            .organization(acme)
            .expect("acme resolves")
            .display_name,
        "Acme"
    );

    let caller = context(acme, principal(10));
    tenancy
        .create_team(&caller, team(30), "Platform")
        .expect("team");
    assert_eq!(
        tenancy
            .create_team(&caller, team(30), "Impostor")
            .expect_err("the identity is already recorded")
            .reason,
        DenialReason::Denied
    );
    assert_eq!(
        tenancy.team(team(30)).expect("team resolves").display_name,
        "Platform"
    );
}

/// `mandate.tenancy.OrganizationMembershipAdded` declares `context`, `organization_id`,
/// `principal_id` and `membership_id`, and no field from which the authority path could be
/// read back. So the authority decides in [`Tenancy::may_add_organization_membership`] and
/// in `decide_add_organization_membership`, which a command path runs before it appends
/// the event — and the half that *writes* never sees it.
///
/// That is not a convention here, it is the type: `Tenancy::apply` takes a `&TenancyEvent`
/// and `Tenancy::fold` takes a `&[TenancyEvent]`, and a `MembershipAuthority` cannot be
/// handed to either. This case is the two halves side by side: the tenant path is refused
/// and the platform path admitted at the decision, and the event the platform decision
/// returned rebuilds the same row through a fold that was told nothing at all.
#[test]
fn the_authority_decides_before_the_event_and_the_fold_applies_it_without_one() {
    let acme = organization(1);
    let elsewhere = organization(2);
    let administrator = context(elsewhere, principal(9));
    let joiner = principal(11);

    let mut tenancy = Tenancy::new();
    let created_acme = tenancy
        .create_organization(&administrator, acme, "Acme")
        .expect("acme");
    let created_elsewhere = tenancy
        .create_organization(&administrator, elsewhere, "Platform")
        .expect("elsewhere");

    assert_eq!(
        tenancy
            .may_add_organization_membership(
                &administrator,
                MembershipAuthority::VerifiedOrganization,
                acme,
                joiner,
            )
            .expect_err("the tenant path may not name another organization")
            .reason,
        DenialReason::Denied
    );
    assert_eq!(
        tenancy
            .decide_add_organization_membership(
                &administrator,
                MembershipAuthority::VerifiedOrganization,
                membership(20),
                acme,
                joiner,
            )
            .expect_err("and the command that runs it refuses on the same rule")
            .reason,
        DenialReason::Denied
    );

    let seeded = tenancy
        .add_organization_membership(
            &administrator,
            MembershipAuthority::PlatformOrganizationAdministration,
            membership(20),
            acme,
            joiner,
        )
        .expect("the platform path may");

    let replayed = Tenancy::fold(&[created_acme, created_elsewhere, seeded]);
    assert_eq!(
        replayed, tenancy,
        "a fold that cannot be handed an authority records the same row"
    );
    assert_eq!(replayed.members_of(acme), vec![joiner]);
}

/// What the fold does still refuse is what would leave the projection malformed, and what
/// a log applied in order never asks of it: a membership of an organization that does not
/// resolve or no longer admits authority, an identity it already holds, and a second
/// active membership of the same organization for the same principal.
#[test]
fn the_fold_refuses_what_would_leave_the_projection_malformed() {
    let acme = organization(1);
    let joiner = principal(11);
    let mut tenancy = Tenancy::new();

    assert_eq!(
        tenancy
            .add_organization_membership(
                &platform(),
                MembershipAuthority::PlatformOrganizationAdministration,
                membership(20),
                acme,
                joiner
            )
            .expect_err("no record of that organization exists")
            .reason,
        DenialReason::Denied
    );

    tenancy
        .create_organization(&platform(), acme, "Acme")
        .expect("acme");
    tenancy
        .add_organization_membership(
            &platform(),
            MembershipAuthority::PlatformOrganizationAdministration,
            membership(20),
            acme,
            joiner,
        )
        .expect("membership");
    for identity in [membership(20), membership(21)] {
        assert_eq!(
            tenancy
                .add_organization_membership(
                    &platform(),
                    MembershipAuthority::PlatformOrganizationAdministration,
                    identity,
                    acme,
                    joiner,
                )
                .expect_err("neither the identity nor the membership is written twice")
                .reason,
            DenialReason::Denied
        );
    }
    assert_eq!(tenancy.record_count(), 2);
}

/// `docs/architecture/combined.md`: "Every tenant-owned record resolves to exactly one
/// organization." The scoped readers are that rule in the API: they answer for the
/// caller's own organization and for a live record only, while the record readers keep
/// answering for a fold or a rebuild, which is what an event applied out of order needs.
#[test]
fn a_scoped_read_answers_only_inside_the_callers_organization_and_only_for_a_live_record() {
    let acme = organization(1);
    let other = organization(2);
    let joiner = principal(11);
    let mut tenancy = Tenancy::new();
    tenancy
        .create_organization(&platform(), acme, "Acme")
        .expect("acme");
    tenancy
        .create_organization(&platform(), other, "Other")
        .expect("other");
    let caller = context(acme, principal(10));
    let outsider = context(other, principal(12));
    tenancy
        .add_organization_membership(
            &platform(),
            MembershipAuthority::PlatformOrganizationAdministration,
            membership(20),
            acme,
            joiner,
        )
        .expect("membership");
    tenancy
        .create_team(&caller, team(30), "Platform")
        .expect("team");
    tenancy
        .add_team_membership(
            &caller,
            team_membership(50),
            team(30),
            joiner,
            contribution(60),
        )
        .expect("team membership");
    tenancy
        .create_space(&caller, space(40), "Production")
        .expect("space");

    assert!(tenancy.resolve_organization(&caller, acme).is_some());
    assert!(
        tenancy.resolve_organization(&outsider, acme).is_none(),
        "an organization does not resolve for a caller verified in another"
    );
    assert!(
        tenancy
            .resolve_organization_membership(&caller, membership(20))
            .is_some()
    );
    assert!(tenancy.resolve_team(&caller, team(30)).is_some());
    assert!(
        tenancy
            .resolve_team_membership(&caller, team_membership(50))
            .is_some()
    );
    assert!(tenancy.resolve_space(&caller, space(40)).is_some());

    for (scoped, recorded) in [
        (
            tenancy
                .resolve_organization_membership(&outsider, membership(20))
                .is_none(),
            tenancy.organization_membership(membership(20)).is_some(),
        ),
        (
            tenancy.resolve_team(&outsider, team(30)).is_none(),
            tenancy.team(team(30)).is_some(),
        ),
        (
            tenancy
                .resolve_team_membership(&outsider, team_membership(50))
                .is_none(),
            tenancy.team_membership(team_membership(50)).is_some(),
        ),
        (
            tenancy.resolve_space(&outsider, space(40)).is_none(),
            tenancy.space(space(40)).is_some(),
        ),
    ] {
        assert!(
            scoped,
            "a record outside the caller's organization is unread"
        );
        assert!(recorded, "while the record reader still holds it");
    }

    let held = tenancy.record_count();
    tenancy
        .remove_team_membership(&caller, team_membership(50))
        .expect("removed");
    tenancy.retire_team(&caller, team(30)).expect("retired");
    tenancy.retire_space(&caller, space(40)).expect("retired");
    tenancy
        .remove_organization_membership(&caller, membership(20))
        .expect("removed");
    tenancy
        .close_organization(&platform(), acme)
        .expect("closed");
    assert!(tenancy.resolve_organization(&caller, acme).is_none());
    assert!(
        tenancy
            .resolve_organization_membership(&caller, membership(20))
            .is_none()
    );
    assert!(tenancy.resolve_team(&caller, team(30)).is_none());
    assert!(
        tenancy
            .resolve_team_membership(&caller, team_membership(50))
            .is_none()
    );
    assert!(tenancy.resolve_space(&caller, space(40)).is_none());
    assert_eq!(
        tenancy.record_count(),
        held,
        "a record that stops resolving is still held"
    );
}

/// `CreateOrganization` denied: "the requested display name is not admitted" has no
/// realization (`src/tenancy.rs`), so the one decided path is an identity already
/// recorded.
#[test]
fn create_organization_denials_leave_the_projection_unchanged() {
    let acme = organization(1);
    let caller = context(acme, principal(10));
    let mut tenancy = Tenancy::new();
    tenancy
        .create_organization(&platform(), acme, "Acme")
        .expect("acme");

    refuses!(
        tenancy,
        tenancy.decide_create_organization(&caller, acme, "Impostor"),
        "the identity is already recorded"
    );
    refuses!(
        tenancy,
        tenancy.create_organization(&platform(), acme, "Impostor"),
        "the command wrapper refuses the identity the decide half refuses"
    );
}

/// `CloseOrganization` denied: the organization does not resolve, or has already been
/// closed.
#[test]
fn close_organization_denials_leave_the_projection_unchanged() {
    let acme = organization(1);
    let caller = context(acme, principal(10));
    let mut tenancy = Tenancy::new();
    tenancy
        .create_organization(&platform(), acme, "Acme")
        .expect("acme");

    refuses!(
        tenancy,
        tenancy.decide_close_organization(&caller, organization(2)),
        "no record of that organization exists"
    );
    tenancy
        .close_organization(&platform(), acme)
        .expect("closed");
    refuses!(
        tenancy,
        tenancy.decide_close_organization(&caller, acme),
        "a terminal state does not move twice"
    );
    refuses!(
        tenancy,
        tenancy.close_organization(&platform(), acme),
        "the command wrapper refuses what the decide half refuses"
    );
}

/// `AddOrganizationMembership` denied: the named organization is not the verified one on
/// the tenant path, does not resolve or is closed, the identity is already held, or the
/// principal already holds an active membership there.
#[test]
fn add_organization_membership_denials_leave_the_projection_unchanged() {
    let acme = organization(1);
    let other = organization(2);
    let caller = context(acme, principal(10));
    let joiner = principal(11);
    let mut tenancy = Tenancy::new();
    tenancy
        .create_organization(&platform(), acme, "Acme")
        .expect("acme");
    tenancy
        .create_organization(&platform(), other, "Other")
        .expect("other");
    tenancy
        .add_organization_membership(
            &platform(),
            MembershipAuthority::PlatformOrganizationAdministration,
            membership(20),
            acme,
            joiner,
        )
        .expect("membership");

    refuses!(
        tenancy,
        tenancy.decide_add_organization_membership(
            &caller,
            MembershipAuthority::VerifiedOrganization,
            membership(21),
            other,
            principal(12),
        ),
        "the tenant path may not name an organization other than the verified one"
    );
    refuses!(
        tenancy,
        tenancy.decide_add_organization_membership(
            &caller,
            MembershipAuthority::PlatformOrganizationAdministration,
            membership(21),
            organization(3),
            principal(12),
        ),
        "no record of that organization exists"
    );
    refuses!(
        tenancy,
        tenancy.decide_add_organization_membership(
            &caller,
            MembershipAuthority::VerifiedOrganization,
            membership(20),
            acme,
            principal(12),
        ),
        "the identity is already held"
    );
    refuses!(
        tenancy,
        tenancy.decide_add_organization_membership(
            &caller,
            MembershipAuthority::VerifiedOrganization,
            membership(21),
            acme,
            joiner,
        ),
        "the principal already holds an active membership there"
    );
    refuses!(
        tenancy,
        tenancy.add_organization_membership(
            &platform(),
            MembershipAuthority::PlatformOrganizationAdministration,
            membership(21),
            acme,
            joiner
        ),
        "the command wrapper refuses what the decide half refuses"
    );

    tenancy
        .close_organization(&platform(), acme)
        .expect("closed");
    refuses!(
        tenancy,
        tenancy.decide_add_organization_membership(
            &caller,
            MembershipAuthority::VerifiedOrganization,
            membership(22),
            acme,
            principal(13),
        ),
        "a closed organization admits no new membership"
    );
}

/// `RemoveOrganizationMembership` denied: the membership does not resolve, is outside the
/// verified organization, or has already been removed.
#[test]
fn remove_organization_membership_denials_leave_the_projection_unchanged() {
    let acme = organization(1);
    let other = organization(2);
    let caller = context(acme, principal(10));
    let outsider = context(other, principal(12));
    let joiner = principal(11);
    let mut tenancy = Tenancy::new();
    tenancy
        .create_organization(&platform(), acme, "Acme")
        .expect("acme");
    tenancy
        .create_organization(&platform(), other, "Other")
        .expect("other");
    tenancy
        .add_organization_membership(
            &platform(),
            MembershipAuthority::PlatformOrganizationAdministration,
            membership(20),
            acme,
            joiner,
        )
        .expect("membership");

    refuses!(
        tenancy,
        tenancy.decide_remove_organization_membership(&caller, membership(21)),
        "no record of that membership exists"
    );
    refuses!(
        tenancy,
        tenancy.decide_remove_organization_membership(&outsider, membership(20)),
        "a membership of another organization is not the outsider's to remove"
    );
    refuses!(
        tenancy,
        tenancy.remove_organization_membership(&outsider, membership(20)),
        "and the command wrapper refuses it too"
    );

    tenancy
        .remove_organization_membership(&caller, membership(20))
        .expect("removed");
    refuses!(
        tenancy,
        tenancy.decide_remove_organization_membership(&caller, membership(20)),
        "a terminal state does not move twice"
    );
}

/// `CreateTeam` denied: the verified organization does not resolve or is closed, or the
/// identity is already recorded.
#[test]
fn create_team_denials_leave_the_projection_unchanged() {
    let acme = organization(1);
    let caller = context(acme, principal(10));
    let stranger = context(organization(2), principal(12));
    let mut tenancy = Tenancy::new();
    tenancy
        .create_organization(&platform(), acme, "Acme")
        .expect("acme");
    tenancy
        .create_team(&caller, team(30), "Platform")
        .expect("team");

    refuses!(
        tenancy,
        tenancy.decide_create_team(&stranger, team(31), "Nowhere"),
        "no record of the verified organization exists"
    );
    refuses!(
        tenancy,
        tenancy.decide_create_team(&caller, team(30), "Impostor"),
        "the identity is already recorded"
    );
    refuses!(
        tenancy,
        tenancy.create_team(&caller, team(30), "Impostor"),
        "and the command wrapper refuses it too"
    );

    tenancy
        .close_organization(&platform(), acme)
        .expect("closed");
    refuses!(
        tenancy,
        tenancy.decide_create_team(&caller, team(32), "Later"),
        "a closed organization admits no team"
    );
}

/// `RetireTeam` denied: the team does not resolve, is outside the verified organization,
/// or has already been retired.
#[test]
fn retire_team_denials_leave_the_projection_unchanged() {
    let acme = organization(1);
    let other = organization(2);
    let caller = context(acme, principal(10));
    let outsider = context(other, principal(12));
    let mut tenancy = Tenancy::new();
    tenancy
        .create_organization(&platform(), acme, "Acme")
        .expect("acme");
    tenancy
        .create_organization(&platform(), other, "Other")
        .expect("other");
    tenancy
        .create_team(&caller, team(30), "Platform")
        .expect("team");

    refuses!(
        tenancy,
        tenancy.decide_retire_team(&caller, team(31)),
        "no record of that team exists"
    );
    refuses!(
        tenancy,
        tenancy.decide_retire_team(&outsider, team(30)),
        "a team in another organization is not the outsider's to retire"
    );
    refuses!(
        tenancy,
        tenancy.retire_team(&outsider, team(30)),
        "and the command wrapper refuses it too"
    );

    tenancy.retire_team(&caller, team(30)).expect("retired");
    refuses!(
        tenancy,
        tenancy.decide_retire_team(&caller, team(30)),
        "a terminal state does not move twice"
    );
}

/// `AddTeamMembership` denied: the verified organization is closed, the team does not
/// resolve inside it or is retired, the principal is not a member of that organization,
/// the identity is already recorded, or the principal already holds a membership of that
/// team.
#[test]
fn add_team_membership_denials_leave_the_projection_unchanged() {
    let acme = organization(1);
    let other = organization(2);
    let caller = context(acme, principal(10));
    let outsider = context(other, principal(12));
    let joiner = principal(11);
    let mut tenancy = Tenancy::new();
    tenancy
        .create_organization(&platform(), acme, "Acme")
        .expect("acme");
    tenancy
        .create_organization(&platform(), other, "Other")
        .expect("other");
    tenancy
        .add_organization_membership(
            &platform(),
            MembershipAuthority::PlatformOrganizationAdministration,
            membership(20),
            acme,
            joiner,
        )
        .expect("membership");
    tenancy
        .create_team(&caller, team(30), "Platform")
        .expect("team");
    tenancy
        .create_team(&caller, team(31), "Retired")
        .expect("team");
    tenancy.retire_team(&caller, team(31)).expect("retired");
    tenancy
        .add_team_membership(
            &caller,
            team_membership(50),
            team(30),
            joiner,
            contribution(60),
        )
        .expect("team membership");

    refuses!(
        tenancy,
        tenancy.decide_add_team_membership(
            &caller,
            team_membership(51),
            team(32),
            joiner,
            contribution(61)
        ),
        "no record of that team exists"
    );
    refuses!(
        tenancy,
        tenancy.decide_add_team_membership(
            &outsider,
            team_membership(51),
            team(30),
            joiner,
            contribution(61)
        ),
        "a team in another organization is not the outsider's to write into"
    );
    refuses!(
        tenancy,
        tenancy.decide_add_team_membership(
            &caller,
            team_membership(51),
            team(31),
            joiner,
            contribution(61)
        ),
        "a retired team admits no membership"
    );
    refuses!(
        tenancy,
        tenancy.decide_add_team_membership(
            &caller,
            team_membership(51),
            team(30),
            principal(13),
            contribution(61)
        ),
        "the principal is not a member of that organization"
    );
    refuses!(
        tenancy,
        tenancy.decide_add_team_membership(
            &caller,
            team_membership(50),
            team(30),
            joiner,
            contribution(61)
        ),
        "the identity is already recorded"
    );
    refuses!(
        tenancy,
        tenancy.decide_add_team_membership(
            &caller,
            team_membership(51),
            team(30),
            joiner,
            contribution(61)
        ),
        "the principal already holds a membership of that team"
    );
    refuses!(
        tenancy,
        tenancy.add_team_membership(
            &caller,
            team_membership(51),
            team(30),
            joiner,
            contribution(61)
        ),
        "and the command wrapper refuses it too"
    );

    tenancy
        .close_organization(&platform(), acme)
        .expect("closed");
    refuses!(
        tenancy,
        tenancy.decide_add_team_membership(
            &caller,
            team_membership(52),
            team(30),
            joiner,
            contribution(62)
        ),
        "a closed organization admits no new team membership"
    );
}

/// `RemoveTeamMembership` denied: the membership does not resolve, is outside the
/// verified organization, or has already been removed.
#[test]
fn remove_team_membership_denials_leave_the_projection_unchanged() {
    let acme = organization(1);
    let other = organization(2);
    let caller = context(acme, principal(10));
    let outsider = context(other, principal(12));
    let joiner = principal(11);
    let mut tenancy = Tenancy::new();
    tenancy
        .create_organization(&platform(), acme, "Acme")
        .expect("acme");
    tenancy
        .create_organization(&platform(), other, "Other")
        .expect("other");
    tenancy
        .add_organization_membership(
            &platform(),
            MembershipAuthority::PlatformOrganizationAdministration,
            membership(20),
            acme,
            joiner,
        )
        .expect("membership");
    tenancy
        .create_team(&caller, team(30), "Platform")
        .expect("team");
    tenancy
        .add_team_membership(
            &caller,
            team_membership(50),
            team(30),
            joiner,
            contribution(60),
        )
        .expect("team membership");

    refuses!(
        tenancy,
        tenancy.decide_remove_team_membership(&caller, team_membership(51)),
        "no record of that team membership exists"
    );
    refuses!(
        tenancy,
        tenancy.decide_remove_team_membership(&outsider, team_membership(50)),
        "a team membership of another organization is not the outsider's to remove"
    );
    refuses!(
        tenancy,
        tenancy.remove_team_membership(&outsider, team_membership(50)),
        "and the command wrapper refuses it too"
    );

    tenancy
        .remove_team_membership(&caller, team_membership(50))
        .expect("removed");
    refuses!(
        tenancy,
        tenancy.decide_remove_team_membership(&caller, team_membership(50)),
        "a terminal state does not move twice"
    );
}

/// `CreateSpace` denied: the verified organization does not resolve or is closed, or the
/// identity is already recorded.
#[test]
fn create_space_denials_leave_the_projection_unchanged() {
    let acme = organization(1);
    let caller = context(acme, principal(10));
    let stranger = context(organization(2), principal(12));
    let mut tenancy = Tenancy::new();
    tenancy
        .create_organization(&platform(), acme, "Acme")
        .expect("acme");
    tenancy
        .create_space(&caller, space(40), "Production")
        .expect("space");

    refuses!(
        tenancy,
        tenancy.decide_create_space(&stranger, space(41), "Nowhere"),
        "no record of the verified organization exists"
    );
    refuses!(
        tenancy,
        tenancy.decide_create_space(&caller, space(40), "Impostor"),
        "the identity is already recorded"
    );
    refuses!(
        tenancy,
        tenancy.create_space(&caller, space(40), "Impostor"),
        "and the command wrapper refuses it too"
    );

    tenancy
        .close_organization(&platform(), acme)
        .expect("closed");
    refuses!(
        tenancy,
        tenancy.decide_create_space(&caller, space(42), "Later"),
        "a closed organization admits no space"
    );
}

/// `RetireSpace` denied: the space does not resolve, is outside the verified
/// organization, or has already been retired.
#[test]
fn retire_space_denials_leave_the_projection_unchanged() {
    let acme = organization(1);
    let other = organization(2);
    let caller = context(acme, principal(10));
    let outsider = context(other, principal(12));
    let mut tenancy = Tenancy::new();
    tenancy
        .create_organization(&platform(), acme, "Acme")
        .expect("acme");
    tenancy
        .create_organization(&platform(), other, "Other")
        .expect("other");
    tenancy
        .create_space(&caller, space(40), "Production")
        .expect("space");

    refuses!(
        tenancy,
        tenancy.decide_retire_space(&caller, space(41)),
        "no record of that space exists"
    );
    refuses!(
        tenancy,
        tenancy.decide_retire_space(&outsider, space(40)),
        "a space in another organization is not the outsider's to retire"
    );
    refuses!(
        tenancy,
        tenancy.retire_space(&outsider, space(40)),
        "and the command wrapper refuses it too"
    );

    tenancy.retire_space(&caller, space(40)).expect("retired");
    refuses!(
        tenancy,
        tenancy.decide_retire_space(&caller, space(40)),
        "a terminal state does not move twice"
    );
}

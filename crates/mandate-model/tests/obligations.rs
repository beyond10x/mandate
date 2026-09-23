//! The denial clauses of `mandate.tenancy` that `contracts/obligations/model.json`
//! carried unbound, each driven to exactly the clause it names on the shipped path.
//!
//! `story:obligation-registry` split every implemented command's declared
//! `condition.cause` into its clauses and bound the two an existing case already decided.
//! Thirty-eight were left `blocked_on: story:obligations-model`, which is this file. Ten
//! of them are produced by a `decide_*` half of `crates/mandate-model/src/tenancy.rs` and
//! are decided here; the other twenty-eight are produced by no code this crate ships, and
//! the document re-points each at the owner of the path that would have to refuse. Two of
//! the ten bundled two conditions with different deciders, and each is now tiled into the
//! condition this file decides and the one nothing here does, so thirty are deferred and
//! the crate publishes forty-two clauses. Both halves are listed below.
//!
//! # Why every case here carries a control
//!
//! `tenancy.yaml` gives each command one `denied` clause and one error, so
//! [`mandate_model::tenancy::Denied`] carries `DenialReason::Denied` and nothing else —
//! no discriminator saying *which* declared condition fired, unlike
//! `mandate_federation::Denied` or `mandate_identity::Denial` (`story:refusal-
//! discriminators`). Asserting the reason alone would therefore let any refusal of the
//! command satisfy any clause of it, which is the one thing this registry exists to stop.
//!
//! Each case answers that by pairing the refusal with a **control on the same
//! projection**: the same call, with the one condition the clause names repaired and
//! every other input identical, is accepted. A world in which only the named condition
//! fails, and which accepts the moment that condition is repaired, is what makes the
//! refusal attributable to that clause. Each refusal additionally asserts the projection
//! is byte-identical to the one the decision was read from — the `no_state_change`
//! obligation, on the mutating record half rather than on the `&self` decide half.
//!
//! # What is bound here
//!
//! | command | clause | guard |
//! |---|---|---|
//! | `AddOrganizationMembership` | organization_id differs from the verified organization | `src/tenancy.rs:751-755` |
//! | `AddOrganizationMembership` | the principal is already a member of that organization | `src/tenancy.rs:756-758`, `is_member` |
//! | `AddTeamMembership` | team (the team half of the unresolved/outside clause) | `src/tenancy.rs:986-989` |
//! | `AddTeamMembership` | the team is retired | `src/tenancy.rs:987-988`, `TeamState::Recorded` |
//! | `AddTeamMembership` | the principal is already a member of that team | `src/tenancy.rs:992`, `holds_team_membership` |
//! | `CloseOrganization` | the organization is unresolved | `src/tenancy.rs:703-709` |
//! | `RemoveOrganizationMembership` | membership is outside the verified organization | `src/tenancy.rs:851-855` |
//! | `RemoveTeamMembership` | the membership is outside the verified organization | `src/tenancy.rs:1040-1044` |
//! | `RetireSpace` | the space is outside the verified organization | `src/tenancy.rs:1123-1126` |
//! | `RetireTeam` | the team is outside the verified organization | `src/tenancy.rs:934-937` |
//!
//! # What is not here, and why no case could bind it
//!
//! Thirty clauses stay deferred, none for want of a case:
//!
//! * **The eleven authority clauses** — the ten `Caller lacks … authority` clauses, one per
//!   command, and `AddOrganizationMembership`'s "the caller lacks platform
//!   organization-administration authority", tiled off the clause this file's first case
//!   backs. `src/tenancy.rs:93-96` states that whether a caller holds the authority a command
//!   names "is `mandate-authz`'s and is decided nowhere here";
//!   [`mandate_model::tenancy::MembershipAuthority`] is the caller's statement of which
//!   declared path it was admitted to, not a grant. `decision-blocker:guards`.
//! * **The three display-name clauses** — `src/tenancy.rs:121-125`: "no admission rule for a
//!   display name exists to implement: the compiled entity declares `display_name` as a bare
//!   string with no pattern, length or uniqueness, and no document in `systems/mandate` states
//!   one. This fold admits every string, the empty one included and nothing trimmed".
//!   `decision-blocker:guards`, whose own text asks for the actual validation.
//! * **The nine cross-record transactional clauses** — "cannot commit consistently",
//!   "cannot be invalidated with the closure", "cannot be created without implying …",
//!   "cannot revoke the grants that target it …". `src/tenancy.rs:79-91`: "this crate does
//!   not close the window between a decision and the append that follows it, and no method
//!   here promises to. **The command path closes it**". Each `decide_*` is a single-entity
//!   transition over this one projection, which is exactly what
//!   `decision-blocker:epoch-atomicity` holds open.
//! * **`CloseOrganization`, "closure would require destroying membership or audit
//!   history"** — `Tenancy::apply` inserts at an identity or moves a state and removes
//!   nothing (`src/tenancy.rs:1354-1365`), and `docs/adr/0009-event-sourced-persistence.md`
//!   makes that the rule rather than this fold's choice, so no closure can reach the
//!   condition. Deletion and retention are `decision-blocker:lifecycle`'s.
//! * **The three `mandate.directory` clauses** — `src/tenancy.rs:182-191`:
//!   "`mandate.directory`'s records — group-team mappings and membership contributions — are
//!   projected nowhere here, so this fold cannot see one to refuse on", the group that names
//!   all three; and, of the one such record an accepted outcome of this fold names,
//!   `src/tenancy.rs:100-105`: "That record belongs to `mandate.directory` and to
//!   `story:directory-provenance`, so what is owed here is this sentence, not the record".
//!   No projection here holds a contributing mapping to refuse on.
//! * **The three principal clauses** — `AddOrganizationMembership`, "the principal is
//!   unresolved or disabled"; `AddTeamMembership`, "principal is unresolved or outside
//!   the verified organization", tiled off the clause the team-membership case backs; and
//!   `AddTeamMembership`, "the principal is disabled" — [`Tenancy`] holds five
//!   projections and no principal (`src/tenancy.rs:548-554`), so an unresolved principal
//!   is unobservable here; and `mandate.identity.PrincipalDisabled` is folded nowhere in
//!   the workspace (`crates/mandate-identity/src/lib.rs:219-226`,
//!   `crates/mandate-conformance/src/commands/mod.rs:194`), so no world presents a
//!   disabled one. `story:declared-writers`.
//!
//! `contracts/obligations/model.json` records which story or blocker owns each of those
//! paths.

use mandate_model::tenancy::{MembershipAuthority, Tenancy};
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

/// The organization every case is verified in.
fn acme() -> OrganizationId {
    organization(1)
}

/// A second organization, holding a record of every kind, that no case is verified in.
fn other() -> OrganizationId {
    organization(2)
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
        correlation: CorrelationId::new("obligations"),
    }
}

/// The platform administrator's verified context, whose own organization is never the one
/// being written: `CreateOrganization` and `CloseOrganization` are platform-scoped and
/// `AddOrganizationMembership` has a platform path.
fn platform() -> VerifiedContext {
    context(organization(0xfff0), principal(0xfff1))
}

/// A caller verified in `acme`, holding an active membership of it.
fn caller() -> VerifiedContext {
    context(acme(), principal(100))
}

/// A caller verified in `other`, holding an active membership of it.
fn outsider() -> VerifiedContext {
    context(other(), principal(101))
}

/// A refusal carries the declared reason and moves nothing.
///
/// The projection is cloned before the call and compared after it, so the
/// `no_state_change` half of every case below is an assertion rather than a claim — and it
/// is made on the record half, which writes, not on the `decide_*` half, which takes
/// `&self` and could not write if it tried.
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

/// Two organizations, each holding a membership, a team and a space, and a team membership
/// in the second — the smallest world in which every clause below is the one condition
/// that fails.
fn world() -> Tenancy {
    let mut tenancy = Tenancy::new();
    tenancy
        .create_organization(&platform(), acme(), "Acme")
        .expect("acme is created");
    tenancy
        .create_organization(&platform(), other(), "Other")
        .expect("other is created");
    for (identity, organization, subject) in [
        (membership(10), acme(), principal(100)),
        (membership(12), acme(), principal(102)),
        (membership(11), other(), principal(101)),
    ] {
        tenancy
            .add_organization_membership(
                &platform(),
                MembershipAuthority::PlatformOrganizationAdministration,
                identity,
                organization,
                subject,
            )
            .expect("the platform path populates each organization");
    }
    tenancy
        .create_team(&caller(), team(20), "Acme platform")
        .expect("acme holds a team");
    tenancy
        .create_team(&outsider(), team(21), "Other platform")
        .expect("other holds a team");
    tenancy
        .create_space(&caller(), space(30), "Acme production")
        .expect("acme holds a space");
    tenancy
        .create_space(&outsider(), space(31), "Other production")
        .expect("other holds a space");
    tenancy
        .add_team_membership(
            &outsider(),
            team_membership(40),
            team(21),
            principal(101),
            contribution(41),
        )
        .expect("other holds a team membership");
    tenancy
}

// ==================================================================================
// mandate.tenancy.AddOrganizationMembership
// ==================================================================================

/// "organization_id differs from the verified organization": `src/tenancy.rs` decides this
/// in [`mandate_model::tenancy::Tenancy::may_add_organization_membership`], the only reader
/// of [`MembershipAuthority`] in the crate, before any record guard.
///
/// The declared cause joins that condition to "the caller lacks platform
/// organization-administration authority" with `and`, and the two have different deciders:
/// the fold compares the organizations, and it reads the authority the caller states without
/// validating it against anything. So the second is a clause of its own, carries no test and
/// defers to `decision-blocker:guards`, and this row claims the comparison alone.
///
/// The control is the same call naming the verified organization — the one condition this
/// clause names, repaired, with the path and every other input identical — so what refused is
/// the comparison and nothing else. The acceptance after it drives the other side of the same
/// comparison: `tenancy.yaml` states that `organization_id` "may differ only for a caller
/// holding platform organization-administration authority, which is how the organization
/// `CreateOrganization` returns is first populated", and the fold admits that path on the
/// caller's word.
#[test]
fn a_membership_named_outside_the_verified_organization_without_platform_authority_is_refused() {
    let mut tenancy = world();
    refuses!(
        tenancy,
        tenancy.add_organization_membership(
            &caller(),
            MembershipAuthority::VerifiedOrganization,
            membership(50),
            other(),
            principal(200),
        ),
        "a tenant-path caller naming another organization is refused"
    );

    tenancy
        .add_organization_membership(
            &caller(),
            MembershipAuthority::VerifiedOrganization,
            membership(50),
            acme(),
            principal(200),
        )
        .expect("the same call naming the verified organization is admitted");

    tenancy
        .add_organization_membership(
            &caller(),
            MembershipAuthority::PlatformOrganizationAdministration,
            membership(52),
            other(),
            principal(200),
        )
        .expect("the same membership on the platform path is admitted");
}

/// "the principal is already a member of that organization": a principal holds one active
/// membership of one organization, and the second is refused at a fresh identity, so the
/// refusal is the membership rule rather than the identity guard.
///
/// The control is the same call for a principal of the same organization that holds no
/// membership of it.
#[test]
fn a_second_active_membership_of_one_organization_for_one_principal_is_refused() {
    let mut tenancy = world();
    refuses!(
        tenancy,
        tenancy.add_organization_membership(
            &caller(),
            MembershipAuthority::VerifiedOrganization,
            membership(51),
            acme(),
            principal(100),
        ),
        "a principal already holding an active membership there is refused a second"
    );

    tenancy
        .add_organization_membership(
            &caller(),
            MembershipAuthority::VerifiedOrganization,
            membership(51),
            acme(),
            principal(201),
        )
        .expect("the same identity admits a principal that holds no membership there");
}

// ==================================================================================
// mandate.tenancy.AddTeamMembership
// ==================================================================================

/// "team": the declared cause reads "team or principal is unresolved or outside the
/// verified organization", and `contracts/obligations/model.json` tiles that condition into
/// two clauses — "team", which this case backs, and "principal is unresolved or outside
/// the verified organization", which carries no test and defers to `story:declared-writers`.
/// "team" lies inside "the team is retired", "the principal is already a member of that
/// team" and "Caller lacks team-administration authority", and the registry step admits it
/// anyway: nesting is a question of position in the cause, which the step's tiling walk
/// answers, and this "team" sits at a position of its own.
///
/// Both halves of the team condition the fold can observe are driven — a team identity it
/// holds nothing at, and a team it holds in another organization. The second is the one
/// `tenancy.yaml` publishes as isolation: the team exists, and it is not this caller's.
///
/// The principal half of the clause is not decided here and is not claimed to be, which is
/// why it is a clause of its own rather than a condition bundled into this row: `Tenancy`
/// holds no principal projection, so it answers identically for a principal other records in
/// the world name and for one nothing names. See the module documentation.
///
/// The control is the same call naming the team of the verified organization.
#[test]
fn a_team_membership_of_an_unresolved_team_or_of_a_team_in_another_organization_is_refused() {
    let mut tenancy = world();
    refuses!(
        tenancy,
        tenancy.add_team_membership(
            &caller(),
            team_membership(60),
            team(0x7fff),
            principal(100),
            contribution(70),
        ),
        "a team identity the fold holds nothing at is refused"
    );
    refuses!(
        tenancy,
        tenancy.add_team_membership(
            &caller(),
            team_membership(60),
            team(21),
            principal(100),
            contribution(70),
        ),
        "a team the fold holds in another organization is refused"
    );

    tenancy
        .add_team_membership(
            &caller(),
            team_membership(60),
            team(20),
            principal(100),
            contribution(70),
        )
        .expect("the team of the verified organization admits the same membership");
}

/// "the team is retired": retirement keeps the record and moves its state, and a retired
/// team stops admitting membership. The control is a team of the same organization, at the
/// same identity space and with the same caller, that was never retired — so the state is
/// the only input that differs.
#[test]
fn a_team_membership_added_to_a_retired_team_is_refused() {
    let mut tenancy = world();
    tenancy
        .create_team(&caller(), team(22), "Acme second")
        .expect("a second team of the verified organization");
    tenancy
        .retire_team(&caller(), team(20))
        .expect("the first team retires");

    refuses!(
        tenancy,
        tenancy.add_team_membership(
            &caller(),
            team_membership(61),
            team(20),
            principal(100),
            contribution(71),
        ),
        "a retired team admits no membership"
    );

    tenancy
        .add_team_membership(
            &caller(),
            team_membership(61),
            team(22),
            principal(100),
            contribution(71),
        )
        .expect("a team that is still recorded admits the same membership");
}

/// "the principal is already a member of that team": the second membership is refused at a
/// fresh identity, so what refused is the one-membership-per-principal-per-team rule and
/// not the identity guard.
///
/// The control is the same call for another principal of the same organization.
#[test]
fn a_second_membership_of_one_team_for_one_principal_is_refused() {
    let mut tenancy = world();
    tenancy
        .add_team_membership(
            &caller(),
            team_membership(62),
            team(20),
            principal(100),
            contribution(72),
        )
        .expect("the principal joins the team");

    refuses!(
        tenancy,
        tenancy.add_team_membership(
            &caller(),
            team_membership(63),
            team(20),
            principal(100),
            contribution(73),
        ),
        "a principal already holding a membership of that team is refused a second"
    );

    tenancy
        .add_team_membership(
            &caller(),
            team_membership(63),
            team(20),
            principal(102),
            contribution(73),
        )
        .expect("the same identity admits a principal that holds no membership of that team");
}

// ==================================================================================
// mandate.tenancy.CloseOrganization
// ==================================================================================

/// "the organization is unresolved": the command is platform-scoped, so no verified
/// organization bounds which organization may be named and the only thing that can refuse
/// a well-formed identity is that the fold holds no record at it.
///
/// The control is the same platform caller closing an organization the fold does hold.
#[test]
fn closing_an_organization_the_fold_does_not_hold_is_refused() {
    let mut tenancy = world();
    refuses!(
        tenancy,
        tenancy.close_organization(&platform(), organization(0x7ffe)),
        "an organization the fold holds no record at is refused"
    );

    tenancy
        .close_organization(&platform(), acme())
        .expect("an organization the fold holds is closed by the same caller");
}

// ==================================================================================
// mandate.tenancy.RemoveOrganizationMembership
// ==================================================================================

/// "membership is outside the verified organization": the membership resolves, is active,
/// and belongs to the other organization. `src/tenancy.rs:212-218` records that this fold
/// refuses a record of another organization exactly as it refuses an unrecorded one — the
/// reason channel is closed — so the control is what says which of the two fired.
///
/// The control is the same membership removed by a caller verified in the organization it
/// is in.
#[test]
fn removing_an_organization_membership_of_another_organization_is_refused() {
    let mut tenancy = world();
    refuses!(
        tenancy,
        tenancy.remove_organization_membership(&caller(), membership(11)),
        "a membership of another organization is refused"
    );

    tenancy
        .remove_organization_membership(&outsider(), membership(11))
        .expect("the organization the membership is in removes it");
}

// ==================================================================================
// mandate.tenancy.RemoveTeamMembership
// ==================================================================================

/// "the membership is outside the verified organization": the team membership resolves and
/// is recorded, in the other organization.
///
/// The control is the same membership removed by a caller verified in that organization.
#[test]
fn removing_a_team_membership_of_another_organization_is_refused() {
    let mut tenancy = world();
    refuses!(
        tenancy,
        tenancy.remove_team_membership(&caller(), team_membership(40)),
        "a team membership of another organization is refused"
    );

    tenancy
        .remove_team_membership(&outsider(), team_membership(40))
        .expect("the organization the membership is in removes it");
}

// ==================================================================================
// mandate.tenancy.RetireSpace
// ==================================================================================

/// "the space is outside the verified organization": the space resolves and is recorded, in
/// the other organization.
///
/// The control is the same space retired by a caller verified in that organization.
#[test]
fn retiring_a_space_of_another_organization_is_refused() {
    let mut tenancy = world();
    refuses!(
        tenancy,
        tenancy.retire_space(&caller(), space(31)),
        "a space of another organization is refused"
    );

    tenancy
        .retire_space(&outsider(), space(31))
        .expect("the organization the space is in retires it");
}

// ==================================================================================
// mandate.tenancy.RetireTeam
// ==================================================================================

/// "the team is outside the verified organization": the team resolves and is recorded, in
/// the other organization.
///
/// The control is the same team retired by a caller verified in that organization.
#[test]
fn retiring_a_team_of_another_organization_is_refused() {
    let mut tenancy = world();
    refuses!(
        tenancy,
        tenancy.retire_team(&caller(), team(21)),
        "a team of another organization is refused"
    );

    tenancy
        .retire_team(&outsider(), team(21))
        .expect("the organization the team is in retires it");
}

// ==================================================================================
// The citations this file makes, against the files they name
// ==================================================================================

/// One `file:line` span this file's documentation cites, and the phrases those lines must
/// hold for the claim made of them to be readable there.
///
/// Every span above was written against the fold at this unit's base commit. The unit's own
/// diff and correction 1's rewrite of the fold's module documentation then added seventy-three
/// lines above the `impl Tenancy` block, and thirteen citations stayed where they were: the
/// row citing `holds_team_membership` named `self.apply(&event);` inside `create_team`, and
/// the quotation the display-name deferral rests on named a paragraph about something else.
/// Both corrections were made by re-reading the citations, and re-reading is what had already
/// failed, so the re-read is a case rather than a claim.
///
/// The table is closed both ways by
/// [`every_citation_this_file_makes_states_what_it_is_cited_for`]: a cited span that does not
/// hold its phrase is refused, and so is a span cited above that this table does not carry —
/// so a citation added later is unchecked only until the suite next runs.
const CITED: &[(&str, &[&str])] = &[
    (
        "src/tenancy.rs:751-755",
        &[
            "authority == MembershipAuthority::VerifiedOrganization",
            "organization_id != context.organization",
        ],
    ),
    (
        "src/tenancy.rs:756-758",
        &["self.is_member(organization_id, principal_id)"],
    ),
    (
        "src/tenancy.rs:986-989",
        &[
            "self.teams.get(&team_id)",
            "team.organization_id == context.organization",
        ],
    ),
    ("src/tenancy.rs:987-988", &["TeamState::Recorded"]),
    (
        "src/tenancy.rs:992",
        &["self.holds_team_membership(team_id, principal_id)"],
    ),
    (
        "src/tenancy.rs:703-709",
        &[
            "record.state == OrganizationState::Recorded",
            "if !admitted",
        ],
    ),
    (
        "src/tenancy.rs:851-855",
        &[
            "membership.organization_id != context.organization",
            "OrganizationMembershipState::Active",
        ],
    ),
    (
        "src/tenancy.rs:1040-1044",
        &[
            "membership.organization_id != context.organization",
            "TeamMembershipState::Recorded",
        ],
    ),
    (
        "src/tenancy.rs:1123-1126",
        &["space.organization_id != context.organization"],
    ),
    (
        "src/tenancy.rs:934-937",
        &["team.organization_id != context.organization"],
    ),
    (
        "src/tenancy.rs:93-96",
        &[
            "is `mandate-authz`'s and is decided nowhere here",
            "the caller's statement of which of the contract's two paths it was admitted to, \
             not a grant",
        ],
    ),
    (
        "src/tenancy.rs:121-125",
        &[
            "no admission rule for a display name exists to implement",
            "This fold admits every string, the empty one included and nothing trimmed",
        ],
    ),
    (
        "src/tenancy.rs:79-91",
        &[
            "this crate does not close the window between a decision and the append that \
             follows it",
            "**The command path closes it**",
        ],
    ),
    (
        "src/tenancy.rs:1354-1365",
        &["an insert at the record's own identity or a state move at it"],
    ),
    (
        "src/tenancy.rs:182-191",
        &[
            "Owed to `story:directory-provenance`",
            "are projected nowhere here, so this fold cannot see one to refuse on",
        ],
    ),
    (
        "src/tenancy.rs:100-105",
        &["`mandate.directory.MembershipContribution`"],
    ),
    ("src/tenancy.rs:548-554", &["pub struct Tenancy"]),
    (
        "src/tenancy.rs:212-218",
        &["the **reason** channel is closed"],
    ),
    (
        "crates/mandate-identity/src/lib.rs:219-226",
        &["\"mandate.identity.PrincipalDisabled\""],
    ),
    (
        "crates/mandate-conformance/src/commands/mod.rs:194",
        &["mandate.identity.PrincipalDisabled is folded nowhere"],
    ),
];

/// Every file this documentation names **without** a line number: where it is written from the
/// workspace root, and the phrases it is quoted for.
///
/// A file cited whole claims less than a span does, so it is checked whole, and a name the
/// prose wraps in backticks is the same name in a source that does not — both sides are read
/// with that markup removed. The table is closed both ways for the same reason [`CITED`] is:
/// [`every_citation_this_file_makes_states_what_it_is_cited_for`] refuses a file named above
/// that this table does not carry.
const NAMED: &[(&str, &str, &[&str])] = &[
    (
        "contracts/obligations/model.json",
        "contracts/obligations/model.json",
        &[
            "\"team\"",
            "principal is unresolved or outside the verified organization",
            "organization_id differs from the verified organization",
            "the caller lacks platform organization-administration authority",
        ],
    ),
    (
        "crates/mandate-model/src/tenancy.rs",
        "crates/mandate-model/src/tenancy.rs",
        &[],
    ),
    ("src/tenancy.rs", "src/tenancy.rs", &[]),
    (
        "tenancy.yaml",
        "systems/mandate/domains/tenancy.yaml",
        &[
            "may differ only for a caller holding platform organization-administration \
             authority, which is how the organization CreateOrganization returns is first \
             populated",
        ],
    ),
    (
        "docs/adr/0009-event-sourced-persistence.md",
        "docs/adr/0009-event-sourced-persistence.md",
        &[],
    ),
];

fn manifest() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The file a cited path names, whether it is written from this crate or from the workspace
/// root.
fn resolve(path: &str) -> std::path::PathBuf {
    if path.starts_with("src/") || path.starts_with("tests/") {
        manifest().join(path)
    } else {
        manifest().join("../..").join(path)
    }
}

/// One run of text with its comment markers stripped and its whitespace collapsed, so a
/// citation or a quotation wrapped across lines reads as one run.
fn normalized(text: &str) -> String {
    text.lines()
        .map(|line| {
            line.trim()
                .trim_start_matches("//!")
                .trim_start_matches("///")
                .trim()
        })
        .collect::<Vec<&str>>()
        .join(" ")
        .split_whitespace()
        .collect::<Vec<&str>>()
        .join(" ")
}

/// A quoted file read as the prose that quotes it writes it: the documentation's own backticks
/// are markup and the source does not carry them.
fn unmarked(text: &str) -> String {
    normalized(text).replace('`', "")
}

/// This file's own documentation — every `//!` and `///` line — as one normalized run.
fn documentation() -> String {
    let source = std::fs::read_to_string(manifest().join("tests/obligations.rs"))
        .expect("this file reads itself");
    let doc: Vec<&str> = source
        .lines()
        .map(str::trim_start)
        .filter(|line| line.starts_with("//!") || line.starts_with("///"))
        .collect();
    normalized(&doc.join("\n"))
}

/// Every `<path>.rs:<first>[-<last>]` span the text cites, in the order it cites them.
///
/// Read off the text rather than listed by hand: a citation nobody transcribed into [`CITED`]
/// is the defect this case exists for, so the set it checks may not be a transcription either.
fn cited_spans(text: &str) -> Vec<String> {
    let bytes = text.as_bytes();
    let mut found = Vec::new();
    for (at, _) in text.match_indices(".rs:") {
        let mut first = at;
        while first > 0
            && (matches!(bytes[first - 1], b'_' | b'-' | b'/' | b'.')
                || bytes[first - 1].is_ascii_alphanumeric())
        {
            first -= 1;
        }
        let mut last = at + ".rs:".len();
        while bytes.get(last).is_some_and(u8::is_ascii_digit) {
            last += 1;
        }
        if last == at + ".rs:".len() {
            continue;
        }
        if bytes.get(last) == Some(&b'-') && bytes.get(last + 1).is_some_and(u8::is_ascii_digit) {
            last += 1;
            while bytes.get(last).is_some_and(u8::is_ascii_digit) {
                last += 1;
            }
        }
        found.push(text[first..last].to_owned());
    }
    found
}

/// Every file the text names without a line number, in the order it names them.
fn named_files(text: &str) -> Vec<String> {
    const EXTENSIONS: [&str; 4] = [".rs", ".md", ".json", ".yaml"];

    let mut found = Vec::new();
    for token in text.split([' ', '`', '(', ')', '"', ',', ';', '\n']) {
        let token = token.trim_end_matches(['.', ':', '\'', '*', '!', '?']);
        if token.contains(".rs:") {
            continue;
        }
        if EXTENSIONS.iter().any(|suffix| token.ends_with(suffix)) {
            found.push(token.to_owned());
        }
    }
    found
}

/// Every quotation the text attributes to a span, in the form ``` `src/tenancy.rs:A-B`: "…"
/// ```, as `(span, quotation)`.
fn attributed(text: &str) -> Vec<(String, String)> {
    let mut rows = Vec::new();
    for span in cited_spans(text) {
        let mut from = 0;
        while let Some(at) = text[from..].find(span.as_str()) {
            from += at + span.len();
            let Some(rest) = text[from..].strip_prefix("`: \"") else {
                continue;
            };
            let Some(close) = rest.find('"') else {
                continue;
            };
            rows.push((span.clone(), rest[..close].to_owned()));
        }
    }
    rows
}

/// The lines a span citation names, normalized, or why they cannot be read.
fn cited_lines(citation: &str) -> Result<String, String> {
    let (path, span) = citation
        .rsplit_once(':')
        .ok_or_else(|| format!("{citation}: names no line"))?;
    let (first, last) = span.split_once('-').unwrap_or((span, span));
    let (first, last) = (
        first
            .parse::<usize>()
            .map_err(|error| format!("{citation}: {error}"))?,
        last.parse::<usize>()
            .map_err(|error| format!("{citation}: {error}"))?,
    );
    let file = resolve(path);
    let text =
        std::fs::read_to_string(&file).map_err(|error| format!("{}: {error}", file.display()))?;
    let lines: Vec<&str> = text.lines().collect();
    if first < 1 || last < first || last > lines.len() {
        return Err(format!(
            "{citation} is no span {path} has, which holds {} lines",
            lines.len()
        ));
    }
    Ok(normalized(&lines[first - 1..last].join("\n")))
}

/// Every span this file cites holds what it is cited for, every quotation it attributes to a
/// span is verbatim inside that span, and every file and span it names is one this case reads.
///
/// A `file:line` citation is the one form a reader verifies by opening the file at that line,
/// which is exactly why a wrong one survives review: it reads as precise. Thirteen of them
/// shipped in this file before this case existed — every row of the table above and three of
/// the justifications below it — and the deferral of the three display-name clauses rested on
/// a sentence the fold did not contain at all. Nothing in the gate read a citation, so the
/// only reader was an adversary.
#[test]
fn every_citation_this_file_makes_states_what_it_is_cited_for() {
    let documentation = documentation();
    let made = cited_spans(&documentation);
    let quotations = attributed(&documentation);
    let files = named_files(&documentation);
    let mut wrong: Vec<String> = Vec::new();

    assert!(
        made.len() >= 13 && !quotations.is_empty() && !files.is_empty(),
        "this file's documentation parsed as {} span(s), {} quotation(s) and {} named file(s). \
         The guard table alone cites ten spans and the deferrals below it quote the fold, so a \
         parse that finds fewer is reading something other than this file's documentation and \
         would check nothing",
        made.len(),
        quotations.len(),
        files.len()
    );

    for citation in &made {
        let Some((_, phrases)) = CITED.iter().find(|(cited, _)| cited == citation) else {
            wrong.push(format!(
                "{citation} is cited above and CITED does not carry it, so nothing checks that \
                 those lines state what they are cited for"
            ));
            continue;
        };
        match cited_lines(citation) {
            Err(reason) => wrong.push(reason),
            Ok(read) => {
                for phrase in *phrases {
                    if !read.contains(&normalized(phrase)) {
                        wrong.push(format!(
                            "{citation} is cited for {phrase:?} and holds no such text; it \
                             reads:\n{read}"
                        ));
                    }
                }
            }
        }
    }
    for (cited, _) in CITED {
        if !made.iter().any(|citation| citation == cited) {
            wrong.push(format!(
                "CITED carries {cited} and this file cites no such span, so the table is a \
                 record of a citation that has moved or gone"
            ));
        }
    }

    for (span, quotation) in &quotations {
        match cited_lines(span) {
            Err(reason) => wrong.push(reason),
            Ok(read) => {
                if !read.contains(&normalized(quotation)) {
                    wrong.push(format!(
                        "{span} is quoted as {quotation:?}, which those lines do not say; they \
                         read:\n{read}"
                    ));
                }
            }
        }
    }

    for file in &files {
        if !NAMED.iter().any(|(named, _, _)| named == file) {
            wrong.push(format!(
                "{file} is named above and NAMED does not carry it, so nothing checks that the \
                 file exists or says what it is named for"
            ));
        }
    }
    for (named, path, phrases) in NAMED {
        if !files.iter().any(|file| file == named) {
            wrong.push(format!(
                "NAMED carries {named} and this file names no such file"
            ));
            continue;
        }
        let file = resolve(path);
        match std::fs::read_to_string(&file) {
            Err(error) => wrong.push(format!("{}: {error}", file.display())),
            Ok(text) => {
                let read = unmarked(&text);
                for phrase in *phrases {
                    if !read.contains(&unmarked(phrase)) {
                        wrong.push(format!(
                            "{named} is cited for {phrase:?} and holds no such text"
                        ));
                    }
                }
            }
        }
    }

    assert!(
        wrong.is_empty(),
        "this file makes {} citation(s) that do not state what they are cited for, of {} \
         span(s), {} attributed quotation(s) and {} named file(s):\n\n{}",
        wrong.len(),
        made.len(),
        quotations.len(),
        files.len(),
        wrong.join("\n\n"),
    );
}

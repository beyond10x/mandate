//! The `mandate.tenancy` projections and the fold that writes them.
//!
//! `systems/mandate/domains/tenancy.yaml` declares five entities and ten commands over
//! them. Each command's accepted outcome has a record half — the projection it writes and
//! the state it moves — and that half is one method here.
//!
//! None of the five is declared through [`mandate_types::canonical_record`]: that macro
//! hardcodes the `mandate.core.` prefix (`crates/mandate-types/src/macros.rs`), and every
//! entity here is `mandate.tenancy.*`. They are plain `serde` projections, and
//! `crates/mandate-model/tests/projections.rs` decides them against the compiled entity
//! in `generated/schema/entities` instead. Every field of all five is still bounded by
//! [`mandate_types::PersistedValue`]; the assertion at the end of this module is that
//! bound, and it does not compile if a field is added that the boundary does not admit.
//!
//! # These projections are rebuildable from the log
//!
//! `docs/adr/0009-event-sourced-persistence.md` states that the events are the record and
//! that state tables are "derived, droppable, rebuildable, never authoritative". All five
//! are, and saying so is the point of this section:
//!
//! | required field | the event that carries it | what it declares |
//! |---|---|---|
//! | `Organization.display_name` | `mandate.tenancy.OrganizationCreated` | `context`, `organization_id`, `display_name` |
//! | `Team.display_name` | `mandate.tenancy.TeamCreated` | `context`, `team_id`, `display_name` |
//! | `Space.display_name` | `mandate.tenancy.SpaceCreated` | `context`, `space_id`, `display_name` |
//!
//! The compiled entity marks each `display_name` required, and until
//! `story:event-payloads-for-folds` landed no event declared one: dropping the projection
//! and replaying the log brought the identity and the organization back and lost the name,
//! and this fold was authoritative for those three fields rather than derived. The three
//! creation events now declare `display_name`, so every required field of all five reads
//! out of the log. `crate::graph` records the same close for
//! `mandate.graph.Resource.resource_type`.
//!
//! `crates/mandate-model/tests/adversary_tenancy_topology.rs`
//! `every_required_projection_field_is_carried_by_a_declared_event` decides this against
//! `generated/schema`, for these five and for `mandate.graph.Resource`: it asserts the set
//! of orphaned required fields is empty, so a field dropping out of an event turns it red.
//!
//! Every other field, and every decision below, likewise reads only what its event
//! declares or the aggregate instance that event is appended at.
//!
//! # Deciding, applying and folding are three separate things
//!
//! Each of the ten commands is split in three, and [`TenancyEvent`] is what passes
//! between them:
//!
//! * `decide_*` takes `&self`, reads the projection, and returns either the declared
//!   event or [`Denied`]. It writes nothing: a refusal leaves the projection exactly as
//!   it found it, which is asserted per denied path in
//!   `crates/mandate-model/tests/tenancy.rs`.
//! * [`Tenancy::apply`] takes the event and writes it. It cannot refuse and it is handed
//!   no verified context and no authority beyond what the event itself declares.
//! * [`Tenancy::fold`] applies a whole log to an empty projection. That is the rebuild
//!   `docs/adr/0009-event-sourced-persistence.md` requires, and
//!   `crates/mandate-model/tests/replay.rs` decides it field for field against the live
//!   projection the same commands wrote.
//!
//! The split is what keeps an undeclared input out of the rebuild.
//! `AddOrganizationMembership` may name an organization other than the verified one, and
//! only "for a caller holding platform organization-administration authority"
//! (`tenancy.yaml`). Nothing in `mandate.tenancy.OrganizationMembershipAdded` —
//! `context`, `organization_id`, `principal_id`, `membership_id` — says which path was
//! taken, so a fold that refused on that basis could not replay its own accepted history.
//! [`Tenancy::may_add_organization_membership`] is the only reader of
//! [`MembershipAuthority`] in this crate, [`Tenancy::decide_add_organization_membership`]
//! runs it, and [`Tenancy::apply`] never sees it. `authority` is the only input in this
//! module that decides an outcome and that nothing in the log can supply.
//!
//! # Where a guard lives, and what closes the window after it
//!
//! **Every guard is enforced by a `decide_*` half, against the projection it reads.**
//! [`Tenancy::apply`] and [`Tenancy::fold`] are **total**: they write what they are handed
//! and re-check nothing. That is not an omission, it is what a rebuild is — a fold that
//! refuses is not a rebuild of an accepted history, and
//! `docs/adr/0009-event-sourced-persistence.md` makes every read a fold over the events.
//! A log is the record of what was accepted; replaying it does not ask to accept it again.
//!
//! So this crate does not close the window between a decision and the append that follows
//! it, and no method here promises to. **The command path closes it**: ADR 0009 makes the
//! decide-and-append step one transaction, whose aggregate append is "a compare-and-set on
//! the expected stream version", so a decision read from a state that has since moved
//! fails the append and is retried against the state that moved it. Every cross-record
//! rule this module decides rests on that and on nothing here — a closure landing after a
//! membership was decided, and equally the one-active-membership-per-principal rule, which
//! two concurrent deciders reading one unwritten state would both admit.
//!
//! What this module owes, and holds, is that each guard is evaluated once, at decide, from
//! inputs a replayer would have: the organization must admit authority when the decision is
//! made, and `mandate.tenancy.OrganizationClosed` declares the `id` it closes, so a log
//! applied in order presents no membership after the closure that accepted it.
//!
//! Whether a caller holds the authority a command names — membership administration, team
//! administration, platform organization administration — is `mandate-authz`'s and is
//! decided nowhere here; [`MembershipAuthority`] is the caller's statement of which of the
//! contract's two paths it was admitted to, not a grant.
//!
//! # Two accepted outcomes are realized in part
//!
//! `AddTeamMembership`'s accepted outcome records the manual
//! `mandate.directory.MembershipContribution` atomically with the membership and returns
//! its identity beside the membership's (`tenancy.yaml`, `AddTeamMembership`);
//! [`Tenancy::add_team_membership`] records the membership alone and takes no contribution
//! identity. That record belongs to `mandate.directory` and to
//! `story:directory-provenance`, so what is owed here is this sentence, not the record.
//!
//! # Every denial clause this fold does not realize
//!
//! A `denied` clause with no code behind it is a gap, and the gap is only visible if it is
//! written down. These are all of them, and nothing else in `tenancy.yaml` is unrealized here:
//! thirty clauses across ten commands, each quoted verbatim from its command's declared
//! cause and grouped by what owes it. `contracts/obligations/model.json` is the record of what
//! this crate does not decide; a clause is listed here exactly when it carries `blocked_on`
//! there, and the two documents are one set read from two sides.
//!
//! A bullet names a command and quotes one clause; a quotation wrapped across lines is the
//! clause with its line breaks collapsed to single spaces.
//!
//! ## Owed to `decision-blocker:guards` — fourteen
//!
//! No guard runs here. Authority is the caller's statement (`MembershipAuthority`) and is
//! `mandate-authz`'s to decide, and no admission rule for a display name exists to implement:
//! the compiled entity declares `display_name` as a bare string with no pattern, length or
//! uniqueness, and no document in `systems/mandate` states one. This fold admits every string,
//! the empty one included and nothing trimmed.
//!
//! * `mandate.tenancy.AddOrganizationMembership` — "Caller lacks membership-administration
//!   authority"
//! * `mandate.tenancy.AddOrganizationMembership` — "the caller lacks platform
//!   organization-administration authority"
//! * `mandate.tenancy.AddTeamMembership` — "Caller lacks team-administration authority"
//! * `mandate.tenancy.CloseOrganization` — "Caller lacks platform organization-administration
//!   authority"
//! * `mandate.tenancy.CreateOrganization` — "Caller lacks platform organization-administration
//!   authority"
//! * `mandate.tenancy.CreateOrganization` — "the requested display name is not admitted"
//! * `mandate.tenancy.CreateSpace` — "Caller lacks space-administration authority"
//! * `mandate.tenancy.CreateSpace` — "the display name is not admitted in the verified
//!   organization"
//! * `mandate.tenancy.CreateTeam` — "Caller lacks team-administration authority"
//! * `mandate.tenancy.CreateTeam` — "the display name is not admitted in the verified
//!   organization"
//! * `mandate.tenancy.RemoveOrganizationMembership` — "Caller lacks membership-administration
//!   authority"
//! * `mandate.tenancy.RemoveTeamMembership` — "Caller lacks team-administration authority"
//! * `mandate.tenancy.RetireSpace` — "Caller lacks space-administration authority"
//! * `mandate.tenancy.RetireTeam` — "Caller lacks team-administration authority"
//!
//! ## Owed to `decision-blocker:epoch-atomicity` — nine
//!
//! Each of these denies on a commit this fold cannot attempt. A `Tenancy` is one in-memory
//! projection with no transaction, no epoch and no second record to commit against, so it can
//! neither observe the inconsistency nor refuse on it.
//!
//! * `mandate.tenancy.AddOrganizationMembership` — "membership and its dependent authorization
//!   cannot commit consistently"
//! * `mandate.tenancy.CloseOrganization` — "the sessions, credentials and delegations inside
//!   it cannot be invalidated with the closure"
//! * `mandate.tenancy.CreateOrganization` — "the isolation root cannot be created without
//!   implying membership, grants or authority inside it"
//! * `mandate.tenancy.CreateSpace` — "the space cannot be created without implying a grant or
//!   a resource inside it"
//! * `mandate.tenancy.CreateTeam` — "the team cannot be created without implying a grant or a
//!   directory mapping"
//! * `mandate.tenancy.RemoveOrganizationMembership` — "membership and dependent authorization
//!   invalidation cannot commit consistently"
//! * `mandate.tenancy.RemoveTeamMembership` — "dependent authorization invalidation cannot
//!   commit consistently"
//! * `mandate.tenancy.RetireSpace` — "retirement cannot refuse new authority inside it while
//!   preserving the resources and grants already bound to it"
//! * `mandate.tenancy.RetireTeam` — "retirement cannot revoke the grants that target it while
//!   preserving membership provenance"
//!
//! ## Owed to `decision-blocker:lifecycle` — one
//!
//! Destruction and retention are unsettled, and this fold destroys nothing: every closure,
//! retirement and removal keeps its record and moves a state.
//!
//! * `mandate.tenancy.CloseOrganization` — "closure would require destroying membership or
//!   audit history"
//!
//! ## Owed to `story:directory-provenance` — three
//!
//! `mandate.directory`'s records — group-team mappings and membership contributions — are
//! projected nowhere here, so this fold cannot see one to refuse on.
//!
//! * `mandate.tenancy.AddTeamMembership` — "the membership and the manual contribution
//!   recording its provenance cannot be recorded together"
//! * `mandate.tenancy.RemoveTeamMembership` — "a mandate.directory mapping contribution still
//!   supports it"
//! * `mandate.tenancy.RetireTeam` — "a directory mapping still contributes to it"
//!
//! ## Owed to `story:declared-writers` — three
//!
//! `Tenancy` holds no principal projection, so whether a principal resolves, is disabled, or
//! sits outside the verified organization is a question it answers identically for every
//! principal.
//!
//! * `mandate.tenancy.AddOrganizationMembership` — "the principal is unresolved or disabled"
//! * `mandate.tenancy.AddTeamMembership` — "principal is unresolved or outside the verified
//!   organization"
//! * `mandate.tenancy.AddTeamMembership` — "the principal is disabled"
//!
//! `AddTeamMembership`'s accepted outcome is realized in part for the same reason as its
//! `story:directory-provenance` clause above, and is recorded in its own section; that story
//! owns it too. Every other clause of every other command is decided by a `decide_*` half and
//! covered by a case in `tests/tenancy.rs` or `tests/obligations.rs` of this crate.
//!
//! This is the same kind of record the `space_id` section in `crate::graph` keeps for a
//! field with no writer.
//!
//! # Every refusal carries one reason, and one channel stays open
//!
//! `tenancy.yaml` gives each command a single `denied` clause and a single error,
//! `mandate.tenancy.Denied`, carrying one [`mandate_types::DenialReason`]. A record that
//! belongs to another organization and a record that was never written are covered by the
//! same clause, and they refuse identically here: the **reason** channel is closed, and a
//! caller cannot tell "no such record" from "not yours" by reading a refusal.
//!
//! The **accept/deny** channel is not, exactly as `crate::graph` records for
//! `RegisterResource`. Every creating method here keys its identity globally —
//! [`Tenancy::create_team`], [`Tenancy::create_space`] and both membership writers refuse
//! an identifier another organization already holds and accept a free one — so a caller
//! that writes can discriminate over the whole `TeamId`, `SpaceId`,
//! `OrganizationMembershipId` or `TeamMembershipId` space, one identifier at a time. That
//! is the contract's choice and not this fold's to overturn: `tenancy.yaml` declares each
//! entity's identity as one global key, and keying per organization would contradict the
//! declared identity and admit two records under one identifier, which every relation,
//! grant and membership that references one resolves through. What bounds the channel is
//! that each identifier is a UUID, so an enumerating caller has nothing to enumerate.
//!
//! # Identities are given, not minted
//!
//! Each creating command returns an identity in its response. Minting it belongs to the
//! command handler; this fold takes it as given and refuses to write over one it already
//! holds.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use mandate_types::{
    DenialReason, MembershipContributionId, OrganizationId, OrganizationMembershipId, PrincipalId,
    SpaceId, TeamId, TeamMembershipId, VerifiedContext,
};

/// `mandate.tenancy.Denied`: the fold refused, and wrote nothing.
///
/// Fail closed: no record, no state move and no partial authority follows a refusal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Denied {
    /// The declared reason.
    pub reason: DenialReason,
}

impl Denied {
    /// The one refusal this fold produces.
    const fn refusal() -> Self {
        Self {
            reason: DenialReason::Denied,
        }
    }
}

/// Which of `AddOrganizationMembership`'s two paths the caller was admitted to.
///
/// `tenancy.yaml`, AddOrganizationMembership: `organization_id` "must equal the
/// organization in the caller's verified context; it may differ only for a caller holding
/// platform organization-administration authority, which is how the organization
/// CreateOrganization returns is first populated".
///
/// This is a **decide-side** input, read by [`Tenancy::may_add_organization_membership`]
/// alone. `mandate.tenancy.OrganizationMembershipAdded` declares no field it could be read
/// back from, so [`Tenancy::apply`], which writes that event, is handed no such value and
/// a replay of the log does not need one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MembershipAuthority {
    /// The caller writes inside the organization its verified context names.
    VerifiedOrganization,
    /// The caller holds platform organization-administration authority and may name
    /// another organization.
    PlatformOrganizationAdministration,
}

/// `mandate.tenancy.Organization.State`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OrganizationState {
    /// The initial state.
    Recorded,
    /// The terminal state: the tenant admits no new authority and keeps everything it owns.
    Closed,
}

/// `mandate.tenancy.Organization`: the isolation root every tenant-owned record resolves to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Organization {
    /// The identity of this organization.
    pub id: OrganizationId,
    /// The declared display name.
    pub display_name: String,
    /// The recorded state.
    pub state: OrganizationState,
}

/// `mandate.tenancy.OrganizationMembership.State`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OrganizationMembershipState {
    /// The initial state.
    Active,
    /// The terminal state: the record is kept and stops binding the principal.
    Removed,
}

/// `mandate.tenancy.OrganizationMembership`: what binds an existing principal to a tenant.
///
/// The record carries no role: membership carries no authority by itself, which stays
/// with grants and relationships.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrganizationMembership {
    /// The identity of this membership.
    pub id: OrganizationMembershipId,
    /// The organization the membership is in.
    pub organization_id: OrganizationId,
    /// The principal the membership binds.
    pub principal_id: PrincipalId,
    /// The recorded state.
    pub state: OrganizationMembershipState,
}

/// `mandate.tenancy.Team.State`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TeamState {
    /// The initial state.
    Recorded,
    /// The terminal state: the team stops resolving as an authorization subject.
    Retired,
}

/// `mandate.tenancy.Team`: an authorization subject inside one organization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Team {
    /// The identity of this team.
    pub id: TeamId,
    /// The organization the team belongs to.
    pub organization_id: OrganizationId,
    /// The declared display name.
    pub display_name: String,
    /// The recorded state.
    pub state: TeamState,
}

/// `mandate.tenancy.TeamMembership.State`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TeamMembershipState {
    /// The initial state.
    Recorded,
    /// The terminal state: the record and its provenance are kept.
    Removed,
}

/// `mandate.tenancy.TeamMembership`: a principal's membership of one team.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TeamMembership {
    /// The identity of this membership.
    pub id: TeamMembershipId,
    /// The organization the membership is in.
    pub organization_id: OrganizationId,
    /// The team the membership is of.
    pub team_id: TeamId,
    /// The principal the membership binds.
    pub principal_id: PrincipalId,
    /// The recorded state.
    pub state: TeamMembershipState,
}

/// `mandate.tenancy.Space.State`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SpaceState {
    /// The initial state.
    Recorded,
    /// The terminal state: the boundary admits no new authority and keeps what is bound to it.
    Retired,
}

/// `mandate.tenancy.Space`: a security boundary below the organization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Space {
    /// The identity of this space.
    pub id: SpaceId,
    /// The organization the space belongs to.
    pub organization_id: OrganizationId,
    /// The declared display name.
    pub display_name: String,
    /// The recorded state.
    pub state: SpaceState,
}

/// The ten declared `mandate.tenancy` event payloads.
///
/// Each variant is one compiled payload under `generated/schema/events`, field for field:
/// the variant's fields are that payload's `properties`, with the same names and the same
/// types. `#[serde(untagged)]` is what makes that true on the wire — a variant serializes
/// as the bare payload object, with no discriminant wrapping it — and
/// `crates/mandate-model/tests/replay.rs` decides it against each payload's compiled
/// `required` list.
///
/// Every variant carries the `mandate.core.VerifiedContext` its command was given,
/// because every compiled payload declares one and because [`Tenancy::apply`] reads
/// `organization` out of it: `TeamCreated`, `SpaceCreated` and `TeamMembershipAdded`
/// declare no organization of their own, and the record they write has one.
///
/// **`Serialize` only, deliberately: this enum does not round-trip and no code should
/// assume it does.** Under `#[serde(untagged)]` a reader cannot tell
/// `OrganizationClosed`, `OrganizationMembershipRemoved`, `TeamRetired`,
/// `TeamMembershipRemoved` and `SpaceRetired` apart — all five serialize exactly
/// `{context, id}`, and the five `id`s are all uuid strings. Reading an event back needs
/// a tagged envelope carrying the ESS name beside the payload, which belongs to the
/// persistence story; `story:model-agreement` round-trips through the generated contract
/// shapes rather than through these enums. Deriving `Deserialize` here would compile and
/// would silently resolve four of those five to the first variant that fits.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(untagged)]
pub enum TenancyEvent {
    /// `mandate.tenancy.OrganizationCreated`.
    OrganizationCreated {
        /// The caller's verified context.
        context: VerifiedContext,
        /// The identity `CreateOrganization` returns.
        organization_id: OrganizationId,
        /// The declared display name.
        display_name: String,
    },
    /// `mandate.tenancy.OrganizationClosed`.
    OrganizationClosed {
        /// The caller's verified context.
        context: VerifiedContext,
        /// The organization that stops admitting authority.
        id: OrganizationId,
    },
    /// `mandate.tenancy.OrganizationMembershipAdded`.
    OrganizationMembershipAdded {
        /// The caller's verified context.
        context: VerifiedContext,
        /// The organization the membership is in, which need not be the verified one.
        organization_id: OrganizationId,
        /// The principal the membership binds.
        principal_id: PrincipalId,
        /// The identity `AddOrganizationMembership` returns.
        membership_id: OrganizationMembershipId,
    },
    /// `mandate.tenancy.OrganizationMembershipRemoved`.
    OrganizationMembershipRemoved {
        /// The caller's verified context.
        context: VerifiedContext,
        /// The membership that stops binding its principal.
        id: OrganizationMembershipId,
    },
    /// `mandate.tenancy.TeamCreated`.
    TeamCreated {
        /// The caller's verified context; the team belongs to the organization it names.
        context: VerifiedContext,
        /// The identity `CreateTeam` returns.
        team_id: TeamId,
        /// The declared display name.
        display_name: String,
    },
    /// `mandate.tenancy.TeamRetired`.
    TeamRetired {
        /// The caller's verified context.
        context: VerifiedContext,
        /// The team that stops resolving as an authorization subject.
        id: TeamId,
    },
    /// `mandate.tenancy.TeamMembershipAdded`.
    TeamMembershipAdded {
        /// The caller's verified context; the membership is in the organization it names.
        context: VerifiedContext,
        /// The team the membership is of.
        team_id: TeamId,
        /// The principal the membership binds.
        principal_id: PrincipalId,
        /// The identity `AddTeamMembership` returns.
        team_membership_id: TeamMembershipId,
        /// The identity of the manual `mandate.directory.MembershipContribution` the same
        /// accepted outcome records. That record belongs to `mandate.directory` and is
        /// not written here; the payload declares the identity, so the event carries it.
        contribution_id: MembershipContributionId,
    },
    /// `mandate.tenancy.TeamMembershipRemoved`.
    TeamMembershipRemoved {
        /// The caller's verified context.
        context: VerifiedContext,
        /// The team membership that stops binding its principal.
        id: TeamMembershipId,
    },
    /// `mandate.tenancy.SpaceCreated`.
    SpaceCreated {
        /// The caller's verified context; the space belongs to the organization it names.
        context: VerifiedContext,
        /// The identity `CreateSpace` returns.
        space_id: SpaceId,
        /// The declared display name.
        display_name: String,
    },
    /// `mandate.tenancy.SpaceRetired`.
    SpaceRetired {
        /// The caller's verified context.
        context: VerifiedContext,
        /// The space that stops admitting authority.
        id: SpaceId,
    },
}

impl TenancyEvent {
    /// The qualified ESS name of the payload this event is.
    ///
    /// The match is exhaustive and carries no wildcard arm, so a variant added without a
    /// name here does not compile.
    #[must_use]
    pub fn ess_name(&self) -> &'static str {
        match self {
            Self::OrganizationCreated { .. } => "mandate.tenancy.OrganizationCreated",
            Self::OrganizationClosed { .. } => "mandate.tenancy.OrganizationClosed",
            Self::OrganizationMembershipAdded { .. } => {
                "mandate.tenancy.OrganizationMembershipAdded"
            }
            Self::OrganizationMembershipRemoved { .. } => {
                "mandate.tenancy.OrganizationMembershipRemoved"
            }
            Self::TeamCreated { .. } => "mandate.tenancy.TeamCreated",
            Self::TeamRetired { .. } => "mandate.tenancy.TeamRetired",
            Self::TeamMembershipAdded { .. } => "mandate.tenancy.TeamMembershipAdded",
            Self::TeamMembershipRemoved { .. } => "mandate.tenancy.TeamMembershipRemoved",
            Self::SpaceCreated { .. } => "mandate.tenancy.SpaceCreated",
            Self::SpaceRetired { .. } => "mandate.tenancy.SpaceRetired",
        }
    }
}

/// The fold of the `mandate.tenancy` events: five projections and what writes them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Tenancy {
    organizations: BTreeMap<OrganizationId, Organization>,
    organization_memberships: BTreeMap<OrganizationMembershipId, OrganizationMembership>,
    teams: BTreeMap<TeamId, Team>,
    team_memberships: BTreeMap<TeamMembershipId, TeamMembership>,
    spaces: BTreeMap<SpaceId, Space>,
}

impl Tenancy {
    /// An empty fold, before any event is applied.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The projection every event of a log has been applied to, from empty.
    ///
    /// `docs/adr/0009-event-sourced-persistence.md`: state tables are "derived,
    /// droppable, rebuildable, never authoritative". This is that rebuild. It takes no
    /// verified context and no authority, because a log supplies neither, and it cannot
    /// refuse, because a log records what was accepted rather than asking to accept it
    /// again.
    #[must_use]
    pub fn fold(events: &[TenancyEvent]) -> Self {
        let mut fold = Self::new();
        for event in events {
            fold.apply(event);
        }
        fold
    }

    /// Write one declared event into the projection.
    ///
    /// **Total, and re-checks nothing.** Every guard belongs to a `decide_*` half, which
    /// reads the projection before the event exists and returns the refusal instead of the
    /// event; this writes what it is handed. A fold that re-checks a guard is not a rebuild
    /// of an accepted history, and `docs/adr/0009-event-sourced-persistence.md` makes every
    /// read a fold. The window between a decision and its append belongs to the command
    /// path's transaction, not here; see the module documentation.
    ///
    /// Applying is a keyed write — an insert-if-absent at the record's own identity, or a
    /// state move at it — so a log applied in order reproduces the projection its commands
    /// left, and a log applied twice reaches the same projection again.
    ///
    /// No authority reaches here. `MembershipAuthority` decides one rule that no event
    /// declares, and a replayer holds no such input; see the module documentation.
    pub fn apply(&mut self, event: &TenancyEvent) {
        match event {
            TenancyEvent::OrganizationCreated {
                organization_id,
                display_name,
                ..
            } => self.write_organization(*organization_id, display_name.clone()),
            TenancyEvent::OrganizationClosed { id, .. } => {
                self.move_organization(*id, OrganizationState::Closed);
            }
            TenancyEvent::OrganizationMembershipAdded {
                organization_id,
                principal_id,
                membership_id,
                ..
            } => {
                self.write_organization_membership(*membership_id, *organization_id, *principal_id)
            }
            TenancyEvent::OrganizationMembershipRemoved { id, .. } => {
                self.move_organization_membership(*id, OrganizationMembershipState::Removed);
            }
            TenancyEvent::TeamCreated {
                context,
                team_id,
                display_name,
            } => self.write_team(*team_id, context.organization, display_name.clone()),
            TenancyEvent::TeamRetired { id, .. } => self.move_team(*id, TeamState::Retired),
            TenancyEvent::TeamMembershipAdded {
                context,
                team_id,
                principal_id,
                team_membership_id,
                ..
            } => self.write_team_membership(
                *team_membership_id,
                context.organization,
                *team_id,
                *principal_id,
            ),
            TenancyEvent::TeamMembershipRemoved { id, .. } => {
                self.move_team_membership(*id, TeamMembershipState::Removed);
            }
            TenancyEvent::SpaceCreated {
                context,
                space_id,
                display_name,
            } => self.write_space(*space_id, context.organization, display_name.clone()),
            TenancyEvent::SpaceRetired { id, .. } => self.move_space(*id, SpaceState::Retired),
        }
    }

    /// The decide half of `CreateOrganization`: the declared event, or the refusal.
    ///
    /// The isolation root is created empty: no membership, team, space or grant exists
    /// inside it until that record's own command writes one.
    ///
    /// Nothing is written here. A command path appends the returned
    /// `mandate.tenancy.OrganizationCreated` and applies it.
    ///
    /// # Errors
    ///
    /// Refuses an identity that is already recorded.
    pub fn decide_create_organization(
        &self,
        context: &VerifiedContext,
        id: OrganizationId,
        display_name: impl Into<String>,
    ) -> Result<TenancyEvent, Denied> {
        if self.organizations.contains_key(&id) {
            return Err(Denied::refusal());
        }
        Ok(TenancyEvent::OrganizationCreated {
            context: context.clone(),
            organization_id: id,
            display_name: display_name.into(),
        })
    }

    /// The record half of `CreateOrganization`: decide, apply, return the event a command
    /// path appends.
    ///
    /// # Errors
    ///
    /// Refuses an identity that is already recorded.
    pub fn create_organization(
        &mut self,
        context: &VerifiedContext,
        id: OrganizationId,
        display_name: impl Into<String>,
    ) -> Result<TenancyEvent, Denied> {
        let event = self.decide_create_organization(context, id, display_name)?;
        self.apply(&event);
        Ok(event)
    }

    /// The decide half of `CloseOrganization`: the declared event, or the refusal.
    ///
    /// Nothing the organization owns is destroyed; it stops admitting authority. The
    /// command is platform-scoped, so no verified organization bounds which organization
    /// may be named.
    ///
    /// # Errors
    ///
    /// Refuses an organization that does not resolve or has already been closed.
    pub fn decide_close_organization(
        &self,
        context: &VerifiedContext,
        id: OrganizationId,
    ) -> Result<TenancyEvent, Denied> {
        let admitted = self
            .organizations
            .get(&id)
            .is_some_and(|record| record.state == OrganizationState::Recorded);
        if !admitted {
            return Err(Denied::refusal());
        }
        Ok(TenancyEvent::OrganizationClosed {
            context: context.clone(),
            id,
        })
    }

    /// The record half of `CloseOrganization`: decide, apply, return the event a command
    /// path appends.
    ///
    /// # Errors
    ///
    /// Refuses an organization that does not resolve or has already been closed.
    pub fn close_organization(
        &mut self,
        context: &VerifiedContext,
        id: OrganizationId,
    ) -> Result<TenancyEvent, Denied> {
        let event = self.decide_close_organization(context, id)?;
        self.apply(&event);
        Ok(event)
    }

    /// The decide half of `AddOrganizationMembership`: whether this membership may be
    /// written at all. A command path runs this, and appends
    /// `mandate.tenancy.OrganizationMembershipAdded` only if it returns `Ok`.
    ///
    /// The identity is not an argument: it is minted for the event this admits, and
    /// nothing is decided by it.
    ///
    /// # Errors
    ///
    /// Refuses a named organization other than the verified one on the tenant path, an
    /// organization that does not resolve or is closed, and a principal that already holds
    /// an active membership there.
    pub fn may_add_organization_membership(
        &self,
        context: &VerifiedContext,
        authority: MembershipAuthority,
        organization_id: OrganizationId,
        principal_id: PrincipalId,
    ) -> Result<(), Denied> {
        if authority == MembershipAuthority::VerifiedOrganization
            && organization_id != context.organization
        {
            return Err(Denied::refusal());
        }
        if !self.admits(organization_id) || self.is_member(organization_id, principal_id) {
            return Err(Denied::refusal());
        }
        Ok(())
    }

    /// The decide half of `AddOrganizationMembership`: the declared event, or the
    /// refusal.
    ///
    /// It runs both halves of the decision — the authority rule of
    /// [`Tenancy::may_add_organization_membership`], which no event can carry, and the
    /// record guards that every replayer can evaluate for itself — and returns
    /// `mandate.tenancy.OrganizationMembershipAdded`, whose `organization_id` names the
    /// target outright. That is what lets an accepted history, including the
    /// platform-written first membership of an organization, replay from its declared
    /// events alone.
    ///
    /// # Errors
    ///
    /// Refuses a named organization other than the verified one on the tenant path, an
    /// organization that does not resolve or no longer admits authority, an identity it
    /// already holds, and a principal that already holds an active membership there.
    pub fn decide_add_organization_membership(
        &self,
        context: &VerifiedContext,
        authority: MembershipAuthority,
        id: OrganizationMembershipId,
        organization_id: OrganizationId,
        principal_id: PrincipalId,
    ) -> Result<TenancyEvent, Denied> {
        self.may_add_organization_membership(context, authority, organization_id, principal_id)?;
        if self.organization_memberships.contains_key(&id) {
            return Err(Denied::refusal());
        }
        Ok(TenancyEvent::OrganizationMembershipAdded {
            context: context.clone(),
            organization_id,
            principal_id,
            membership_id: id,
        })
    }

    /// The record half of `AddOrganizationMembership`: decide, apply, return the event a
    /// command path appends.
    ///
    /// The `authority` reaches [`Tenancy::decide_add_organization_membership`] and stops
    /// there. [`Tenancy::apply`], which performs the write, is handed the event and
    /// nothing else, so the one rule no event declares cannot be re-decided on a replay.
    ///
    /// # Errors
    ///
    /// Refuses a named organization other than the verified one on the tenant path, an
    /// organization that does not resolve or no longer admits authority, an identity it
    /// already holds, and a principal that already holds an active membership there.
    ///
    /// Each of those is decided here, once, against the projection as it stands; none is
    /// re-checked by [`Tenancy::apply`], which is total. A decision invalidated before its
    /// append — by a closure, or by a second principal admitted concurrently — is refused
    /// by the command path's transaction, not by this method; see the module
    /// documentation.
    pub fn add_organization_membership(
        &mut self,
        context: &VerifiedContext,
        authority: MembershipAuthority,
        id: OrganizationMembershipId,
        organization_id: OrganizationId,
        principal_id: PrincipalId,
    ) -> Result<TenancyEvent, Denied> {
        let event = self.decide_add_organization_membership(
            context,
            authority,
            id,
            organization_id,
            principal_id,
        )?;
        self.apply(&event);
        Ok(event)
    }

    /// The decide half of `RemoveOrganizationMembership`: the declared event, or the
    /// refusal.
    ///
    /// # Errors
    ///
    /// Refuses a membership that does not resolve inside the verified organization, and
    /// one that has already been removed.
    pub fn decide_remove_organization_membership(
        &self,
        context: &VerifiedContext,
        id: OrganizationMembershipId,
    ) -> Result<TenancyEvent, Denied> {
        let membership = self
            .organization_memberships
            .get(&id)
            .ok_or_else(Denied::refusal)?;
        if membership.organization_id != context.organization
            || membership.state != OrganizationMembershipState::Active
        {
            return Err(Denied::refusal());
        }
        Ok(TenancyEvent::OrganizationMembershipRemoved {
            context: context.clone(),
            id,
        })
    }

    /// The record half of `RemoveOrganizationMembership`: decide, apply, return the
    /// event a command path appends.
    ///
    /// # Errors
    ///
    /// Refuses a membership that does not resolve inside the verified organization, and
    /// one that has already been removed.
    pub fn remove_organization_membership(
        &mut self,
        context: &VerifiedContext,
        id: OrganizationMembershipId,
    ) -> Result<TenancyEvent, Denied> {
        let event = self.decide_remove_organization_membership(context, id)?;
        self.apply(&event);
        Ok(event)
    }

    /// The decide half of `CreateTeam`: the declared event, or the refusal.
    ///
    /// The team belongs to the organization the verified context names; no selector
    /// carries one, and `mandate.tenancy.TeamCreated` declares none, so the fold reads it
    /// back off the event's own `context`.
    ///
    /// # Errors
    ///
    /// Refuses a verified organization that does not resolve or is closed, and an
    /// identity that is already recorded.
    pub fn decide_create_team(
        &self,
        context: &VerifiedContext,
        id: TeamId,
        display_name: impl Into<String>,
    ) -> Result<TenancyEvent, Denied> {
        if !self.admits(context.organization) || self.teams.contains_key(&id) {
            return Err(Denied::refusal());
        }
        Ok(TenancyEvent::TeamCreated {
            context: context.clone(),
            team_id: id,
            display_name: display_name.into(),
        })
    }

    /// The record half of `CreateTeam`: decide, apply, return the event a command path
    /// appends.
    ///
    /// # Errors
    ///
    /// Refuses a verified organization that does not resolve or is closed, and an
    /// identity that is already recorded.
    pub fn create_team(
        &mut self,
        context: &VerifiedContext,
        id: TeamId,
        display_name: impl Into<String>,
    ) -> Result<TenancyEvent, Denied> {
        let event = self.decide_create_team(context, id, display_name)?;
        self.apply(&event);
        Ok(event)
    }

    /// The decide half of `RetireTeam`: the declared event, or the refusal.
    ///
    /// # Errors
    ///
    /// Refuses a team that does not resolve inside the verified organization, and one
    /// that has already been retired.
    pub fn decide_retire_team(
        &self,
        context: &VerifiedContext,
        id: TeamId,
    ) -> Result<TenancyEvent, Denied> {
        let team = self.teams.get(&id).ok_or_else(Denied::refusal)?;
        if team.organization_id != context.organization || team.state != TeamState::Recorded {
            return Err(Denied::refusal());
        }
        Ok(TenancyEvent::TeamRetired {
            context: context.clone(),
            id,
        })
    }

    /// The record half of `RetireTeam`: decide, apply, return the event a command path
    /// appends.
    ///
    /// # Errors
    ///
    /// Refuses a team that does not resolve inside the verified organization, and one
    /// that has already been retired.
    pub fn retire_team(
        &mut self,
        context: &VerifiedContext,
        id: TeamId,
    ) -> Result<TenancyEvent, Denied> {
        let event = self.decide_retire_team(context, id)?;
        self.apply(&event);
        Ok(event)
    }

    /// The decide half of `AddTeamMembership`: the declared event, or the refusal.
    ///
    /// `mandate.tenancy.TeamMembershipAdded` declares `contribution_id`, the identity of
    /// the manual `mandate.directory.MembershipContribution` the same accepted outcome
    /// records. This fold does not write that record — it belongs to `mandate.directory`
    /// and to `story:directory-provenance` — and the event carries the identity all the
    /// same, because the payload declares it.
    ///
    /// # Errors
    ///
    /// Refuses a verified organization that does not resolve or is closed, a team that
    /// does not resolve inside it or is retired, a principal that is not a member of that
    /// organization, an identity that is already recorded, and a principal that already
    /// holds a membership of that team.
    pub fn decide_add_team_membership(
        &self,
        context: &VerifiedContext,
        id: TeamMembershipId,
        team_id: TeamId,
        principal_id: PrincipalId,
        contribution_id: MembershipContributionId,
    ) -> Result<TenancyEvent, Denied> {
        if !self.admits(context.organization) {
            return Err(Denied::refusal());
        }
        let team = self.teams.get(&team_id).ok_or_else(Denied::refusal)?;
        let resolves =
            team.organization_id == context.organization && team.state == TeamState::Recorded;
        if !resolves
            || !self.is_member(context.organization, principal_id)
            || self.team_memberships.contains_key(&id)
            || self.holds_team_membership(team_id, principal_id)
        {
            return Err(Denied::refusal());
        }
        Ok(TenancyEvent::TeamMembershipAdded {
            context: context.clone(),
            team_id,
            principal_id,
            team_membership_id: id,
            contribution_id,
        })
    }

    /// The record half of `AddTeamMembership`: decide, apply, return the event a command
    /// path appends.
    ///
    /// # Errors
    ///
    /// Refuses a verified organization that does not resolve or is closed, a team that
    /// does not resolve inside it or is retired, a principal that is not a member of that
    /// organization, an identity that is already recorded, and a principal that already
    /// holds a membership of that team.
    pub fn add_team_membership(
        &mut self,
        context: &VerifiedContext,
        id: TeamMembershipId,
        team_id: TeamId,
        principal_id: PrincipalId,
        contribution_id: MembershipContributionId,
    ) -> Result<TenancyEvent, Denied> {
        let event =
            self.decide_add_team_membership(context, id, team_id, principal_id, contribution_id)?;
        self.apply(&event);
        Ok(event)
    }

    /// The decide half of `RemoveTeamMembership`: the declared event, or the refusal.
    ///
    /// # Errors
    ///
    /// Refuses a membership that does not resolve inside the verified organization, and
    /// one that has already been removed.
    pub fn decide_remove_team_membership(
        &self,
        context: &VerifiedContext,
        id: TeamMembershipId,
    ) -> Result<TenancyEvent, Denied> {
        let membership = self.team_memberships.get(&id).ok_or_else(Denied::refusal)?;
        if membership.organization_id != context.organization
            || membership.state != TeamMembershipState::Recorded
        {
            return Err(Denied::refusal());
        }
        Ok(TenancyEvent::TeamMembershipRemoved {
            context: context.clone(),
            id,
        })
    }

    /// The record half of `RemoveTeamMembership`: decide, apply, return the event a
    /// command path appends.
    ///
    /// # Errors
    ///
    /// Refuses a membership that does not resolve inside the verified organization, and
    /// one that has already been removed.
    pub fn remove_team_membership(
        &mut self,
        context: &VerifiedContext,
        id: TeamMembershipId,
    ) -> Result<TenancyEvent, Denied> {
        let event = self.decide_remove_team_membership(context, id)?;
        self.apply(&event);
        Ok(event)
    }

    /// The decide half of `CreateSpace`: the declared event, or the refusal.
    ///
    /// Creating the boundary grants nothing inside it. The space belongs to the
    /// organization the verified context names; `mandate.tenancy.SpaceCreated` declares
    /// none, so the fold reads it back off the event's own `context`.
    ///
    /// # Errors
    ///
    /// Refuses a verified organization that does not resolve or is closed, and an
    /// identity that is already recorded.
    pub fn decide_create_space(
        &self,
        context: &VerifiedContext,
        id: SpaceId,
        display_name: impl Into<String>,
    ) -> Result<TenancyEvent, Denied> {
        if !self.admits(context.organization) || self.spaces.contains_key(&id) {
            return Err(Denied::refusal());
        }
        Ok(TenancyEvent::SpaceCreated {
            context: context.clone(),
            space_id: id,
            display_name: display_name.into(),
        })
    }

    /// The record half of `CreateSpace`: decide, apply, return the event a command path
    /// appends.
    ///
    /// # Errors
    ///
    /// Refuses a verified organization that does not resolve or is closed, and an
    /// identity that is already recorded.
    pub fn create_space(
        &mut self,
        context: &VerifiedContext,
        id: SpaceId,
        display_name: impl Into<String>,
    ) -> Result<TenancyEvent, Denied> {
        let event = self.decide_create_space(context, id, display_name)?;
        self.apply(&event);
        Ok(event)
    }

    /// The decide half of `RetireSpace`: the declared event, or the refusal.
    ///
    /// # Errors
    ///
    /// Refuses a space that does not resolve inside the verified organization, and one
    /// that has already been retired.
    pub fn decide_retire_space(
        &self,
        context: &VerifiedContext,
        id: SpaceId,
    ) -> Result<TenancyEvent, Denied> {
        let space = self.spaces.get(&id).ok_or_else(Denied::refusal)?;
        if space.organization_id != context.organization || space.state != SpaceState::Recorded {
            return Err(Denied::refusal());
        }
        Ok(TenancyEvent::SpaceRetired {
            context: context.clone(),
            id,
        })
    }

    /// The record half of `RetireSpace`: decide, apply, return the event a command path
    /// appends.
    ///
    /// # Errors
    ///
    /// Refuses a space that does not resolve inside the verified organization, and one
    /// that has already been retired.
    pub fn retire_space(
        &mut self,
        context: &VerifiedContext,
        id: SpaceId,
    ) -> Result<TenancyEvent, Denied> {
        let event = self.decide_retire_space(context, id)?;
        self.apply(&event);
        Ok(event)
    }

    /// The organization as the verified caller can read it: its own, and still `Recorded`.
    ///
    /// `docs/architecture/combined.md`: "Every tenant-owned record resolves to exactly one
    /// organization." These five scoped readers are that rule in this API, and they are
    /// the pair of [`crate::graph::Topology::resolve`]. What a consumer such as
    /// `story:check-api` or `story:graph-policy` reads is one of these, never a record
    /// reader below.
    #[must_use]
    pub fn resolve_organization(
        &self,
        context: &VerifiedContext,
        id: OrganizationId,
    ) -> Option<&Organization> {
        self.organizations
            .get(&id)
            .filter(|record| record.id == context.organization)
            .filter(|record| record.state == OrganizationState::Recorded)
    }

    /// The organization membership as the verified caller can read it: inside the
    /// caller's organization, and still `Active`.
    #[must_use]
    pub fn resolve_organization_membership(
        &self,
        context: &VerifiedContext,
        id: OrganizationMembershipId,
    ) -> Option<&OrganizationMembership> {
        self.organization_memberships
            .get(&id)
            .filter(|record| record.organization_id == context.organization)
            .filter(|record| record.state == OrganizationMembershipState::Active)
    }

    /// The team as the verified caller can read it: inside the caller's organization, and
    /// still `Recorded`.
    #[must_use]
    pub fn resolve_team(&self, context: &VerifiedContext, id: TeamId) -> Option<&Team> {
        self.teams
            .get(&id)
            .filter(|record| record.organization_id == context.organization)
            .filter(|record| record.state == TeamState::Recorded)
    }

    /// The team membership as the verified caller can read it: inside the caller's
    /// organization, and still `Recorded`.
    #[must_use]
    pub fn resolve_team_membership(
        &self,
        context: &VerifiedContext,
        id: TeamMembershipId,
    ) -> Option<&TeamMembership> {
        self.team_memberships
            .get(&id)
            .filter(|record| record.organization_id == context.organization)
            .filter(|record| record.state == TeamMembershipState::Recorded)
    }

    /// The space as the verified caller can read it: inside the caller's organization, and
    /// still `Recorded`.
    #[must_use]
    pub fn resolve_space(&self, context: &VerifiedContext, id: SpaceId) -> Option<&Space> {
        self.spaces
            .get(&id)
            .filter(|record| record.organization_id == context.organization)
            .filter(|record| record.state == SpaceState::Recorded)
    }

    /// The organization record, in whatever state it holds.
    ///
    /// A record reader, not a tenant-scoped one: it answers for every organization and for
    /// a closed one, because a fold, a rebuild and a test need the record that outlives its
    /// resolution. A caller's read is [`Tenancy::resolve_organization`].
    #[must_use]
    pub fn organization(&self, id: OrganizationId) -> Option<&Organization> {
        self.organizations.get(&id)
    }

    /// The organization membership record, in whatever state it holds.
    ///
    /// A record reader; see [`Tenancy::organization`]. A caller's read is
    /// [`Tenancy::resolve_organization_membership`].
    #[must_use]
    pub fn organization_membership(
        &self,
        id: OrganizationMembershipId,
    ) -> Option<&OrganizationMembership> {
        self.organization_memberships.get(&id)
    }

    /// The team record, in whatever state it holds.
    ///
    /// A record reader; see [`Tenancy::organization`]. A caller's read is
    /// [`Tenancy::resolve_team`].
    #[must_use]
    pub fn team(&self, id: TeamId) -> Option<&Team> {
        self.teams.get(&id)
    }

    /// The team membership record, in whatever state it holds.
    ///
    /// A record reader; see [`Tenancy::organization`]. A caller's read is
    /// [`Tenancy::resolve_team_membership`].
    #[must_use]
    pub fn team_membership(&self, id: TeamMembershipId) -> Option<&TeamMembership> {
        self.team_memberships.get(&id)
    }

    /// The space record, in whatever state it holds.
    ///
    /// A record reader; see [`Tenancy::organization`]. A caller's read is
    /// [`Tenancy::resolve_space`].
    #[must_use]
    pub fn space(&self, id: SpaceId) -> Option<&Space> {
        self.spaces.get(&id)
    }

    /// Whether the organization resolves and still admits authority.
    ///
    /// Organization-scoped rather than context-scoped: the caller names the organization
    /// it is asking about, so this answers nothing it did not already name.
    #[must_use]
    pub fn admits(&self, organization: OrganizationId) -> bool {
        self.organizations
            .get(&organization)
            .is_some_and(|record| record.state == OrganizationState::Recorded)
    }

    /// Whether the principal holds an active membership of the organization.
    ///
    /// Organization-scoped rather than context-scoped; see [`Tenancy::admits`].
    #[must_use]
    pub fn is_member(&self, organization: OrganizationId, principal: PrincipalId) -> bool {
        self.organization_memberships.values().any(|membership| {
            membership.organization_id == organization
                && membership.principal_id == principal
                && membership.state == OrganizationMembershipState::Active
        })
    }

    /// The principals holding an active membership of the organization.
    ///
    /// Organization-scoped rather than context-scoped; see [`Tenancy::admits`].
    #[must_use]
    pub fn members_of(&self, organization: OrganizationId) -> Vec<PrincipalId> {
        let mut principals: Vec<PrincipalId> = self
            .organization_memberships
            .values()
            .filter(|membership| {
                membership.organization_id == organization
                    && membership.state == OrganizationMembershipState::Active
            })
            .map(|membership| membership.principal_id)
            .collect();
        principals.sort_unstable();
        principals.dedup();
        principals
    }

    /// The organizations the principal holds an active membership of.
    ///
    /// A principal joins as many organizations as it is admitted to, and no record here
    /// carries authority that spans them.
    ///
    /// This is the one read that crosses organizations by construction, and it is a
    /// fold-level read: it exists to observe that property, and answering it for a caller
    /// would disclose that a principal it shares with another tenant is a member there. A
    /// caller's read is [`Tenancy::resolve_organization_membership`].
    #[must_use]
    pub fn organizations_of(&self, principal: PrincipalId) -> Vec<OrganizationId> {
        let mut organizations: Vec<OrganizationId> = self
            .organization_memberships
            .values()
            .filter(|membership| {
                membership.principal_id == principal
                    && membership.state == OrganizationMembershipState::Active
            })
            .map(|membership| membership.organization_id)
            .collect();
        organizations.sort_unstable();
        organizations.dedup();
        organizations
    }

    /// How many records the fold holds, in every state and every organization. Nothing is
    /// ever destroyed, so this count only grows.
    ///
    /// A fold-level read, like the record readers; it is not a caller's read.
    #[must_use]
    pub fn record_count(&self) -> usize {
        self.organizations.len()
            + self.organization_memberships.len()
            + self.teams.len()
            + self.team_memberships.len()
            + self.spaces.len()
    }

    fn holds_team_membership(&self, team: TeamId, principal: PrincipalId) -> bool {
        self.team_memberships.values().any(|membership| {
            membership.team_id == team
                && membership.principal_id == principal
                && membership.state == TeamMembershipState::Recorded
        })
    }

    /// The ten keyed writes [`Tenancy::apply`] performs, and the only writes in this
    /// module. Each is an insert at the record's own identity or a state move at it, so
    /// applying a log in order rebuilds what its commands wrote.
    ///
    /// **A creation is insert-if-absent: the first one for an identity is the one that
    /// stands.** A creation names the first event of a record, so a redelivered creation —
    /// which the kit's at-least-once delivery admits, and which no `decide_*` path emits —
    /// must write nothing rather than return a record from a terminal state to its initial
    /// one. `or_insert_with` is that rule; a state move is already idempotent because the
    /// target state is absorbing. `crates/mandate-model/tests/replay.rs`
    /// `a_redelivered_creation_after_a_terminal_state_writes_nothing` decides it for all
    /// six creating events.
    fn write_organization(&mut self, id: OrganizationId, display_name: String) {
        self.organizations
            .entry(id)
            .or_insert_with(|| Organization {
                id,
                display_name,
                state: OrganizationState::Recorded,
            });
    }

    fn move_organization(&mut self, id: OrganizationId, state: OrganizationState) {
        if let Some(record) = self.organizations.get_mut(&id) {
            record.state = state;
        }
    }

    fn write_organization_membership(
        &mut self,
        id: OrganizationMembershipId,
        organization_id: OrganizationId,
        principal_id: PrincipalId,
    ) {
        self.organization_memberships
            .entry(id)
            .or_insert_with(|| OrganizationMembership {
                id,
                organization_id,
                principal_id,
                state: OrganizationMembershipState::Active,
            });
    }

    fn move_organization_membership(
        &mut self,
        id: OrganizationMembershipId,
        state: OrganizationMembershipState,
    ) {
        if let Some(record) = self.organization_memberships.get_mut(&id) {
            record.state = state;
        }
    }

    fn write_team(&mut self, id: TeamId, organization_id: OrganizationId, display_name: String) {
        self.teams.entry(id).or_insert_with(|| Team {
            id,
            organization_id,
            display_name,
            state: TeamState::Recorded,
        });
    }

    fn move_team(&mut self, id: TeamId, state: TeamState) {
        if let Some(record) = self.teams.get_mut(&id) {
            record.state = state;
        }
    }

    fn write_team_membership(
        &mut self,
        id: TeamMembershipId,
        organization_id: OrganizationId,
        team_id: TeamId,
        principal_id: PrincipalId,
    ) {
        self.team_memberships
            .entry(id)
            .or_insert_with(|| TeamMembership {
                id,
                organization_id,
                team_id,
                principal_id,
                state: TeamMembershipState::Recorded,
            });
    }

    fn move_team_membership(&mut self, id: TeamMembershipId, state: TeamMembershipState) {
        if let Some(record) = self.team_memberships.get_mut(&id) {
            record.state = state;
        }
    }

    fn write_space(&mut self, id: SpaceId, organization_id: OrganizationId, display_name: String) {
        self.spaces.entry(id).or_insert_with(|| Space {
            id,
            organization_id,
            display_name,
            state: SpaceState::Recorded,
        });
    }

    fn move_space(&mut self, id: SpaceId, state: SpaceState) {
        if let Some(record) = self.spaces.get_mut(&id) {
            record.state = state;
        }
    }
}

impl mandate_types::PersistedValue for OrganizationState {}
impl mandate_types::PersistedValue for OrganizationMembershipState {}
impl mandate_types::PersistedValue for TeamState {}
impl mandate_types::PersistedValue for TeamMembershipState {}
impl mandate_types::PersistedValue for SpaceState {}

/// The credential boundary over the five projections, asserted rather than described.
///
/// [`mandate_types::canonical_record`] cannot declare these — it hardcodes the
/// `mandate.core.` prefix — so the check it performs is written out here instead: every
/// field of every projection implements [`mandate_types::PersistedValue`], which
/// `CredentialSecret` and `CredentialProof` do not. Each record is destructured without
/// `..`, so a field added and not named here does not compile, and a field whose type the
/// boundary does not admit does not compile either. `crate::graph` carries the same block
/// for `mandate.graph.Resource`.
const _: () = {
    fn persistable<T: mandate_types::PersistedValue + ?Sized>(_: &T) {}

    #[allow(dead_code)]
    fn every_projection_field_is_persistable(
        organization: &Organization,
        organization_membership: &OrganizationMembership,
        team: &Team,
        team_membership: &TeamMembership,
        space: &Space,
    ) {
        let Organization {
            id,
            display_name,
            state,
        } = organization;
        persistable(id);
        persistable(display_name);
        persistable(state);

        let OrganizationMembership {
            id,
            organization_id,
            principal_id,
            state,
        } = organization_membership;
        persistable(id);
        persistable(organization_id);
        persistable(principal_id);
        persistable(state);

        let Team {
            id,
            organization_id,
            display_name,
            state,
        } = team;
        persistable(id);
        persistable(organization_id);
        persistable(display_name);
        persistable(state);

        let TeamMembership {
            id,
            organization_id,
            team_id,
            principal_id,
            state,
        } = team_membership;
        persistable(id);
        persistable(organization_id);
        persistable(team_id);
        persistable(principal_id);
        persistable(state);

        let Space {
            id,
            organization_id,
            display_name,
            state,
        } = space;
        persistable(id);
        persistable(organization_id);
        persistable(display_name);
        persistable(state);
    }
};

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
//! # These projections are not rebuildable from the log today
//!
//! `docs/adr/0009-event-sourced-persistence.md` states that the events are the record and
//! that state tables are "derived, droppable, rebuildable, never authoritative". Three of
//! these five are not, and saying so is the point of this section:
//!
//! | required field | the event that would carry it | what it declares |
//! |---|---|---|
//! | `Organization.display_name` | `mandate.tenancy.OrganizationCreated` | `context`, `organization_id` |
//! | `Team.display_name` | `mandate.tenancy.TeamCreated` | `context`, `team_id` |
//! | `Space.display_name` | `mandate.tenancy.SpaceCreated` | `context`, `space_id` |
//!
//! The compiled entity marks each `display_name` required, so dropping the projection and
//! replaying the log loses all three: the identity and the organization come back and the
//! name does not. `mandate.graph.Resource.resource_type` is the same gap in `crate::graph`.
//! Until the events carry them, these are method arguments here and the fold is
//! authoritative for those three fields, not derived. The fix is to the contract, which is
//! `story:event-payloads-for-folds`'s to make; no event is invented here to paper over it.
//!
//! Everything else is rebuildable: every other field, and every decision below, reads only
//! what its event declares or the aggregate instance that event is appended at.
//!
//! # Deciding and applying are separate where a decision needs what no event carries
//!
//! `AddOrganizationMembership` may name an organization other than the verified one, and
//! only "for a caller holding platform organization-administration authority"
//! (`tenancy.yaml`). Nothing in `mandate.tenancy.OrganizationMembershipAdded` —
//! `context`, `organization_id`, `principal_id`, `membership_id` — says which path was
//! taken, so a fold that refused on that basis could not replay its own accepted history.
//! The two halves are therefore separate:
//!
//! * [`Tenancy::may_add_organization_membership`] **decides**, and is the only reader of
//!   [`MembershipAuthority`] in this crate. A command path runs it before it appends the
//!   event.
//! * [`Tenancy::add_organization_membership`] **applies**, taking the event's own
//!   `membership_id`, `organization_id` and `principal_id` and nothing else. It cannot be
//!   handed an authority, so it cannot re-decide the one rule a replay could not
//!   reproduce.
//!
//! Only that rule moved. Every guard that a replayer *can* evaluate stays in the fold, and
//! the test for which is which is whether the log supplies it: the organization must still
//! admit authority when the row is written, and `mandate.tenancy.OrganizationClosed`
//! declares the `id` it closes, so the apply half keeps that guard — a closure that lands
//! between the two calls is refused rather than written into a closed tenant.
//!
//! The other nine commands decide and apply in one step, and are correct that way because
//! every input their decision reads is recoverable from the event they append: a replayer
//! evaluating the same guard on the same event reaches the same outcome. Each removal and
//! closure event declares `context` and, where the command does not already pin it through
//! its declared `instance`, the identity it moves; each creation event declares the
//! identity it returns. `authority` is the only input in this module that decides an
//! outcome and that nothing in the log can supply.
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
//! `CreateOrganization`, `CreateTeam` and `CreateSpace` each deny when "the display name
//! is not admitted", and this fold admits every string, the empty one included and nothing
//! trimmed. No admission rule exists to implement: the compiled entity declares
//! `display_name` as a bare string with no pattern, length or uniqueness, and no document
//! in `systems/mandate` states one. So the denial clause has no realization here and this
//! sentence is the record of that, in the same way the `space_id` section in
//! `crate::graph` records a field with no writer.
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
    DenialReason, OrganizationId, OrganizationMembershipId, PrincipalId, SpaceId, TeamId,
    TeamMembershipId, VerifiedContext,
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
/// back from, so [`Tenancy::add_organization_membership`], which applies that event, does
/// not consult it and a replay of the log does not need it.
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

    /// The record half of `CreateOrganization`.
    ///
    /// The isolation root is created empty: no membership, team, space or grant exists
    /// inside it until that record's own command writes one.
    ///
    /// # Errors
    ///
    /// Refuses an identity that is already recorded.
    pub fn create_organization(
        &mut self,
        id: OrganizationId,
        display_name: impl Into<String>,
    ) -> Result<(), Denied> {
        if self.organizations.contains_key(&id) {
            return Err(Denied::refusal());
        }
        self.organizations.insert(
            id,
            Organization {
                id,
                display_name: display_name.into(),
                state: OrganizationState::Recorded,
            },
        );
        Ok(())
    }

    /// The record half of `CloseOrganization`.
    ///
    /// Nothing the organization owns is destroyed; it stops admitting authority. The
    /// command is platform-scoped, so no verified organization bounds it.
    ///
    /// # Errors
    ///
    /// Refuses an organization that does not resolve or has already been closed.
    pub fn close_organization(&mut self, id: OrganizationId) -> Result<(), Denied> {
        let organization = self
            .organizations
            .get_mut(&id)
            .ok_or_else(Denied::refusal)?;
        if organization.state != OrganizationState::Recorded {
            return Err(Denied::refusal());
        }
        organization.state = OrganizationState::Closed;
        Ok(())
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

    /// The apply half of `AddOrganizationMembership`: the fold of
    /// `mandate.tenancy.OrganizationMembershipAdded`.
    ///
    /// It takes what the event declares — `membership_id`, `organization_id`,
    /// `principal_id` — and nothing else. It takes no authority, because nothing in the
    /// event could supply one on a replay, and it takes no context, because
    /// `organization_id` names the target outright. That is what lets an accepted history,
    /// including the platform-written first membership of an organization, replay from its
    /// declared events alone.
    ///
    /// # Errors
    ///
    /// Refuses an organization that does not resolve or no longer admits authority, an
    /// identity it already holds, and a principal that already holds an active membership
    /// there. Every one of those is recoverable from the log — `OrganizationClosed`
    /// declares the `id` it closes — so a log applied in order satisfies all three, and a
    /// closure that lands between the decide call and this one is refused here rather than
    /// written. The authority rule, the one thing no event carries, is
    /// [`Tenancy::may_add_organization_membership`]'s alone.
    pub fn add_organization_membership(
        &mut self,
        id: OrganizationMembershipId,
        organization_id: OrganizationId,
        principal_id: PrincipalId,
    ) -> Result<(), Denied> {
        if !self.admits(organization_id)
            || self.organization_memberships.contains_key(&id)
            || self.is_member(organization_id, principal_id)
        {
            return Err(Denied::refusal());
        }
        self.organization_memberships.insert(
            id,
            OrganizationMembership {
                id,
                organization_id,
                principal_id,
                state: OrganizationMembershipState::Active,
            },
        );
        Ok(())
    }

    /// The record half of `RemoveOrganizationMembership`.
    ///
    /// # Errors
    ///
    /// Refuses a membership that does not resolve inside the verified organization, and
    /// one that has already been removed.
    pub fn remove_organization_membership(
        &mut self,
        context: &VerifiedContext,
        id: OrganizationMembershipId,
    ) -> Result<(), Denied> {
        let membership = self
            .organization_memberships
            .get_mut(&id)
            .ok_or_else(Denied::refusal)?;
        if membership.organization_id != context.organization
            || membership.state != OrganizationMembershipState::Active
        {
            return Err(Denied::refusal());
        }
        membership.state = OrganizationMembershipState::Removed;
        Ok(())
    }

    /// The record half of `CreateTeam`.
    ///
    /// The team belongs to the organization the verified context names; no selector
    /// carries one.
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
    ) -> Result<(), Denied> {
        if !self.admits(context.organization) || self.teams.contains_key(&id) {
            return Err(Denied::refusal());
        }
        self.teams.insert(
            id,
            Team {
                id,
                organization_id: context.organization,
                display_name: display_name.into(),
                state: TeamState::Recorded,
            },
        );
        Ok(())
    }

    /// The record half of `RetireTeam`.
    ///
    /// # Errors
    ///
    /// Refuses a team that does not resolve inside the verified organization, and one
    /// that has already been retired.
    pub fn retire_team(&mut self, context: &VerifiedContext, id: TeamId) -> Result<(), Denied> {
        let team = self.teams.get_mut(&id).ok_or_else(Denied::refusal)?;
        if team.organization_id != context.organization || team.state != TeamState::Recorded {
            return Err(Denied::refusal());
        }
        team.state = TeamState::Retired;
        Ok(())
    }

    /// The record half of `AddTeamMembership`.
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
    ) -> Result<(), Denied> {
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
        self.team_memberships.insert(
            id,
            TeamMembership {
                id,
                organization_id: context.organization,
                team_id,
                principal_id,
                state: TeamMembershipState::Recorded,
            },
        );
        Ok(())
    }

    /// The record half of `RemoveTeamMembership`.
    ///
    /// # Errors
    ///
    /// Refuses a membership that does not resolve inside the verified organization, and
    /// one that has already been removed.
    pub fn remove_team_membership(
        &mut self,
        context: &VerifiedContext,
        id: TeamMembershipId,
    ) -> Result<(), Denied> {
        let membership = self
            .team_memberships
            .get_mut(&id)
            .ok_or_else(Denied::refusal)?;
        if membership.organization_id != context.organization
            || membership.state != TeamMembershipState::Recorded
        {
            return Err(Denied::refusal());
        }
        membership.state = TeamMembershipState::Removed;
        Ok(())
    }

    /// The record half of `CreateSpace`.
    ///
    /// Creating the boundary grants nothing inside it.
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
    ) -> Result<(), Denied> {
        if !self.admits(context.organization) || self.spaces.contains_key(&id) {
            return Err(Denied::refusal());
        }
        self.spaces.insert(
            id,
            Space {
                id,
                organization_id: context.organization,
                display_name: display_name.into(),
                state: SpaceState::Recorded,
            },
        );
        Ok(())
    }

    /// The record half of `RetireSpace`.
    ///
    /// # Errors
    ///
    /// Refuses a space that does not resolve inside the verified organization, and one
    /// that has already been retired.
    pub fn retire_space(&mut self, context: &VerifiedContext, id: SpaceId) -> Result<(), Denied> {
        let space = self.spaces.get_mut(&id).ok_or_else(Denied::refusal)?;
        if space.organization_id != context.organization || space.state != SpaceState::Recorded {
            return Err(Denied::refusal());
        }
        space.state = SpaceState::Retired;
        Ok(())
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

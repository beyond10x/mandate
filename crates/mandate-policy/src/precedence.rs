//! The deny-precedence combinator and role expansion: the single home of both.
//!
//! `docs/architecture/combined.md:53` states the rule in three words — "Denies override
//! grants" — and the same paragraph states the other half: "an empty source list grants
//! none". `story:check-api` consumes this module rather than restating either, which is
//! the point of it having one home.
//!
//! # The role gap, named
//!
//! "Role bundles" has no referent in the contract. `mandate.graph.Grant.role` is a bare
//! `String` (`graph.yaml:96-97`) and no domain declares a catalog mapping a role name onto
//! actions. [`expand`] therefore expands over a [`RoleCatalog`] the caller supplies, and
//! this crate invents no role names. A role the catalog does not know is
//! [`Expansion::UnknownRole`], which contributes a denial: an unknown name is an absence of
//! authority, and the closed direction is to refuse.

use mandate_types::{Action, DenialReason, OrganizationId};

use crate::port::{ChallengeRequirement, PolicyEffect};

/// One source's contribution to a decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Component {
    /// This source contributed nothing: it had no opinion, or it was a group with no
    /// components in it.
    ///
    /// This is the identity of [`combine`]. It is not an allow and it is not a refusal —
    /// combining it with anything yields that thing, and combining nothing but this
    /// yields [`Combined::Nothing`], which fails closed at the top.
    Nothing,
    /// This source found authority.
    Allowed,
    /// This source permits the request once an approval is satisfied.
    ApprovalRequired,
    /// This source refuses, for the reason the contract declares.
    Denied(DenialReason),
}

impl Component {
    /// The component a policy effect contributes.
    #[must_use]
    pub const fn of_effect(effect: PolicyEffect) -> Self {
        match effect {
            PolicyEffect::Allow => Self::Allowed,
            PolicyEffect::Deny => Self::Denied(DenialReason::Denied),
            PolicyEffect::ApprovalRequired => Self::ApprovalRequired,
        }
    }
}

/// What every component together comes to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Combined {
    /// No source contributed anything.
    ///
    /// This value has two readings, and which one applies is decided by the accessor the
    /// consumer reaches for, not by anything about the value:
    ///
    /// * **Decided** — read through [`Combined::allowed`] and
    ///   [`Combined::denial_reason`], it is a refusal, indistinguishable from
    ///   `Denied(DenialReason::Denied)`. A source with zero applicable rules grants
    ///   nothing (`docs/architecture/combined.md:53`).
    /// * **Composed** — read through [`Combined::component`] and folded into another
    ///   [`combine`], it is the identity and contributes nothing, where a real refusal
    ///   would deny the whole combination.
    ///
    /// A consumer composing several sources reads `component()`; a consumer deciding a
    /// request reads `allowed()` / `denial_reason()`. Reading the composed form as the
    /// decision is the mistake this doc exists to prevent: it would turn "no rule applied"
    /// into "no opinion" at the point the answer is given, which is the open direction.
    Nothing,
    /// Every source that spoke allowed it, and at least one did.
    Allowed,
    /// No source refused, and at least one requires an approval first.
    ApprovalRequired,
    /// At least one source refused, or none spoke at all.
    Denied(DenialReason),
}

impl Combined {
    /// This result as a component, so results can be combined further.
    #[must_use]
    pub const fn component(self) -> Component {
        match self {
            Self::Nothing => Component::Nothing,
            Self::Allowed => Component::Allowed,
            Self::ApprovalRequired => Component::ApprovalRequired,
            Self::Denied(reason) => Component::Denied(reason),
        }
    }

    /// Whether the request is allowed outright.
    #[must_use]
    pub const fn allowed(self) -> bool {
        matches!(self, Self::Allowed)
    }

    /// The reason the caller is told, for every result that is not an allow.
    ///
    /// Total with [`Combined::allowed`]: a result either allows or names a reason, and
    /// never neither. Three of the mappings this story owes `story:check-api` are produced
    /// here — [`DenialReason::Denied`] for a refusal and for a combination that found
    /// nothing, and the fourth, [`DenialReason::ApprovalRequired`], for the ordinary
    /// approval answer. An approval requirement is not a denial, but it is not an allow
    /// either, and the caller is owed the name of what it is: this is the single home of
    /// precedence, so it is named here rather than restated by every consumer.
    ///
    /// `DenialReason::TenantMismatch` and `DenialReason::Unavailable` reach a caller
    /// through the refusing port's own error, not through a combination.
    #[must_use]
    pub const fn denial_reason(self) -> Option<DenialReason> {
        match self {
            Self::Denied(reason) => Some(reason),
            Self::Nothing => Some(DenialReason::Denied),
            Self::ApprovalRequired => Some(DenialReason::ApprovalRequired),
            Self::Allowed => None,
        }
    }
}

/// Where a reason sits in the contract's own declaration order
/// (`mandate.core.DenialReason`).
fn rank(reason: DenialReason) -> usize {
    DenialReason::VARIANTS
        .iter()
        .position(|declared| *declared == reason)
        .unwrap_or(usize::MAX)
}

/// Combine every component into one, denies first.
///
/// A refusal from any source wins over every allow and every approval requirement. Where
/// more than one source refuses, the reason reported is the one the contract declares
/// first.
///
/// # The property, at the width it actually holds
///
/// Combining is commutative and associative over **every** input, empty groups included.
/// [`Component::Nothing`] is the identity: `combine(&[])` is [`Combined::Nothing`], whose
/// [`Combined::component`] contributes nothing, so combining in groups always agrees with
/// combining all the components at once. `Combined::component` exists for exactly that
/// composition, and an earlier revision of this module claimed the property while
/// `combine(&[])` folded to a denial that poisoned any combination it entered.
///
/// Failing closed is not weakened by that: [`Combined::Nothing`] answers `false` to
/// [`Combined::allowed`] and reports [`DenialReason::Denied`], so a check that found no
/// source still grants nothing. What changed is that the denial is produced where the
/// decision is read, not injected into an algebra that then cannot be folded.
#[must_use]
pub fn combine(components: &[Component]) -> Combined {
    let mut refusal: Option<DenialReason> = None;
    let mut approval = false;
    let mut allowed = false;

    for component in components {
        match component {
            Component::Denied(reason) => {
                refusal = Some(match refusal {
                    Some(held) if rank(held) <= rank(*reason) => held,
                    _ => *reason,
                });
            }
            Component::ApprovalRequired => approval = true,
            Component::Allowed => allowed = true,
            Component::Nothing => {}
        }
    }

    match (refusal, approval, allowed) {
        (Some(reason), _, _) => Combined::Denied(reason),
        (None, true, _) => Combined::ApprovalRequired,
        (None, false, true) => Combined::Allowed,
        (None, false, false) => Combined::Nothing,
    }
}

/// What actions a role name carries, for an organization.
///
/// The contract declares no such mapping, so it is a port: whoever owns role definitions
/// answers it.
pub trait RoleCatalog {
    /// The actions the role carries, or `None` if the catalog does not know the role.
    fn actions(&self, organization: &OrganizationId, role: &str) -> Option<Vec<Action>>;
}

/// What expanding a role name said about a requested action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expansion {
    /// The role carries the action.
    Covers,
    /// The role is known and does not carry the action.
    DoesNotCover,
    /// The catalog does not know the role.
    UnknownRole,
}

impl Expansion {
    /// The component this expansion contributes.
    ///
    /// Only [`Expansion::Covers`] contributes an allow; both of the others refuse, so an
    /// unknown role can never turn into authority.
    #[must_use]
    pub const fn component(self) -> Component {
        match self {
            Self::Covers => Component::Allowed,
            Self::DoesNotCover | Self::UnknownRole => Component::Denied(DenialReason::Denied),
        }
    }
}

/// Whether a grant's role name carries the requested action.
#[must_use]
pub fn expand<C: RoleCatalog + ?Sized>(
    catalog: &C,
    organization: &OrganizationId,
    role: &str,
    action: &Action,
) -> Expansion {
    match catalog.actions(organization, role) {
        None => Expansion::UnknownRole,
        Some(actions) if actions.contains(action) => Expansion::Covers,
        Some(_) => Expansion::DoesNotCover,
    }
}

/// Where a challenge requirement sits in the order of what a caller can clear on its own.
///
/// Lower is stricter. The order is total and declared here rather than derived from the
/// enum, so adding a variant does not silently rank it last: this `match` is exhaustive and
/// a new [`ChallengeRequirement`] does not compile until it is placed.
///
/// * [`ChallengeRequirement::Approval`] — a second party has to act. The caller cannot
///   clear it alone, so it is the strictest.
/// * [`ChallengeRequirement::Reauthentication`] — the caller clears it by itself.
const fn strictness(requirement: ChallengeRequirement) -> usize {
    match requirement {
        ChallengeRequirement::Approval => 0,
        ChallengeRequirement::Reauthentication => 1,
    }
}

/// The strictest requirement among those a set of sources asked for, or `None` if none did.
///
/// Which party has to clear a challenge is a precedence question, and this is the single
/// home of precedence, so it is decided here and not by the order rules happen to sit in a
/// list. Taking a minimum over a total order makes it commutative and associative, exactly
/// as [`combine`] is.
#[must_use]
pub fn strictest(requirements: &[ChallengeRequirement]) -> Option<ChallengeRequirement> {
    requirements
        .iter()
        .copied()
        .min_by_key(|requirement| strictness(*requirement))
}

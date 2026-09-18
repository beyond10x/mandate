//! The policy ports: what an evaluation is asked, and what it answers with.
//!
//! An evaluation answers a component — allow, deny or approval-required — the version it
//! answered under, and any challenge material the caller must satisfy. It never answers a
//! `mandate.authorization.Decision`: combining components into one is `mandate-authz`'s
//! (`docs/architecture/ownership.md:13`), and the deny precedence that combination obeys
//! lives in [`crate::precedence`].
//!
//! A refusal is one of two things and the caller can tell them apart: policy decided
//! against the caller ([`PolicyError::Denied`]), or policy could not decide
//! ([`PolicyError::CouldNotAnswer`]). Both fail closed.

use mandate_types::{
    Action, AuthoritySubject, CorrelationId, DenialReason, OrganizationId, PolicyVersion,
    ResourceRef, VerifiedContext,
};

use crate::record::{AuthorizationModel, Policy};

mod sealed {
    /// The seal on [`super::AttributeInput`].
    pub trait Sealed {}

    impl Sealed for bool {}
    impl Sealed for String {}
    impl Sealed for &str {}
    impl Sealed for mandate_types::Action {}
    impl Sealed for mandate_types::AuthoritySubject {}
    impl Sealed for mandate_types::OrganizationId {}
    impl Sealed for mandate_types::ResourceRef {}
}

/// A value an attribute may carry.
///
/// Every variant is a canonical type. The evaluation input is opaque in the sense that the
/// contract does not yet declare which attributes exist — `docs/sources/original-design.md:738`
/// still asks how resource attributes are trusted and distributed — but it is not opaque
/// about what a value may be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttributeValue {
    /// An unconstrained string.
    Text(String),
    /// A boolean.
    Flag(bool),
    /// A declared action.
    Action(Action),
    /// A tagged principal-or-team subject.
    Subject(AuthoritySubject),
    /// A configured organization.
    Organization(OrganizationId),
    /// A resource named by its type and identity.
    Resource(ResourceRef),
}

/// What may be put into an [`AttributeSet`].
///
/// Sealed on purpose: the implementors are the canonical types listed on
/// [`AttributeValue`], and no crate outside this one can add another. That is what stops a
/// backend's own row travelling through the opaque attribute input into policy.
pub trait AttributeInput: sealed::Sealed {
    /// This value as the attribute value it carries.
    fn into_value(self) -> AttributeValue;
}

impl AttributeInput for bool {
    fn into_value(self) -> AttributeValue {
        AttributeValue::Flag(self)
    }
}

impl AttributeInput for String {
    fn into_value(self) -> AttributeValue {
        AttributeValue::Text(self)
    }
}

impl AttributeInput for &str {
    fn into_value(self) -> AttributeValue {
        AttributeValue::Text(self.to_owned())
    }
}

impl AttributeInput for Action {
    fn into_value(self) -> AttributeValue {
        AttributeValue::Action(self)
    }
}

impl AttributeInput for AuthoritySubject {
    fn into_value(self) -> AttributeValue {
        AttributeValue::Subject(self)
    }
}

impl AttributeInput for OrganizationId {
    fn into_value(self) -> AttributeValue {
        AttributeValue::Organization(self)
    }
}

impl AttributeInput for ResourceRef {
    fn into_value(self) -> AttributeValue {
        AttributeValue::Resource(self)
    }
}

/// The attribute input an evaluation reads, in the order it was built.
///
/// The parameter cannot be frozen until resource-attribute trust and distribution are
/// decided, so it stays a named set rather than a declared record; the adapter story
/// revisits it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AttributeSet {
    entries: Vec<(String, AttributeValue)>,
}

impl AttributeSet {
    /// An empty set.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// The set with one more named value. A repeated name replaces the value held.
    #[must_use]
    pub fn with(mut self, name: impl Into<String>, value: impl AttributeInput) -> Self {
        let name = name.into();
        let value = value.into_value();
        if let Some(held) = self.entries.iter_mut().find(|(held, _)| held == &name) {
            held.1 = value;
        } else {
            self.entries.push((name, value));
        }
        self
    }

    /// The value held under a name, if any.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&AttributeValue> {
        self.entries
            .iter()
            .find(|(held, _)| held == name)
            .map(|(_, value)| value)
    }

    /// Every name the set carries, in the order they were added.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.entries.iter().map(|(name, _)| name.as_str())
    }

    /// How many names the set carries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the set carries nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// What policy is asked.
#[derive(Debug)]
pub struct PolicyRequest<'a> {
    /// The context the question is asked in. Its organization is the tenancy bound.
    pub context: &'a VerifiedContext,
    /// The subject the question is about.
    pub subject: &'a AuthoritySubject,
    /// The action requested.
    pub action: &'a Action,
    /// The resource the action is on.
    pub resource: &'a ResourceRef,
    /// The attribute input, opaque by decision.
    pub attributes: &'a AttributeSet,
}

/// One component of a decision, as policy sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyEffect {
    /// Policy permits the request.
    Allow,
    /// Policy refuses the request.
    Deny,
    /// Policy permits the request only once an approval is satisfied.
    ApprovalRequired,
}

impl PolicyEffect {
    /// Every effect the port can answer, in declaration order.
    pub const ALL: &'static [Self] = &[Self::Allow, Self::Deny, Self::ApprovalRequired];
}

/// What a caller must satisfy before an approval-required answer can become an allow.
///
/// `docs/architecture/combined.md:67` requires high-risk reauthentication or approval for
/// administrative changes; which one is the policy's to say.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeRequirement {
    /// An approval artifact from another party.
    Approval,
    /// A fresh authentication by the caller.
    Reauthentication,
}

/// The challenge material an approval-required answer carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    /// What must be satisfied.
    pub requirement: ChallengeRequirement,
    /// The correlation the challenge is answered under, carried from the request.
    pub correlation: CorrelationId,
}

/// What an evaluation answered, and the version it answered under.
///
/// The version is not decoration: `policy.yaml:2` requires every decision to stay
/// attributable to the exact version that made it, which is why a superseded version is
/// kept rather than deleted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evaluation {
    /// The component policy contributes.
    pub effect: PolicyEffect,
    /// The policy version the answer was made under.
    pub version: PolicyVersion,
    /// The challenge material, when the effect is
    /// [`PolicyEffect::ApprovalRequired`].
    pub challenge: Option<Challenge>,
}

/// Why policy could not decide.
///
/// Each of these is an absence, never a statement about the caller's authority, and each
/// fails closed as [`DenialReason::Unavailable`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unanswered {
    /// No policy version could be reached for the organization, so no answer could be
    /// attributed to one.
    Unreachable,
    /// The authorization model version the answer needs is not yet observable
    /// (`policy.yaml:103`).
    ModelNotCaughtUp,
    /// An attribute in the request did not arrive from a trusted source
    /// (`docs/sources/original-design.md:3369`).
    AttributeUntrusted,
}

impl Unanswered {
    /// Every reason this crate can fail to answer for, in declaration order.
    pub const ALL: &'static [Self] = &[
        Self::Unreachable,
        Self::ModelNotCaughtUp,
        Self::AttributeUntrusted,
    ];
}

/// A policy refusal: a decision against the caller, or an inability to decide.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyError {
    /// Policy decided against the caller, for the reason the contract declares.
    Denied(DenialReason),
    /// Policy could not decide.
    CouldNotAnswer(Unanswered),
}

impl PolicyError {
    /// The declared reason the caller is told.
    ///
    /// An inability to decide is told as [`DenialReason::Unavailable`].
    #[must_use]
    pub const fn denial_reason(&self) -> DenialReason {
        match self {
            Self::Denied(reason) => *reason,
            Self::CouldNotAnswer(_) => DenialReason::Unavailable,
        }
    }

    /// Whether policy decided against the caller.
    #[must_use]
    pub const fn is_denial(&self) -> bool {
        matches!(self, Self::Denied(_))
    }

    /// Whether policy could not decide.
    #[must_use]
    pub const fn is_could_not_answer(&self) -> bool {
        matches!(self, Self::CouldNotAnswer(_))
    }
}

/// What a mutation did to the fold.
///
/// `docs/adr/0009-event-sourced-persistence.md` makes every state a fold over recorded
/// moves, so repeating a move already recorded is accepted and records nothing further.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MutationOutcome {
    /// The move was recorded by this call.
    Recorded,
    /// The move was already recorded; this call changed nothing.
    AlreadyRecorded,
}

impl MutationOutcome {
    /// Whether this call changed the fold.
    #[must_use]
    pub const fn changed(self) -> bool {
        matches!(self, Self::Recorded)
    }
}

/// What a supersede command recorded. The record is kept, never deleted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Superseded<T> {
    /// The projection as it now stands.
    pub record: T,
    /// Whether this call recorded the move.
    pub outcome: MutationOutcome,
}

/// The policy evaluation port.
pub trait PolicyEvaluator {
    /// Evaluate the request against the organization's current policy.
    ///
    /// # Errors
    ///
    /// [`PolicyError::Denied`] when policy decides against the caller;
    /// [`PolicyError::CouldNotAnswer`] when it cannot decide.
    fn evaluate(&self, request: &PolicyRequest<'_>) -> Result<Evaluation, PolicyError>;
}

/// `mandate.policy.SupersedePolicy` and `mandate.policy.SupersedeAuthorizationModel`.
///
/// Both commands were added to `policy.yaml` in wave 1. The story's Units table predates
/// them and records that "the policy units own none"; the contract on this branch declares
/// two, and they are realized here as ports for the same reason the graph commands are.
pub trait PolicyAdministration {
    /// Stop a policy version being the current one, keeping its source.
    ///
    /// # Errors
    ///
    /// The refusals the contract declares at `policy.yaml:83`: missing authority, a policy
    /// outside the verified organization, no later version recorded, or decisions in
    /// flight that could not stay attributable.
    fn supersede_policy(
        &mut self,
        context: &VerifiedContext,
        id: &mandate_types::PolicyId,
    ) -> Result<Superseded<Policy>, PolicyError>;

    /// Stop an authorization model version being the current one, keeping its schema.
    ///
    /// # Errors
    ///
    /// The refusals the contract declares at `policy.yaml:103`.
    fn supersede_authorization_model(
        &mut self,
        context: &VerifiedContext,
        id: &mandate_types::AuthorizationModelId,
    ) -> Result<Superseded<AuthorizationModel>, PolicyError>;
}

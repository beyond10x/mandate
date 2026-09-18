//! An in-memory policy double: the fold, behind every port this crate declares.
//!
//! It is `pub` and publicly constructible because `story:check-api` builds its scenarios
//! with it. What it has not been told, it refuses: no recorded policy version means no
//! answer can be attributed to one (`policy.yaml:2`), no recorded model version means the
//! model the answer needs is not observable, and an attribute it was not told to trust is
//! refused rather than read (`docs/sources/original-design.md:3369`). All three fail closed
//! as [`mandate_types::DenialReason::Unavailable`].
//!
//! A request no rule matches is answered [`PolicyEffect::Deny`] — that is an answer, not a
//! refusal, and it is the closed direction: an empty source list grants none
//! (`docs/architecture/combined.md:53`).

use mandate_types::{
    Action, AuthoritySubject, AuthorizationModelId, DenialReason, OrganizationId, PolicyId,
    ResourceRef, VerifiedContext,
};

use crate::port::{
    Challenge, ChallengeRequirement, Evaluation, MutationOutcome, PolicyAdministration,
    PolicyEffect, PolicyError, PolicyEvaluator, PolicyRequest, Superseded, Unanswered,
};
use crate::precedence::{Combined, Component, RoleCatalog, combine, strictest};
use crate::record::{AuthorizationModel, Policy};

#[derive(Debug, Clone, PartialEq, Eq)]
struct Rule {
    organization: OrganizationId,
    subject: AuthoritySubject,
    action: Action,
    resource: ResourceRef,
    effect: PolicyEffect,
    requirement: Option<ChallengeRequirement>,
}

/// An in-memory policy fold, behind every port this crate declares.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PolicyDouble {
    policies: Vec<Policy>,
    models: Vec<AuthorizationModel>,
    rules: Vec<Rule>,
    trusted: Vec<String>,
    roles: Vec<(OrganizationId, String, Vec<Action>)>,
}

impl PolicyDouble {
    /// An empty fold: no version recorded, so nothing it says can be attributed yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Fold in a policy version. The most recently recorded current version is the one an
    /// evaluation is attributed to.
    pub fn record_policy(&mut self, policy: Policy) {
        self.policies.push(policy);
    }

    /// Fold in an authorization model version.
    pub fn record_model(&mut self, model: AuthorizationModel) {
        self.models.push(model);
    }

    /// Tell the double that an attribute name arrives from a trusted source.
    pub fn trust_attribute(&mut self, name: impl Into<String>) {
        let name = name.into();
        if !self.trusted.contains(&name) {
            self.trusted.push(name);
        }
    }

    /// Record a rule that allows.
    pub fn allow(
        &mut self,
        organization: OrganizationId,
        subject: AuthoritySubject,
        action: Action,
        resource: ResourceRef,
    ) {
        self.rules.push(Rule {
            organization,
            subject,
            action,
            resource,
            effect: PolicyEffect::Allow,
            requirement: None,
        });
    }

    /// Record a rule that refuses.
    pub fn deny(
        &mut self,
        organization: OrganizationId,
        subject: AuthoritySubject,
        action: Action,
        resource: ResourceRef,
    ) {
        self.rules.push(Rule {
            organization,
            subject,
            action,
            resource,
            effect: PolicyEffect::Deny,
            requirement: None,
        });
    }

    /// Record a rule that allows only once a challenge is satisfied.
    pub fn require_approval(
        &mut self,
        organization: OrganizationId,
        subject: AuthoritySubject,
        action: Action,
        resource: ResourceRef,
        requirement: ChallengeRequirement,
    ) {
        self.rules.push(Rule {
            organization,
            subject,
            action,
            resource,
            effect: PolicyEffect::ApprovalRequired,
            requirement: Some(requirement),
        });
    }

    /// Tell the double what actions a role name carries.
    pub fn record_role(
        &mut self,
        organization: OrganizationId,
        role: impl Into<String>,
        actions: Vec<Action>,
    ) {
        self.roles.push((organization, role.into(), actions));
    }

    /// Every policy version the fold holds, in the order they were recorded.
    #[must_use]
    pub fn policies(&self) -> &[Policy] {
        &self.policies
    }

    /// Every model version the fold holds, in the order they were recorded.
    #[must_use]
    pub fn models(&self) -> &[AuthorizationModel] {
        &self.models
    }

    fn current_policy(&self, organization: &OrganizationId) -> Option<&Policy> {
        self.policies
            .iter()
            .rev()
            .find(|policy| &policy.organization_id == organization && policy.current())
    }

    fn current_model(&self, organization: &OrganizationId) -> Option<&AuthorizationModel> {
        self.models
            .iter()
            .rev()
            .find(|model| &model.organization_id == organization && model.current())
    }
}

impl PolicyEvaluator for PolicyDouble {
    fn evaluate(&self, request: &PolicyRequest<'_>) -> Result<Evaluation, PolicyError> {
        let organization = &request.context.organization;

        let policy = self
            .current_policy(organization)
            .ok_or(PolicyError::CouldNotAnswer(Unanswered::Unreachable))?;
        if self.current_model(organization).is_none() {
            return Err(PolicyError::CouldNotAnswer(Unanswered::ModelNotCaughtUp));
        }
        if request
            .attributes
            .names()
            .any(|name| !self.trusted.iter().any(|trusted| trusted == name))
        {
            return Err(PolicyError::CouldNotAnswer(Unanswered::AttributeUntrusted));
        }

        // Every rule that names this request, folded through the one home of deny
        // precedence. The double holds its rules in a list, and resolving them with
        // `find` would have made the answer depend on the order they were recorded in:
        // an allow recorded before a deny would have answered allow while the deny was
        // held for exactly the same request. `combined.md:53` says denies override
        // grants, and `crate::precedence` is where this crate says that once.
        let matched: Vec<&Rule> = self
            .rules
            .iter()
            .filter(|rule| {
                &rule.organization == organization
                    && &rule.subject == request.subject
                    && &rule.action == request.action
                    && &rule.resource == request.resource
            })
            .collect();

        let components: Vec<Component> = matched
            .iter()
            .map(|rule| Component::of_effect(rule.effect))
            .collect();

        // A request no rule names contributes nothing, and nothing grants none.
        let effect = match combine(&components) {
            Combined::Allowed => PolicyEffect::Allow,
            Combined::ApprovalRequired => PolicyEffect::ApprovalRequired,
            Combined::Denied(_) | Combined::Nothing => PolicyEffect::Deny,
        };

        // Which party has to clear the challenge is a precedence question too, and
        // `Iterator::find` over the rule list would have decided it by list position —
        // the same defect the fold above removed, one field over. `precedence::strictest`
        // decides it by a total order, so two approval rules answer the same whichever
        // way round they were recorded. The challenge only survives if the fold still
        // comes to an approval requirement; a denied answer has nothing to clear.
        let requirement = match effect {
            PolicyEffect::ApprovalRequired => strictest(
                &matched
                    .iter()
                    .filter(|rule| rule.effect == PolicyEffect::ApprovalRequired)
                    .filter_map(|rule| rule.requirement)
                    .collect::<Vec<_>>(),
            ),
            PolicyEffect::Allow | PolicyEffect::Deny => None,
        };

        Ok(Evaluation {
            effect,
            version: policy.version.clone(),
            challenge: requirement.map(|requirement| Challenge {
                requirement,
                correlation: request.context.correlation.clone(),
            }),
        })
    }
}

impl PolicyAdministration for PolicyDouble {
    fn supersede_policy(
        &mut self,
        context: &VerifiedContext,
        id: &PolicyId,
    ) -> Result<Superseded<Policy>, PolicyError> {
        let position = self
            .policies
            .iter()
            .position(|policy| &policy.id == id)
            .ok_or(PolicyError::Denied(DenialReason::Denied))?;

        if self.policies[position].organization_id != context.organization {
            return Err(PolicyError::Denied(DenialReason::TenantMismatch));
        }
        if !self.policies[position].current() {
            return Ok(Superseded {
                record: self.policies[position].clone(),
                outcome: MutationOutcome::AlreadyRecorded,
            });
        }

        let organization = self.policies[position].organization_id;
        let later = self.policies[position + 1..]
            .iter()
            .any(|policy| policy.organization_id == organization && policy.current());
        if !later {
            return Err(PolicyError::Denied(DenialReason::Denied));
        }

        let outcome = self.policies[position].supersede();

        Ok(Superseded {
            record: self.policies[position].clone(),
            outcome,
        })
    }

    fn supersede_authorization_model(
        &mut self,
        context: &VerifiedContext,
        id: &AuthorizationModelId,
    ) -> Result<Superseded<AuthorizationModel>, PolicyError> {
        let position = self
            .models
            .iter()
            .position(|model| &model.id == id)
            .ok_or(PolicyError::Denied(DenialReason::Denied))?;

        if self.models[position].organization_id != context.organization {
            return Err(PolicyError::Denied(DenialReason::TenantMismatch));
        }
        if !self.models[position].current() {
            return Ok(Superseded {
                record: self.models[position].clone(),
                outcome: MutationOutcome::AlreadyRecorded,
            });
        }

        let organization = self.models[position].organization_id;
        let later = self.models[position + 1..]
            .iter()
            .any(|model| model.organization_id == organization && model.current());
        if !later {
            return Err(PolicyError::Denied(DenialReason::Denied));
        }

        let outcome = self.models[position].supersede();

        Ok(Superseded {
            record: self.models[position].clone(),
            outcome,
        })
    }
}

impl RoleCatalog for PolicyDouble {
    fn actions(&self, organization: &OrganizationId, role: &str) -> Option<Vec<Action>> {
        self.roles
            .iter()
            .find(|(held, name, _)| held == organization && name == role)
            .map(|(_, _, actions)| actions.clone())
    }
}

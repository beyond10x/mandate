//! `mandate.identity.IncrementSecurityEpoch` over the write port.
//!
//! The command names exactly one target (`systems/mandate/domains/identity.yaml`), so
//! exactly one generation advances and every other dimension is untouched. The advance is
//! the write port's compare-and-set, which is the one event-log transaction
//! `decision-blocker:epoch-atomicity` requires; a concurrent writer that read the same
//! version is refused rather than merged.
//!
//! Whether the caller holds authority for the selected target is the authorization
//! domain's decision and is not made here; the verified context is carried through to the
//! event the accepted outcome emits.
//!
//! Whether the target lies inside the caller's verified organization **is** decided here:
//! "tenant containment fails" is a condition of the declared `denied` outcome, and it is
//! the same comparison of a record's organization against `VerifiedContext::organization`
//! that `RevokeSession` makes. The port only supplies which organizations its records
//! place the target in ([`TargetTenancy`]); the comparison is [`IncrementSecurityEpoch::execute`]'s.

use serde::Serialize;

use mandate_types::{DenialReason, OrganizationId, SecurityEpochTarget, VerifiedContext};

use crate::{Denial, SecurityEpochWrite, StreamVersion};

/// Which organizations the recorded history places a security-epoch target in.
///
/// Read by [`IncrementSecurityEpoch::execute`] before it reaches the write port, so that a
/// caller verified in one organization cannot advance a generation another organization's
/// sessions are bound to.
pub trait TargetTenancy {
    /// Every organization a recorded event places this target in, each once.
    ///
    /// An `Organization` target is its own organization. A `Principal` or `Federation`
    /// target is placed by every record that names it together with an organization. A
    /// target no record places answers none: no snapshot, and so no session, is bound to
    /// its generation in any organization.
    fn organizations_of(&self, target: &SecurityEpochTarget) -> Vec<OrganizationId>;
}

/// The command input: a verified context and the one target it selects.
///
/// The declared input, field for field (`identity.yaml`,
/// `mandate.identity.IncrementSecurityEpoch`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IncrementSecurityEpoch {
    context: VerifiedContext,
    target: SecurityEpochTarget,
}

/// `mandate.identity.SecurityEpochIncremented`, the event the accepted outcome emits.
///
/// The declared payload, field for field: the verified context the command was evaluated
/// in, and the one target that advanced. The context is the command's own
/// (`context: input.context`), which is why the write port that appends this event is
/// handed one rather than inventing it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SecurityEpochIncremented {
    context: VerifiedContext,
    target: SecurityEpochTarget,
}

impl SecurityEpochIncremented {
    /// The payload for a verified context and the target that advanced.
    #[must_use]
    pub const fn new(context: VerifiedContext, target: SecurityEpochTarget) -> Self {
        Self { context, target }
    }

    /// The context the command was evaluated in.
    #[must_use]
    pub const fn context(&self) -> &VerifiedContext {
        &self.context
    }

    /// What advanced.
    #[must_use]
    pub const fn target(&self) -> &SecurityEpochTarget {
        &self.target
    }
}

impl IncrementSecurityEpoch {
    /// The command for a verified context and a selected target.
    #[must_use]
    pub const fn new(context: VerifiedContext, target: SecurityEpochTarget) -> Self {
        Self { context, target }
    }

    /// The context the command is evaluated in.
    #[must_use]
    pub const fn context(&self) -> &VerifiedContext {
        &self.context
    }

    /// The one target the command selects.
    #[must_use]
    pub const fn target(&self) -> &SecurityEpochTarget {
        &self.target
    }

    /// Advance the selected target's generation, at the version it was read at.
    ///
    /// # Errors
    ///
    /// Returns `TenantMismatch` through the declared `denied` outcome when the target lies
    /// outside the caller's verified organization, before the write port is reached. Returns
    /// the declared refusal when the generation is at its maximum — which fails closed, with
    /// no wrap and no reuse — and when another writer advanced the same target since
    /// `expected` was read.
    ///
    /// The tenancy check is not atomic with the write: it is a read before the
    /// compare-and-set, whose token is the target's stream version, so a placement that
    /// commits between the two is advanced past — the transactional behaviour
    /// `decision-blocker:epoch-atomicity` owns.
    pub fn execute<W>(
        &self,
        epochs: &mut W,
        expected: StreamVersion,
    ) -> Result<SecurityEpochIncremented, Denial>
    where
        W: SecurityEpochWrite + TargetTenancy + ?Sized,
    {
        if !self.contained(epochs) {
            return Err(Denial::new(DenialReason::TenantMismatch));
        }
        epochs.increment(&self.context, &self.target, expected)?;
        Ok(SecurityEpochIncremented::new(
            self.context.clone(),
            self.target.clone(),
        ))
    }

    /// Whether the target lies inside the caller's verified organization.
    ///
    /// An organization target by identity. A principal or connection by every organization
    /// the records place it in, and one placement elsewhere refuses, whether or not any
    /// session there is still live. The rule fails closed because the port has no
    /// session-liveness read: forgetting a placement on a wrong "not live" answer would hand
    /// one organization another's lever.
    fn contained<W>(&self, epochs: &W) -> bool
    where
        W: TargetTenancy + ?Sized,
    {
        match &self.target {
            SecurityEpochTarget::Organization(id) => *id == self.context.organization,
            SecurityEpochTarget::Principal(_) | SecurityEpochTarget::Federation(_) => epochs
                .organizations_of(&self.target)
                .iter()
                .all(|organization| *organization == self.context.organization),
        }
    }
}

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

use mandate_types::{SecurityEpochTarget, VerifiedContext};

use crate::{Denial, SecurityEpochWrite, StreamVersion};

/// The command input: a verified context and the one target it selects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncrementSecurityEpoch {
    context: VerifiedContext,
    target: SecurityEpochTarget,
}

/// `mandate.identity.SecurityEpochIncremented`, the event the accepted outcome emits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityEpochIncremented {
    context: VerifiedContext,
    target: SecurityEpochTarget,
}

impl SecurityEpochIncremented {
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
    /// Returns the declared refusal when the generation is at its maximum — which fails
    /// closed, with no wrap and no reuse — and when another writer advanced the same
    /// target since `expected` was read.
    pub fn execute<W>(
        &self,
        epochs: &mut W,
        expected: StreamVersion,
    ) -> Result<SecurityEpochIncremented, Denial>
    where
        W: SecurityEpochWrite + ?Sized,
    {
        epochs.increment(&self.target, expected)?;
        Ok(SecurityEpochIncremented {
            context: self.context.clone(),
            target: self.target.clone(),
        })
    }
}

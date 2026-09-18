//! The identity-local security epoch snapshot and the verdict it produces.
//!
//! `mandate.identity.SecurityEpochSnapshot` is declared with an `EpochSnapshotRef`
//! identity and the principal, organization and connection it applies to; the contract
//! carries no generation on it, because `EpochSnapshotRef` is a record handle and never a
//! number (`systems/mandate/domains/identity.yaml`). The per-dimension values the
//! addendum requires live here, in this crate's projection of that record, and not in
//! `mandate-model` or `mandate-types` — see the crate documentation for why.

use core::fmt;

use mandate_types::{
    DenialReason, EpochSnapshotRef, FederationConnectionId, OrganizationId, PrincipalId,
    SecurityEpochTarget,
};

use crate::{Denial, Generation, IdentityRead};

/// One of the three dimensions a session's eligibility is snapshotted over.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EpochDimension {
    /// The principal's own generation.
    Principal,
    /// The organization's generation.
    Organization,
    /// The federation connection's generation.
    Federation,
}

impl fmt::Display for EpochDimension {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Principal => "principal",
            Self::Organization => "organization",
            Self::Federation => "federation",
        };
        formatter.write_str(name)
    }
}

/// Whether a snapshot still matches the authoritative generations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Eligibility {
    /// Every applicable dimension matches; other checks still apply.
    Current,
    /// The named dimension does not match the authoritative generation.
    Stale(EpochDimension),
}

impl Eligibility {
    /// Whether every applicable dimension matches.
    #[must_use]
    pub const fn is_current(self) -> bool {
        matches!(self, Self::Current)
    }

    /// The dimension that does not match, when one does not.
    #[must_use]
    pub const fn stale_dimension(self) -> Option<EpochDimension> {
        match self {
            Self::Current => None,
            Self::Stale(dimension) => Some(dimension),
        }
    }

    /// The declared refusal a stale verdict produces.
    ///
    /// `mandate.identity.Denied` with `mandate.core.DenialReason::StaleEpoch`.
    #[must_use]
    pub const fn denial(self) -> Option<Denial> {
        match self {
            Self::Current => None,
            Self::Stale(_) => Some(Denial::new(DenialReason::StaleEpoch)),
        }
    }
}

/// The generations a session was issued against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityEpochSnapshot {
    id: EpochSnapshotRef,
    principal: PrincipalId,
    principal_generation: Generation,
    organization: OrganizationId,
    organization_generation: Generation,
    federation: Option<(FederationConnectionId, Generation)>,
}

impl SecurityEpochSnapshot {
    /// A snapshot over the two dimensions every session has.
    #[must_use]
    pub const fn new(
        id: EpochSnapshotRef,
        principal: PrincipalId,
        principal_generation: Generation,
        organization: OrganizationId,
        organization_generation: Generation,
    ) -> Self {
        Self {
            id,
            principal,
            principal_generation,
            organization,
            organization_generation,
            federation: None,
        }
    }

    /// The same snapshot, also covering the federation connection it came from.
    #[must_use]
    pub fn with_federation(
        self,
        connection: FederationConnectionId,
        generation: Generation,
    ) -> Self {
        Self {
            federation: Some((connection, generation)),
            ..self
        }
    }

    /// The handle this snapshot is keyed by.
    #[must_use]
    pub const fn id(&self) -> &EpochSnapshotRef {
        &self.id
    }

    /// The principal the snapshot applies to.
    #[must_use]
    pub const fn principal(&self) -> &PrincipalId {
        &self.principal
    }

    /// The organization the snapshot applies to.
    #[must_use]
    pub const fn organization(&self) -> &OrganizationId {
        &self.organization
    }

    /// The federation connection the snapshot applies to, when it came from one.
    #[must_use]
    pub const fn connection(&self) -> Option<&FederationConnectionId> {
        match &self.federation {
            Some((connection, _)) => Some(connection),
            None => None,
        }
    }

    /// The generation this snapshot recorded for a target, or `None` when the target
    /// names a subject this snapshot does not apply to.
    ///
    /// This is where isolation is decided: an increment on one organization names a
    /// target no other organization's snapshot records, so it cannot make that snapshot
    /// stale.
    #[must_use]
    pub fn recorded(&self, target: &SecurityEpochTarget) -> Option<Generation> {
        match target {
            SecurityEpochTarget::Principal(id) if *id == self.principal => {
                Some(self.principal_generation)
            }
            SecurityEpochTarget::Organization(id) if *id == self.organization => {
                Some(self.organization_generation)
            }
            SecurityEpochTarget::Federation(id) => match &self.federation {
                Some((connection, generation)) if connection == id => Some(*generation),
                _ => None,
            },
            _ => None,
        }
    }

    /// Every target this snapshot is compared against, in comparison order.
    #[must_use]
    pub fn targets(&self) -> Vec<SecurityEpochTarget> {
        let mut targets = vec![
            SecurityEpochTarget::Principal(self.principal),
            SecurityEpochTarget::Organization(self.organization),
        ];
        if let Some((connection, _)) = &self.federation {
            targets.push(SecurityEpochTarget::Federation(*connection));
        }
        targets
    }

    /// The verdict for this snapshot against the authoritative generations.
    ///
    /// Each applicable dimension must match exactly; the first mismatch is reported.
    pub fn eligibility<R>(&self, epochs: &R) -> Eligibility
    where
        R: IdentityRead + ?Sized,
    {
        for target in self.targets() {
            let Some(recorded) = self.recorded(&target) else {
                continue;
            };
            if epochs.current(&target).generation() != recorded {
                return Eligibility::Stale(dimension_of(&target));
            }
        }
        Eligibility::Current
    }
}

/// The dimension a target names.
const fn dimension_of(target: &SecurityEpochTarget) -> EpochDimension {
    match target {
        SecurityEpochTarget::Principal(_) => EpochDimension::Principal,
        SecurityEpochTarget::Organization(_) => EpochDimension::Organization,
        SecurityEpochTarget::Federation(_) => EpochDimension::Federation,
    }
}

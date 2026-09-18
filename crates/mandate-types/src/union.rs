//! The accepted `union` types, realized as the tagged value the contract declares.
//!
//! `SecurityEpochTarget` names what an epoch applies to. It carries a reference, never a
//! generation, so realizing it does not touch the numeric epoch representation that
//! `UNMAPPED-EPOCH` still blocks.

use crate::{FederationConnectionId, OrganizationId, PrincipalId, TeamId};

canonical_unions! {
    AuthoritySubject {
        "principal" => Principal(PrincipalId),
        "team" => Team(TeamId),
    },
    SecurityEpochTarget {
        "principal" => Principal(PrincipalId),
        "organization" => Organization(OrganizationId),
        "federation" => Federation(FederationConnectionId),
    },
}

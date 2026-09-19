//! The typed registry of every command's adapter obligations.
//!
//! `docs/architecture/runtime-decisions.md:118`: `decision-blocker:guards` asks for "A written
//! adapter contract naming, for every one of the [61] commands ... which party establishes each
//! declared precondition. A sample is not evidence; the table is the enumeration." This module
//! is that enumeration in code, and `docs/architecture/adapter-contract.md` is the document
//! derived from it. The code is the normative half: a document can drift and a test cannot.
//!
//! # What is enumerated, and what bounds it
//!
//! One [`Obligation`] per `operationId` of `generated/openapi/*.yaml` — 61 today, read from the
//! documents at test time rather than restated, so a command the contract adds fails
//! `crates/mandate-server/tests/obligations.rs` until it has a row.
//!
//! Each row states how the command is reached ([`Wire`]) and, for the four the login road
//! serves, one [`Clause`] per phrase of its declared denial with the party that establishes it
//! ([`Establishes`]). The clause phrases are not typed out here as a matter of style: the test
//! splits each command's row in `docs/architecture/command-obligations.md` — which
//! `xtask/src/main.rs:255-315` already pins, verbatim, to the contract's own `denied` cause —
//! with [`clauses_of`], and requires the registry to name exactly the clauses that split
//! produces. A denial phrase that drifts in the contract fails here.
//!
//! # The bound on the class, stated rather than implied
//!
//! The per-clause enumeration covers the **four road commands**, 25 clauses. The other 57 rows
//! state, in whole, that this adapter establishes none of their preconditions and decodes
//! nothing for them: they are reached only through their generated
//! `POST /<domain>/commands/<Command>` projection, which `docs/public/contracts.md:29` says
//! implements no product route. Their product routes, and the per-clause enumeration that
//! comes with those routes, are `story:protocol-adapters`' residue. That is a bound, not a
//! claim of completeness: `decision-blocker:guards` does not clear on this registry alone.
//!
//! # One reading recorded, because the split is mechanical and the prose is not
//!
//! `mandate.credential.IntrospectCredential`'s declared cause reads "Caller proof lacks
//! introspection authority for the registered server/tenant or is itself invalid, revoked or
//! expired, ...". [`clauses_of`] splits that comma, so "revoked or expired" becomes a clause of
//! its own where the prose means it as the tail of the one before it. The split is kept
//! mechanical — a splitter with an exception list is a splitter that can be taught to miss a
//! clause — and the reading is recorded here and reported as a contract-prose observation
//! against `systems/mandate/domains/credential.yaml:446`.

use crate::routes::Method;

/// Which party establishes a declared precondition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Establishes {
    /// The wire form decides it, so the adapter refuses before any handler is reached.
    Adapter,
    /// A deciding handler establishes it against reads this crate cannot make. The adapter's
    /// obligation is the opposite of a decision: admit the request unchanged, and pass no
    /// selector by which the caller could have established the condition itself.
    Handler,
}

/// One phrase of a command's declared `denied` cause, and who establishes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Clause {
    /// The phrase, verbatim from the command's row in `docs/architecture/command-obligations.md`.
    pub phrase: &'static str,
    /// Which party establishes it.
    pub establishes: Establishes,
}

/// The body form a product route's request carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BodyForm {
    /// A JSON object request body.
    Json,
    /// An `application/x-www-form-urlencoded` request body.
    Form,
    /// The request target's query component.
    Query,
}

/// How a command is reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Wire {
    /// Only through its generated `POST /<domain>/commands/<Command>` projection. This library
    /// declares no product route for it and decodes nothing for it.
    Generated,
    /// Through a product route of [`crate::routes::ROUTES`].
    Product {
        /// The method the route answers.
        method: Method,
        /// The path the route answers.
        path: &'static str,
        /// Where the request's parameters are carried.
        body: BodyForm,
    },
}

/// One command's adapter obligations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Obligation {
    /// The `operationId` the generated projection publishes for this command.
    pub command: &'static str,
    /// How it is reached.
    pub wire: Wire,
    /// The decoder in `crate::decode` that builds its declared input, when this library has one.
    pub decoder: Option<&'static str>,
    /// One entry per phrase of its declared denial, for the commands the login road serves.
    pub clauses: &'static [Clause],
}

/// The four commands the customer login road serves, in the order the road runs them.
pub const ROAD_COMMANDS: &[&str] = &[
    "mandate.federation.AuthenticateFederation",
    "mandate.federation.AuthorizePublicClient",
    "mandate.credential.RedeemAuthorizationCode",
    "mandate.credential.IntrospectCredential",
];

/// `mandate.federation.AuthenticateFederation`'s declared denial, clause by clause.
const AUTHENTICATE_FEDERATION: &[Clause] = &[
    Clause {
        phrase: "Connection is disabled/untrusted",
        establishes: Establishes::Handler,
    },
    Clause {
        phrase: "proof signature/issuer/audience/expiry is invalid",
        establishes: Establishes::Handler,
    },
    Clause {
        phrase: "tenant resolution has zero or multiple matches",
        establishes: Establishes::Handler,
    },
    Clause {
        phrase: "principal linking is absent/conflicting",
        establishes: Establishes::Handler,
    },
    // The one clause of this command the wire form decides: the request body admits
    // `connection_id` and `proof` and refuses every other member, so there is no unverified
    // input for a fallback to reach for.
    Clause {
        phrase: "any email-domain/unverified-input fallback would be required",
        establishes: Establishes::Adapter,
    },
];

/// `mandate.federation.AuthorizePublicClient`'s declared denial, clause by clause.
const AUTHORIZE_PUBLIC_CLIENT: &[Clause] = &[
    Clause {
        phrase: "Session proof is invalid/stale",
        establishes: Establishes::Handler,
    },
    Clause {
        phrase: "client is not a registered public client",
        establishes: Establishes::Handler,
    },
    Clause {
        phrase: "the client is disabled",
        establishes: Establishes::Handler,
    },
    Clause {
        phrase: "exact redirect URI or state/applicable nonce binding fails",
        establishes: Establishes::Handler,
    },
    // Absent, mis-shaped, or offered under a method other than S256: each is decided by the
    // request alone. Case `pkce-plain` is the third.
    Clause {
        phrase: "S256 challenge is absent/invalid",
        establishes: Establishes::Adapter,
    },
    Clause {
        phrase: "target is unregistered/outside tenant",
        establishes: Establishes::Handler,
    },
    Clause {
        phrase: "STS code issuance/narrowing is refused",
        establishes: Establishes::Handler,
    },
];

/// `mandate.credential.RedeemAuthorizationCode`'s declared denial, clause by clause.
const REDEEM_AUTHORIZATION_CODE: &[Clause] = &[
    // "server-resolved" is the adapter's half of this clause: a caller-presented `code_id` is
    // refused, so the identifier the proof is resolved against is never one the caller chose.
    Clause {
        phrase: "Code proof does not match the server-resolved code_id",
        establishes: Establishes::Adapter,
    },
    Clause {
        phrase: "code is expired",
        establishes: Establishes::Handler,
    },
    // The verifier's *form* is the adapter's — case `pkce-missing` and RFC 7636 section 4.1 —
    // and the three mismatches themselves are the handler's, against the code record.
    Clause {
        phrase: "client, redirect URI or S256 verifier mismatches",
        establishes: Establishes::Adapter,
    },
    Clause {
        phrase: "the bound client is disabled",
        establishes: Establishes::Handler,
    },
    Clause {
        phrase: "source/session epoch is stale",
        establishes: Establishes::Handler,
    },
    Clause {
        phrase: "registered target is disabled or outside the verified tenant",
        establishes: Establishes::Handler,
    },
    Clause {
        phrase: "narrowing/atomic issuance validation fails",
        establishes: Establishes::Handler,
    },
];

/// `mandate.credential.IntrospectCredential`'s declared denial, clause by clause.
///
/// The second entry is the tail of the first in the contract's prose; see the module note.
const INTROSPECT_CREDENTIAL: &[Clause] = &[
    Clause {
        phrase: "Caller proof lacks introspection authority for the registered server/tenant or is itself invalid",
        establishes: Establishes::Handler,
    },
    Clause {
        phrase: "revoked or expired",
        establishes: Establishes::Handler,
    },
    Clause {
        phrase: "the presented credential proof is malformed",
        establishes: Establishes::Adapter,
    },
    Clause {
        phrase: "principal/connection/epoch validation fails",
        establishes: Establishes::Handler,
    },
    Clause {
        phrase: "audience mismatches",
        establishes: Establishes::Handler,
    },
    Clause {
        phrase: "authoritative online resolution is unavailable",
        establishes: Establishes::Handler,
    },
];

/// Every command the contract declares, with its adapter obligations.
///
/// The four road commands first, in road order; the other 57 after, by name.
pub const OBLIGATIONS: &[Obligation] = &[
    Obligation {
        command: "mandate.federation.AuthenticateFederation",
        wire: Wire::Product {
            method: Method::Post,
            path: "/v1/federation/login",
            body: BodyForm::Json,
        },
        decoder: Some("decode::authenticate_federation"),
        clauses: AUTHENTICATE_FEDERATION,
    },
    Obligation {
        command: "mandate.federation.AuthorizePublicClient",
        wire: Wire::Product {
            method: Method::Get,
            path: "/oauth/authorize",
            body: BodyForm::Query,
        },
        decoder: Some("decode::authorize_public_client"),
        clauses: AUTHORIZE_PUBLIC_CLIENT,
    },
    Obligation {
        command: "mandate.credential.RedeemAuthorizationCode",
        wire: Wire::Product {
            method: Method::Post,
            path: "/oauth/token",
            body: BodyForm::Form,
        },
        decoder: Some("decode::redeem_authorization_code"),
        clauses: REDEEM_AUTHORIZATION_CODE,
    },
    Obligation {
        command: "mandate.credential.IntrospectCredential",
        wire: Wire::Product {
            method: Method::Post,
            path: "/oauth/introspect",
            body: BodyForm::Form,
        },
        decoder: Some("decode::introspect_credential"),
        clauses: INTROSPECT_CREDENTIAL,
    },
    Obligation {
        command: "mandate.audit.RecordAuditEvent",
        wire: Wire::Generated,
        decoder: None,
        clauses: &[],
    },
    Obligation {
        command: "mandate.audit.RedactAuditEvent",
        wire: Wire::Generated,
        decoder: None,
        clauses: &[],
    },
    Obligation {
        command: "mandate.authorization.Check",
        wire: Wire::Generated,
        decoder: None,
        clauses: &[],
    },
    Obligation {
        command: "mandate.credential.DisableResourceServer",
        wire: Wire::Generated,
        decoder: None,
        clauses: &[],
    },
    Obligation {
        command: "mandate.credential.ExchangeCredential",
        wire: Wire::Generated,
        decoder: None,
        clauses: &[],
    },
    Obligation {
        command: "mandate.credential.IssueAuthorizationCode",
        wire: Wire::Generated,
        decoder: None,
        clauses: &[],
    },
    Obligation {
        command: "mandate.credential.IssueReferenceCredential",
        wire: Wire::Generated,
        decoder: None,
        clauses: &[],
    },
    Obligation {
        command: "mandate.credential.IssueSelfContainedCredential",
        wire: Wire::Generated,
        decoder: None,
        clauses: &[],
    },
    Obligation {
        command: "mandate.credential.RegisterResourceServer",
        wire: Wire::Generated,
        decoder: None,
        clauses: &[],
    },
    Obligation {
        command: "mandate.credential.RegisterSigningKey",
        wire: Wire::Generated,
        decoder: None,
        clauses: &[],
    },
    Obligation {
        command: "mandate.credential.RetireSigningKey",
        wire: Wire::Generated,
        decoder: None,
        clauses: &[],
    },
    Obligation {
        command: "mandate.credential.RevokeAccessCredential",
        wire: Wire::Generated,
        decoder: None,
        clauses: &[],
    },
    Obligation {
        command: "mandate.credential.RevokeSigningKey",
        wire: Wire::Generated,
        decoder: None,
        clauses: &[],
    },
    Obligation {
        command: "mandate.delegation.CompleteExecution",
        wire: Wire::Generated,
        decoder: None,
        clauses: &[],
    },
    Obligation {
        command: "mandate.delegation.ConsumeApproval",
        wire: Wire::Generated,
        decoder: None,
        clauses: &[],
    },
    Obligation {
        command: "mandate.delegation.CreateDelegation",
        wire: Wire::Generated,
        decoder: None,
        clauses: &[],
    },
    Obligation {
        command: "mandate.delegation.RetireAgent",
        wire: Wire::Generated,
        decoder: None,
        clauses: &[],
    },
    Obligation {
        command: "mandate.delegation.RevokeDelegation",
        wire: Wire::Generated,
        decoder: None,
        clauses: &[],
    },
    Obligation {
        command: "mandate.delegation.SupersedeAgentCapabilityCeiling",
        wire: Wire::Generated,
        decoder: None,
        clauses: &[],
    },
    Obligation {
        command: "mandate.directory.CompleteSyncJob",
        wire: Wire::Generated,
        decoder: None,
        clauses: &[],
    },
    Obligation {
        command: "mandate.directory.CreateDirectoryGroupTeamMapping",
        wire: Wire::Generated,
        decoder: None,
        clauses: &[],
    },
    Obligation {
        command: "mandate.directory.FailSyncJob",
        wire: Wire::Generated,
        decoder: None,
        clauses: &[],
    },
    Obligation {
        command: "mandate.directory.RemoveDirectoryGroupMembership",
        wire: Wire::Generated,
        decoder: None,
        clauses: &[],
    },
    Obligation {
        command: "mandate.directory.RemoveDirectoryGroupTeamMapping",
        wire: Wire::Generated,
        decoder: None,
        clauses: &[],
    },
    Obligation {
        command: "mandate.directory.RemoveMembershipContribution",
        wire: Wire::Generated,
        decoder: None,
        clauses: &[],
    },
    Obligation {
        command: "mandate.directory.RetireDirectoryGroup",
        wire: Wire::Generated,
        decoder: None,
        clauses: &[],
    },
    Obligation {
        command: "mandate.directory.SyncDirectoryMembership",
        wire: Wire::Generated,
        decoder: None,
        clauses: &[],
    },
    Obligation {
        command: "mandate.federation.DisableFederationConnection",
        wire: Wire::Generated,
        decoder: None,
        clauses: &[],
    },
    Obligation {
        command: "mandate.federation.DisableOAuthClient",
        wire: Wire::Generated,
        decoder: None,
        clauses: &[],
    },
    Obligation {
        command: "mandate.federation.LinkExternalPrincipal",
        wire: Wire::Generated,
        decoder: None,
        clauses: &[],
    },
    Obligation {
        command: "mandate.federation.ProvisionExternalPrincipal",
        wire: Wire::Generated,
        decoder: None,
        clauses: &[],
    },
    Obligation {
        command: "mandate.federation.RegisterFederationConnection",
        wire: Wire::Generated,
        decoder: None,
        clauses: &[],
    },
    Obligation {
        command: "mandate.federation.RegisterOAuthClient",
        wire: Wire::Generated,
        decoder: None,
        clauses: &[],
    },
    Obligation {
        command: "mandate.federation.UnlinkExternalPrincipal",
        wire: Wire::Generated,
        decoder: None,
        clauses: &[],
    },
    Obligation {
        command: "mandate.graph.DeregisterResource",
        wire: Wire::Generated,
        decoder: None,
        clauses: &[],
    },
    Obligation {
        command: "mandate.graph.RegisterResource",
        wire: Wire::Generated,
        decoder: None,
        clauses: &[],
    },
    Obligation {
        command: "mandate.graph.RemoveRelation",
        wire: Wire::Generated,
        decoder: None,
        clauses: &[],
    },
    Obligation {
        command: "mandate.graph.RevokeGrant",
        wire: Wire::Generated,
        decoder: None,
        clauses: &[],
    },
    Obligation {
        command: "mandate.graph.WriteRelationship",
        wire: Wire::Generated,
        decoder: None,
        clauses: &[],
    },
    Obligation {
        command: "mandate.identity.DisablePrincipal",
        wire: Wire::Generated,
        decoder: None,
        clauses: &[],
    },
    Obligation {
        command: "mandate.identity.IncrementSecurityEpoch",
        wire: Wire::Generated,
        decoder: None,
        clauses: &[],
    },
    Obligation {
        command: "mandate.identity.RefreshSession",
        wire: Wire::Generated,
        decoder: None,
        clauses: &[],
    },
    Obligation {
        command: "mandate.identity.RevokeRefreshCredential",
        wire: Wire::Generated,
        decoder: None,
        clauses: &[],
    },
    Obligation {
        command: "mandate.identity.RevokeSession",
        wire: Wire::Generated,
        decoder: None,
        clauses: &[],
    },
    Obligation {
        command: "mandate.policy.SupersedeAuthorizationModel",
        wire: Wire::Generated,
        decoder: None,
        clauses: &[],
    },
    Obligation {
        command: "mandate.policy.SupersedePolicy",
        wire: Wire::Generated,
        decoder: None,
        clauses: &[],
    },
    Obligation {
        command: "mandate.tenancy.AddOrganizationMembership",
        wire: Wire::Generated,
        decoder: None,
        clauses: &[],
    },
    Obligation {
        command: "mandate.tenancy.AddTeamMembership",
        wire: Wire::Generated,
        decoder: None,
        clauses: &[],
    },
    Obligation {
        command: "mandate.tenancy.CloseOrganization",
        wire: Wire::Generated,
        decoder: None,
        clauses: &[],
    },
    Obligation {
        command: "mandate.tenancy.CreateOrganization",
        wire: Wire::Generated,
        decoder: None,
        clauses: &[],
    },
    Obligation {
        command: "mandate.tenancy.CreateSpace",
        wire: Wire::Generated,
        decoder: None,
        clauses: &[],
    },
    Obligation {
        command: "mandate.tenancy.CreateTeam",
        wire: Wire::Generated,
        decoder: None,
        clauses: &[],
    },
    Obligation {
        command: "mandate.tenancy.RemoveOrganizationMembership",
        wire: Wire::Generated,
        decoder: None,
        clauses: &[],
    },
    Obligation {
        command: "mandate.tenancy.RemoveTeamMembership",
        wire: Wire::Generated,
        decoder: None,
        clauses: &[],
    },
    Obligation {
        command: "mandate.tenancy.RetireSpace",
        wire: Wire::Generated,
        decoder: None,
        clauses: &[],
    },
    Obligation {
        command: "mandate.tenancy.RetireTeam",
        wire: Wire::Generated,
        decoder: None,
        clauses: &[],
    },
    Obligation {
        command: "mandate.workload.RevokeWorkloadIdentity",
        wire: Wire::Generated,
        decoder: None,
        clauses: &[],
    },
];

/// The obligations of one command, or `None` when this registry declares none.
#[must_use]
pub fn obligation(command: &str) -> Option<&'static Obligation> {
    OBLIGATIONS
        .iter()
        .find(|obligation| obligation.command == command)
}

/// Split a declared denial cause into the clauses it carries.
///
/// The obligations table writes a cause as a sentence of clauses, and separates them one of two
/// ways: with `; ` when a clause carries a comma of its own
/// (`RedeemAuthorizationCode`: "client, redirect URI or S256 verifier mismatches"), and with
/// `, ` otherwise. This picks the semicolon when the cause carries one, because a cause that
/// uses semicolons uses them for every separation; a leading `or ` and the trailing `.` are
/// stripped from the last clause.
///
/// Mechanical on purpose. A splitter with an exception list is a splitter that can be taught to
/// miss a clause, which is the one failure the enumeration exists to prevent.
#[must_use]
pub fn clauses_of(cause: &str) -> Vec<&str> {
    let cause = cause.trim().trim_end_matches('.');
    let separator = if cause.contains("; ") { "; " } else { ", " };
    cause
        .split(separator)
        .map(|clause| clause.trim().trim_start_matches("or ").trim())
        .filter(|clause| !clause.is_empty())
        .collect()
}

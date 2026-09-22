//! Forced outcomes, the ports they are forced at, and the ledger of everything this target
//! stood in for.
//!
//! §12's `configure_external_outcome` exists for an outcome *the input cannot decide* — a
//! provider that will not accept the mail — and the suite arms one for every command
//! `systems/mandate` declares. This module decides, per command, **where** that fault goes:
//! at the port the handler consults, named, and never at the handler's own answer. A target
//! that "forced" a denial by returning one without calling the handler would report a
//! manufactured expectation, which is the one failure a conformance report cannot show.
//!
//! # Thirteen commands are refused before dispatch, for two different reasons
//!
//! Ten `mandate.tenancy` commands and the two `mandate.graph` registration commands are
//! decided entirely inside a fold: `Tenancy` and `Topology` read no port at all, so there is
//! nowhere to put a fault. They carry [`NO_PORT`].
//!
//! `mandate.identity.RevokeSession` is the thirteenth and is **not** one of them, and saying
//! so is the point of the distinction: `mandate_identity::revoke_session` calls
//! `log.resolve(&id)`, which is `IdentityRead::resolve` — the same port method
//! `refresh_session` reads and that this module *does* substitute a reader at. What stops
//! the substitution is the signature: the handler takes `&mut IdentityLog`, the concrete
//! type, so the port it reads through is not one a caller can replace. It carries
//! [`NOT_SUBSTITUTABLE`], which names the port and says why the arming cannot reach it.
//!
//! All thirteen refuse the arming step itself, before the command is dispatched, and record
//! that refusal — ruling 5 of the wave D enforcement track. The class is
//! `story:testkit-doubles`' and the deciders'.
//!
//! # An armed row says what the substituted reader did
//!
//! A row that said `armed` and nothing else attributed a scenario's answer to a fault
//! without showing that the fault reached anything, which is the same defect as reporting a
//! manufactured expectation one layer out. Every substituted reader therefore counts its own
//! consultations and its own refusals, and the row carries both in its `kind` and its
//! `consulted`:
//!
//! | `kind` | what it says |
//! |---|---|
//! | `armed` | a reader was substituted and it answered something the standing reader could not have |
//! | `armed-unrefused` | a reader was substituted and consulted `consulted` times, and refused nothing |
//! | `armed-unreached` | the arming lapsed without a reader ever being consulted: the command refused, or decided, before reading anything |
//! | `refused-before-dispatch` | there was no reader to substitute; see above |
//! | `unsupported-command` | no crate realizes the command |
//!
//! What a substituted reader answers is decided by the signature it is answering through,
//! not by what would make an injection look effective: **absence** for every read whose
//! signature can express one, and a **refusal** only where the signature cannot.
//! `admits_audience` returns `Result<(), Denied>` and `increment` returns
//! `Result<EpochState, Denial>`; neither has an "it holds nothing" value, so the fault at
//! those two ports is the refusal or it is nothing at all. Every other read answers `None`,
//! `Ok(None)` or the port's own "could not answer", which is what an **empty real store**
//! answers.
//!
//! **An empty real store is not always the standing reader**, and one port here is exactly
//! that case. [`ScenarioKeys`] resolves **every** key reference, so
//! `KeyMaterialResolver::thumbprint` answering `None` is an answer the standing reader never
//! gives — and that is what produces `KeyReferenceUnresolvable` at
//! `services/sts/src/keys.rs:204`. The divergence *is* the arming for
//! `mandate.credential.RegisterSigningKey`, and it is stated here rather than hidden behind
//! a rule that does not hold at it.
//!
//! `mandate_graph::double::GraphDouble` looked like a second such port and is not: it opens
//! at revision `0` and **decides against** a caller it holds no membership for, which is an
//! empty store's own decision and not an outage, and [`Substituted`]'s `GraphRead::check`
//! now gives that same answer rather than reporting an inability it is not having.
//!
//! So `armed-unrefused` is a statement about what the substituted reader *did* — it was
//! consulted and refused nothing — and not a claim that the scenario would have come out the
//! same without the arming. Whether it would have is a second run, which `injections.json`
//! is not, and `tests/adversary_conformance_1.rs` is where that comparison is actually
//! made.
//!
//! # Every double is written down
//!
//! [`Ledger`] is what `injections.json` is. It carries three lists and they answer three
//! different questions: which real adapter each standing double stood in for, what was done
//! at which port for each armed scenario, and which scenarios this target could not satisfy
//! and whose story owns each. A run whose doubles were not written down is a run nobody can
//! attribute.

use std::cell::Cell;
use std::collections::BTreeMap;

use mandate_federation::record::FederationConnection;
use mandate_federation::verifier::VerifiedProof;
use mandate_federation::{DenialClause, Denied, FederationVerifier};
use mandate_types::{ClientId, CredentialProof, DenialReason, ExternalSubject, Issuer};
use serde::Serialize;

/// One adapter this target does not have, and what stood in for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StandingDouble {
    /// The port the real deployment answers.
    pub port: &'static str,
    /// The type that answered it here.
    pub double: &'static str,
    /// Why a double rather than the adapter.
    pub why: &'static str,
}

/// What was done at a port for one armed scenario.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Injection {
    /// The scenario that armed it.
    pub scenario: String,
    /// The command whose next invocation it applies to.
    pub command: String,
    /// The port the fault was placed at, or `none` where the handler consults none.
    pub port: &'static str,
    /// What was done: see the table in the module documentation.
    pub kind: &'static str,
    /// How many times the substituted reader was consulted.
    ///
    /// Zero for every row that substituted nothing, and zero for an `armed` row whose
    /// command refused before reading — which is the fact the row exists to make visible.
    pub consulted: u32,
}

/// One scenario this target could not satisfy, and the story that owns it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Blocked {
    /// The scenario.
    pub scenario: String,
    /// The command that could not be driven, where one command is responsible.
    pub command: String,
    /// The class: what kind of gap this is.
    pub reason: &'static str,
    /// The live story that owns closing it.
    pub blocked_on: String,
}

/// Everything this run stood in for, injected or could not satisfy.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Ledger {
    /// The doubles that answered a port no adapter is attached to.
    pub standing_doubles: Vec<StandingDouble>,
    /// Every armed external outcome, in the order the suite armed them.
    pub injections: Vec<Injection>,
    /// Every scenario that did not pass, with the story that owns it.
    pub blocked: Vec<Blocked>,
}

impl Ledger {
    /// A ledger naming the doubles this target stands on.
    ///
    /// Recorded once at the start of a run rather than per scenario: they are properties of
    /// the target, and repeating them 146 times would say nothing more.
    #[must_use]
    pub fn opened() -> Self {
        Self {
            standing_doubles: STANDING.to_vec(),
            injections: Vec::new(),
            blocked: Vec::new(),
        }
    }

    /// Record what was done at a port for one scenario.
    pub fn inject(
        &mut self,
        scenario: &str,
        command: &str,
        port: &'static str,
        kind: &'static str,
    ) {
        self.injections.push(Injection {
            scenario: scenario.to_owned(),
            command: command.to_owned(),
            port,
            kind,
            consulted: 0,
        });
    }

    /// Record what the reader substituted for one armed command actually did.
    ///
    /// Called after the handler returns, because that is when the count exists. An arming
    /// whose command never reached a substitution leaves the row at `armed-unreached` and
    /// `consulted: 0`, which is the honest reading and the one the row is for.
    pub fn consulted(&mut self, scenario: &str, command: &str, consulted: u32, refused: u32) {
        let Some(row) = self
            .injections
            .iter_mut()
            .rev()
            .find(|held| held.scenario == scenario && held.command == command)
        else {
            return;
        };
        row.consulted = consulted;
        // Read off the two counts and nothing else. An earlier label said "the arming
        // could not change the scenario", which `refused == 0` does not show: whether it
        // would have is a second run of the suite, and this document is one run.
        row.kind = if refused > 0 {
            "armed"
        } else if consulted > 0 {
            "armed-unrefused"
        } else {
            "armed-unreached"
        };
    }

    /// Record a scenario this target could not satisfy, once.
    ///
    /// A scenario reaches this at most once even when several of its steps are refused: the
    /// runner stops a scenario at the first refusal, and a second entry for one identity
    /// would make `injections.json` disagree with `report.outcomes`, which is a partition.
    pub fn block(&mut self, scenario: &str, command: &str, reason: &'static str, story: &str) {
        if self.blocked.iter().any(|held| held.scenario == scenario) {
            return;
        }
        self.blocked.push(Blocked {
            scenario: scenario.to_owned(),
            command: command.to_owned(),
            reason,
            blocked_on: story.to_owned(),
        });
    }

    /// The ledger in the canonical order a byte comparison needs.
    #[must_use]
    pub fn sorted(mut self) -> Self {
        self.injections.sort_by(|one, other| {
            (&one.scenario, &one.command).cmp(&(&other.scenario, &other.command))
        });
        self.blocked
            .sort_by(|one, other| one.scenario.cmp(&other.scenario));
        self
    }
}

/// The doubles this target stands on, each naming the adapter it replaces.
const STANDING: &[StandingDouble] = &[
    StandingDouble {
        port: "mandate_federation::FederationVerifier",
        double: "mandate_conformance::external::ScenarioVerifier",
        why: "no signature verification is performed: the claims are read out of the \
              proof's own payload segment, unverified, so a scenario that authored a proof \
              is answered with what it authored rather than with a forged validation",
    },
    StandingDouble {
        port: "mandate_federation::IdentityAllocator",
        double: "mandate_federation::SequentialAllocator",
        why: "no crate in the federation dependency ceiling generates a uuid",
    },
    StandingDouble {
        port: "mandate_federation::SessionIssuer",
        double: "mandate_federation::RecordingSessionIssuer",
        why: "session issuance is `mandate.identity`'s and reaches this crate as a port",
    },
    StandingDouble {
        port: "mandate_federation::register_client::ClientRegistrationAdmission",
        double: "mandate_federation::register_client::ConfiguredAdmission",
        why: "client-administration authority is an authorization decision no crate in \
              the federation ceiling makes",
    },
    StandingDouble {
        port: "mandate_graph::port::GraphRead",
        double: "mandate_graph::double::GraphDouble",
        why: "the relationship store is `story:graph-policy-adapter`'s",
    },
    StandingDouble {
        port: "mandate_policy::port::PolicyEvaluator",
        double: "mandate_policy::double::PolicyDouble",
        why: "the policy engine is `story:graph-policy-adapter`'s",
    },
    StandingDouble {
        port: "mandate_authz::CheckRequest::expected_audience",
        double: "the verified context's own audience",
        why: "no audience registry is reachable from the authorization ceiling, so the \
              caller states what it requires; this target requires what the context carries, \
              which makes the audience bound satisfied rather than evaluated",
    },
    StandingDouble {
        port: "mandate_authz::CheckRequest::relation",
        double: "the requested action's own name",
        why: "no domain declares a mapping from an action to the roles that carry it, so \
              the caller names the relation the graph is asked about",
    },
    StandingDouble {
        port: "mandate_authz::CheckRequest::minimum",
        double: "AuthzRevision(\"0\")",
        why: "the revision floor a read must not answer below; the initial one, so a read \
              is refused for the authority and never for the floor",
    },
    StandingDouble {
        port: "mandate_authz::CheckRequest::attributes",
        double: "an empty mandate_policy::port::AttributeSet",
        why: "the attribute input policy evaluates against; no declared command input \
              carries one and no port answers it",
    },
    StandingDouble {
        port: "mandate_authz::CheckRequest::scope",
        double: "None",
        why: "the authority a request is made under; the declared input carries none, so \
              no scope bound is intersected and none is claimed to have been",
    },
    StandingDouble {
        port: "mandate_authz::decision::DecisionIdAllocator",
        double: "mandate_authz::decision::SequentialDecisionIds",
        why: "no crate in the authorization ceiling generates a uuid",
    },
    StandingDouble {
        port: "mandate_authz::decision::ChallengeIssuer",
        double: "mandate_authz::decision::FixedChallenge",
        why: "an approval policy and a challenge expiry are values no port answers",
    },
    StandingDouble {
        port: "mandate_identity::IdentityLog",
        double: "mandate_identity::IdentityLog",
        why: "the in-memory double of the event-log adapter a later story supplies",
    },
    StandingDouble {
        port: "mandate_sts::CredentialDigest",
        double: "mandate_sts::issue::Sha256Digest",
        why: "the digest domain a deployment configures; this is the crate's own SHA-256",
    },
    StandingDouble {
        port: "mandate_sts::SecretSource",
        double: "mandate_sts::CountingSecrets",
        why: "no crate in the STS dependency ceiling holds a random source",
    },
    StandingDouble {
        port: "mandate_sts::IdentityAllocator",
        double: "mandate_sts::SequentialAllocator",
        why: "no crate in the STS dependency ceiling generates a uuid",
    },
    StandingDouble {
        port: "mandate_token::signing_real::AllowedAlgorithms",
        double: "AllowedAlgorithms([\"ES256\"])",
        why: "UNMAPPED-ALGORITHM-POLICY: a SigningAlgorithm is a name and the admitted set \
              is a deployment's, validated at startup; this target states one of the two \
              names mandate-token admits so RegisterSigningKey is decided against a policy \
              rather than against nothing",
    },
    StandingDouble {
        port: "mandate_sts::code::CodeLifetime",
        double: "CodeLifetime(\"PT10M\")",
        why: "the longest lifetime a deployment issues an authorization code for; the \
              contract carries no default and `code.rs` has no constant, so the ceiling \
              IssueAuthorizationCode is bounded by is stated here",
    },
    StandingDouble {
        port: "mandate_sts::issue::IssuanceSigner",
        double: "mandate_sts::issue::StaticSigner",
        why: "the signing key material is the deployment's and no scenario supplies one",
    },
    StandingDouble {
        port: "mandate_sts::keys::KeyMaterialResolver",
        double: "mandate_conformance::external::ScenarioKeys",
        why: "the public half of a key reference is material the deployment loads; this \
              answers a thumbprint derived from the reference itself and computes no key",
    },
    StandingDouble {
        port: "mandate_sts::code::OAuthClientReads",
        double: "mandate_sts::code::RecordedClients",
        why: "mandate.federation owns the OAuth client record and no command of this \
              contract writes it into the STS's own read model",
    },
    StandingDouble {
        port: "mandate_sts::binding::SessionReads",
        double: "mandate_sts::binding::RecordedSessions",
        why: "mandate.identity owns the session record and the STS reads it over an adapter \
              no crate on this line supplies",
    },
    StandingDouble {
        port: "mandate_sts::store::AuthorizationCodeLog",
        double: "mandate_sts::store::InMemoryCodeLog",
        why: "the in-memory double of the code log the STS deployment supplies",
    },
];

/// The port each realized command's fault is placed at, and `NO_PORT` where there is none.
///
/// One row per command the target dispatches, which
/// `crates/mandate-conformance/tests/target.rs` decides against the dispatch table: a
/// command that grew a dispatch arm and no row here would arm nothing and record nothing.
pub const PORTS: &[(&str, &str)] = &[
    (
        "mandate.federation.RegisterFederationConnection",
        "mandate_federation::ConnectionStore",
    ),
    (
        "mandate.federation.LinkExternalPrincipal",
        "mandate_federation::LinkStore",
    ),
    (
        "mandate.federation.AuthenticateFederation",
        "mandate_federation::FederationVerifier",
    ),
    (
        "mandate.federation.ProvisionExternalPrincipal",
        "mandate_federation::FederationVerifier",
    ),
    (
        "mandate.federation.AuthorizePublicClient",
        "mandate_federation::publicclient::OAuthClientStore",
    ),
    (
        "mandate.federation.DisableFederationConnection",
        "mandate_federation::ConnectionStore",
    ),
    (
        "mandate.federation.UnlinkExternalPrincipal",
        "mandate_federation::ExternalPrincipalStore",
    ),
    (
        "mandate.federation.DisableOAuthClient",
        "mandate_federation::publicclient::OAuthClientStore",
    ),
    (
        "mandate.federation.RegisterOAuthClient",
        "mandate_federation::register_client::ClientRegistrationAdmission",
    ),
    (
        "mandate.credential.RegisterResourceServer",
        "mandate_sts::registry::ResourceServerReads",
    ),
    (
        "mandate.credential.DisableResourceServer",
        "mandate_sts::registry::ResourceServerReads",
    ),
    (
        "mandate.credential.IssueReferenceCredential",
        "mandate_sts::registry::ResourceServerReads",
    ),
    (
        "mandate.credential.IssueSelfContainedCredential",
        "mandate_sts::registry::ResourceServerReads",
    ),
    (
        "mandate.credential.IntrospectCredential",
        "mandate_sts::resolve::CredentialResolution",
    ),
    (
        "mandate.credential.RevokeAccessCredential",
        "mandate_sts::resolve::CredentialReads",
    ),
    (
        "mandate.credential.RegisterSigningKey",
        "mandate_sts::keys::KeyMaterialResolver",
    ),
    (
        "mandate.credential.RetireSigningKey",
        "mandate_sts::keys::SigningKeyReads",
    ),
    (
        "mandate.credential.RevokeSigningKey",
        "mandate_sts::keys::SigningKeyReads",
    ),
    (
        "mandate.credential.IssueAuthorizationCode",
        "mandate_sts::registry::ResourceServerReads",
    ),
    (
        "mandate.credential.RedeemAuthorizationCode",
        "mandate_sts::registry::ResourceServerReads",
    ),
    ("mandate.identity.RevokeSession", NOT_SUBSTITUTABLE),
    (
        "mandate.identity.RefreshSession",
        "mandate_identity::IdentityRead",
    ),
    (
        "mandate.identity.IncrementSecurityEpoch",
        "mandate_identity::SecurityEpochWrite",
    ),
    (
        "mandate.authorization.Check",
        "mandate_graph::port::GraphRead",
    ),
    ("mandate.graph.RegisterResource", NO_PORT),
    ("mandate.graph.DeregisterResource", NO_PORT),
    ("mandate.tenancy.CreateOrganization", NO_PORT),
    ("mandate.tenancy.CloseOrganization", NO_PORT),
    ("mandate.tenancy.CreateTeam", NO_PORT),
    ("mandate.tenancy.RetireTeam", NO_PORT),
    ("mandate.tenancy.CreateSpace", NO_PORT),
    ("mandate.tenancy.RetireSpace", NO_PORT),
    ("mandate.tenancy.AddOrganizationMembership", NO_PORT),
    ("mandate.tenancy.RemoveOrganizationMembership", NO_PORT),
    ("mandate.tenancy.AddTeamMembership", NO_PORT),
    ("mandate.tenancy.RemoveTeamMembership", NO_PORT),
];

/// What a command that consults no port has instead of one.
pub const NO_PORT: &str = "none";

/// The port a command reads through a concrete type, which no caller can replace.
///
/// `mandate_identity::revoke_session` takes `&mut IdentityLog` and calls `log.resolve(&id)`
/// — `IdentityRead::resolve`. The port is read; the *handler's signature* is what makes it
/// unsubstitutable, and recording `none` here would assert of this command what is true only
/// of the tenancy and graph folds.
pub const NOT_SUBSTITUTABLE: &str = "mandate_identity::IdentityRead (concrete log)";

/// The port a command's fault is placed at, when the target dispatches the command.
#[must_use]
pub fn port_of(command: &str) -> Option<&'static str> {
    PORTS
        .iter()
        .find(|(named, _)| *named == command)
        .map(|(_, port)| *port)
}

/// A read model that answers nothing, at every port this target can substitute one at.
///
/// Renamed from what it was: it is not merely "empty", it is *the reader put in the standing
/// one's place*, and what a reader of `injections.json` needs to know about it is what it
/// did — so it counts.
///
/// This is what an armed external outcome *is* for a command whose refusal comes from a
/// read: the port answers that the record is not there, the handler reads that answer and
/// decides its own declared refusal. Nothing here decides an outcome and nothing fabricates
/// a record — the alternative, a store that answered with a record built to force a
/// particular clause, would be this target writing the state the scenario is about.
///
/// For a scenario whose fold is already empty the armed read is the same answer the standing
/// fold gives, and `injections.json` records the arming either way: what was done at which
/// port is the fact, and whether it changed the answer is a property of the scenario.
#[derive(Debug)]
pub struct Substituted {
    /// How many reads this reader answered.
    consulted: Cell<u32>,
    /// How many of those answers were a refusal rather than an absence.
    ///
    /// Only two ports can be given one: `admits_audience` and `increment`, whose signatures
    /// carry no "it holds nothing" value. Every other read here answers absence, which is
    /// what an empty standing fold answers too — so a reader that never refused cannot have
    /// changed the scenario, and the row says `armed-standing`.
    refused: Cell<u32>,
}

impl Substituted {
    /// A reader that has answered nothing yet.
    #[must_use]
    pub fn new() -> Self {
        Self {
            consulted: Cell::new(0),
            refused: Cell::new(0),
        }
    }

    /// How many reads it answered.
    #[must_use]
    pub fn consulted(&self) -> u32 {
        self.consulted.get()
    }

    /// How many of those were refusals the standing reader could not have given.
    #[must_use]
    pub fn refused(&self) -> u32 {
        self.refused.get()
    }

    /// Count one read.
    fn read(&self) {
        self.consulted.set(self.consulted.get().saturating_add(1));
    }

    /// Count one read whose answer is a refusal.
    fn refuse(&self) {
        self.read();
        self.refused.set(self.refused.get().saturating_add(1));
    }
}

impl Default for Substituted {
    fn default() -> Self {
        Self::new()
    }
}

impl mandate_federation::ConnectionStore for Substituted {
    fn connection(
        &self,
        _id: &mandate_types::FederationConnectionId,
    ) -> Option<FederationConnection> {
        self.read();
        None
    }

    fn enabled_for_issuer(&self, _issuer: &Issuer) -> Vec<FederationConnection> {
        self.read();
        Vec::new()
    }
}

impl mandate_federation::LinkStore for Substituted {
    fn records_on_key(
        &self,
        _key: &mandate_federation::record::ExternalKey,
    ) -> Vec<mandate_federation::record::ExternalPrincipal> {
        self.read();
        Vec::new()
    }
}

impl mandate_federation::ExternalPrincipalStore for Substituted {
    fn external_principal(
        &self,
        _id: &mandate_types::ExternalPrincipalId,
    ) -> Option<mandate_federation::record::ExternalPrincipal> {
        self.read();
        None
    }
}

impl mandate_federation::PrincipalStore for Substituted {
    fn organization_of(
        &self,
        _principal_id: &mandate_types::PrincipalId,
    ) -> Option<mandate_types::OrganizationId> {
        self.read();
        None
    }
}

impl mandate_federation::publicclient::OAuthClientStore for Substituted {
    fn client(
        &self,
        _id: &mandate_types::OAuthClientId,
    ) -> Option<mandate_federation::record::OAuthClient> {
        self.read();
        None
    }
}

impl mandate_identity::IdentityRead for Substituted {
    fn resolve(&self, _id: &mandate_types::SessionId) -> Option<mandate_identity::Session> {
        self.read();
        None
    }

    fn principal(&self, _id: &mandate_types::PrincipalId) -> Option<mandate_identity::Principal> {
        self.read();
        None
    }

    fn current(
        &self,
        _target: &mandate_types::SecurityEpochTarget,
    ) -> mandate_identity::EpochState {
        self.read();
        mandate_identity::EpochState::new(
            mandate_identity::Generation::ZERO,
            mandate_identity::StreamVersion::INITIAL,
        )
    }

    fn snapshot(
        &self,
        _id: &mandate_types::EpochSnapshotRef,
    ) -> Option<mandate_identity::SecurityEpochSnapshot> {
        self.read();
        None
    }

    /// The instant the run is evaluated at, which the standing log also answers.
    ///
    /// Not a record and not a thing a reader can hold nothing of: `IdentityRead::as_of` is
    /// the host's clock reaching the fold, and this target's clock is
    /// [`crate::FIXED_INSTANT`] for every reader it builds. Leaving it defaulted to `None`
    /// made `refresh_session` fail closed with `Unavailable` — "the reader has no clock" —
    /// which is a clause the standing log never reaches and an answer about the *run* that
    /// the arming has no business changing. A fault at this port belongs in the reads above,
    /// not in whether the target owns a clock.
    fn as_of(&self) -> Option<mandate_types::Timestamp> {
        self.read();
        Some(mandate_types::Timestamp::new(crate::FIXED_INSTANT))
    }
}

impl mandate_identity::SecurityEpochWrite for Substituted {
    /// The compare-and-set a write port that holds no stream can honestly report: the
    /// stream is not the one that was read, which is the declared refusal
    /// `mandate_identity::SecurityEpochWrite::increment` documents for a moved stream.
    fn increment(
        &mut self,
        _context: &mandate_types::VerifiedContext,
        _target: &mandate_types::SecurityEpochTarget,
        _expected: mandate_identity::StreamVersion,
    ) -> Result<mandate_identity::EpochState, mandate_identity::Denial> {
        self.refuse();
        Err(mandate_identity::Denial::new(DenialReason::Unavailable))
    }
}

impl mandate_sts::registry::ResourceServerReads for Substituted {
    fn resource_server(
        &self,
        _id: &mandate_types::ResourceServerId,
    ) -> Option<mandate_token::projection::ResourceServer> {
        self.read();
        None
    }

    fn registered(
        &self,
        _organization_id: &mandate_types::OrganizationId,
        _audience: &mandate_types::Audience,
    ) -> Option<mandate_token::projection::ResourceServer> {
        self.read();
        None
    }

    /// The one read of this port that answers a `Result`, and the one an armed outcome can
    /// place a fault at: the store says this organization does not admit the audience,
    /// which is the same answer the real fold gives for an audience another registration
    /// already holds (`AudienceAmbiguous`). A reader that admitted everything would make
    /// `RegisterResourceServer`'s armed denial impossible to express at a port at all.
    fn admits_audience(
        &self,
        _organization_id: &mandate_types::OrganizationId,
        _audience: &mandate_types::Audience,
    ) -> Result<(), mandate_token::projection::Denied> {
        self.refuse();
        Err(mandate_token::projection::Denied::new(
            DenialReason::Denied,
            mandate_token::projection::DenialClause::AudienceAmbiguous,
        ))
    }
}

impl mandate_sts::resolve::CredentialReads for Substituted {
    fn access_credential(
        &self,
        _id: &mandate_types::CredentialId,
    ) -> Option<mandate_token::projection::AccessCredential> {
        self.read();
        None
    }
}

impl mandate_sts::resolve::CredentialResolution for Substituted {
    /// `Ok(None)` and **not** `Err(ResolutionUnavailable)`, which is the correction the
    /// adversary's second finding forced.
    ///
    /// This signature can express absence, so a reader that holds nothing says so. An
    /// earlier version answered unavailability here, and that made the arming look
    /// effective at a port where it was not: the standing fold answers `Ok(None)` for the
    /// same read, so the substitution changed nothing and the row now says so.
    /// Manufacturing a refusal where the signature can express absence is the same defect
    /// as manufacturing an expectation — the target choosing the answer rather than
    /// reporting one.
    fn resolve(
        &self,
        _verifier: &mandate_types::CredentialVerifier,
    ) -> Result<
        Option<mandate_token::projection::AccessCredential>,
        mandate_sts::resolve::ResolutionUnavailable,
    > {
        self.read();
        Ok(None)
    }
}

impl mandate_sts::keys::SigningKeyReads for Substituted {
    fn signing_key(
        &self,
        _id: &mandate_types::SigningKeyId,
    ) -> Option<mandate_token::projection::SigningKey> {
        self.read();
        None
    }

    fn signing_keys(&self) -> Vec<mandate_token::projection::SigningKey> {
        self.read();
        Vec::new()
    }

    fn holds_its_key_material(&self, _id: &mandate_types::SigningKeyId) -> bool {
        self.read();
        false
    }
}

impl mandate_federation::register_client::ClientRegistrationAdmission for Substituted {
    /// The same three answers `ConfiguredAdmission::new()` gives — it admits nothing by
    /// construction — so an arming at this port is recorded `armed-standing` unless a
    /// scenario configured an admission first.
    fn admits_client_administration(&self, _context: &mandate_types::VerifiedContext) -> bool {
        self.read();
        false
    }

    fn admits_organization(&self, _organization_id: &mandate_types::OrganizationId) -> bool {
        self.read();
        false
    }

    fn admits_redirect_uri(
        &self,
        _organization_id: &mandate_types::OrganizationId,
        _uri: &mandate_types::RedirectUri,
    ) -> bool {
        self.read();
        false
    }
}

impl mandate_graph::port::GraphRead for Substituted {
    type Revision = mandate_types::AuthzRevision;

    /// The answer an empty `GraphDouble` gives: no such authority, decided.
    ///
    /// This read used to answer `CouldNotAnswer(ResourceUnresolved)`, and the adversary's
    /// pass-2 case is right that it was wrong. `GraphDouble::new()` opens at revision `0`,
    /// so the `AuthzRevision("0")` floor `crate::commands::authz` states passes
    /// `require_revision`, and the double then refuses at `admits` with
    /// `GraphError::Denied(DenialReason::Denied)` — *a decision against the caller*, which
    /// is what a store holding no membership for a subject honestly decides.
    /// `CouldNotAnswer` says something else entirely: that the reader could not answer at
    /// all, an outage, which `GraphError::denial_reason` maps to `Unavailable`. A
    /// substituted reader that reported an outage it is not having would be manufacturing
    /// the fault rather than holding nothing, and the declared reason a scenario saw would
    /// be one no standing run produces.
    ///
    /// Not counted as a refusal, for the same reason: `refused` marks an answer that
    /// manufactures a declared denial where the signature could have expressed absence, and
    /// this is the absence — the empty store's own decision, identical to the standing
    /// double's.
    fn check(
        &self,
        _query: &mandate_graph::port::GraphQuery<'_>,
        _minimum: &Self::Revision,
    ) -> Result<mandate_graph::port::Observed, mandate_graph::port::GraphError> {
        self.read();
        Err(mandate_graph::port::GraphError::Denied(
            DenialReason::Denied,
        ))
    }
}

impl mandate_graph::topology::ResourceLookup for Substituted {
    fn placement(
        &self,
        _organization: &mandate_types::OrganizationId,
        _resource: &mandate_types::ResourceRef,
    ) -> Result<mandate_graph::topology::Placement, mandate_graph::port::GraphError> {
        self.read();
        Err(mandate_graph::port::GraphError::CouldNotAnswer(
            mandate_graph::port::Unanswered::ResourceUnresolved,
        ))
    }
}

impl mandate_sts::keys::KeyMaterialResolver for Substituted {
    /// Absence, and that **is** the arming at this port.
    ///
    /// `services/sts/src/keys.rs:204` turns a `None` here into the declared
    /// `KeyReferenceUnresolvable` clause, which is the only answer a resolver that cannot
    /// reach the deployment's key material can give — the signature carries no other. Unlike
    /// every other absence on this type, it is **not** what the standing reader answers:
    /// [`ScenarioKeys`] resolves every reference. The divergence is the injection, and the
    /// row for `mandate.credential.RegisterSigningKey` is what records it.
    fn thumbprint(&self, _reference: &mandate_types::KeyReference) -> Option<String> {
        self.read();
        None
    }
}

/// The key-material resolver a scenario is answered through.
///
/// A deployment loads the public half of a key reference and computes its RFC 7638
/// thumbprint; nothing on this target's dependency line holds key material. This answers a
/// thumbprint derived from the reference's own text, so a registration is decided against a
/// value that is stable, distinct per reference, and honestly not a thumbprint of anything
/// — which `injections.json` says. It computes no key and validates none.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScenarioKeys;

impl mandate_sts::keys::KeyMaterialResolver for ScenarioKeys {
    fn thumbprint(&self, reference: &mandate_types::KeyReference) -> Option<String> {
        let mut rendered = String::with_capacity(reference.as_str().len() * 2);
        for byte in reference.as_str().bytes() {
            rendered.push_str(&format!("{byte:02x}"));
        }
        Some(rendered)
    }
}

/// The outcome armed for the next invocation of one command.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Armed(Option<String>);

impl Armed {
    /// Arm the next invocation of `command`.
    pub fn arm(&mut self, command: &str) {
        self.0 = Some(command.to_owned());
    }

    /// Whether `command` is armed, consuming the arming: §12 says it applies to the **next**
    /// invocation and then lapses.
    pub fn take(&mut self, command: &str) -> bool {
        if self.0.as_deref() == Some(command) {
            self.0 = None;
            return true;
        }
        false
    }
}

/// The verifier the scenarios are answered through.
///
/// Step 3 of the resolution order is a signature check no crate in this target's ceiling
/// performs, and `mandate_federation::verifier::ConstructedVerifier` answers one fixed
/// result for every proof — which would deny every authored scenario for the wrong reason.
/// This reads the claims out of the proof's own payload segment and reports **those** as
/// what it validated, so an authored proof is answered with what its author wrote. It
/// verifies no signature and says so in `injections.json`: nothing here is evidence that a
/// proof was genuine.
#[derive(Debug, Default)]
pub struct ScenarioVerifier {
    /// Whether the next verification is the armed refusal.
    refusing: bool,
    /// How many proofs this verifier was asked about.
    consulted: Cell<u32>,
}

impl ScenarioVerifier {
    /// A verifier that reads what a proof claims.
    #[must_use]
    pub fn reading() -> Self {
        Self {
            refusing: false,
            consulted: Cell::new(0),
        }
    }

    /// A verifier that refuses the proof, as the armed external outcome at this port.
    #[must_use]
    pub fn refusing() -> Self {
        Self {
            refusing: true,
            consulted: Cell::new(0),
        }
    }

    /// How many proofs it was asked about.
    #[must_use]
    pub fn consulted(&self) -> u32 {
        self.consulted.get()
    }

    /// How many of those answers were a refusal the reading verifier could not have given.
    ///
    /// `FederationVerifier::verify` returns `Result<VerifiedProof, Denied>` and has no
    /// "holds nothing" value, so the armed answer at this port is the refusal or it is
    /// nothing — and a verifier that was never asked refused nothing, whatever it was armed
    /// to do.
    #[must_use]
    pub fn refused(&self) -> u32 {
        if self.refusing {
            self.consulted.get()
        } else {
            0
        }
    }
}

impl FederationVerifier for ScenarioVerifier {
    fn verify(
        &self,
        _connection: &FederationConnection,
        proof: &CredentialProof,
    ) -> Result<VerifiedProof, Denied> {
        self.consulted.set(self.consulted.get().saturating_add(1));
        if self.refusing {
            return Err(Denied::new(
                DenialReason::InvalidCredential,
                DenialClause::ProofInvalid,
            ));
        }
        let refused = || Denied::new(DenialReason::InvalidCredential, DenialClause::ProofInvalid);
        let text = std::str::from_utf8(proof.expose_bytes()).map_err(|_| refused())?;
        let claims = claims(text).ok_or_else(refused)?;
        let issuer = claims.get("iss").ok_or_else(refused)?;
        let subject = claims.get("sub").ok_or_else(refused)?;
        let audience = claims.get("aud").ok_or_else(refused)?;
        let mut verified = VerifiedProof::new(
            Issuer::new(issuer.clone()),
            ExternalSubject::new(subject.clone()),
            ClientId::new(audience.clone()),
        );
        for (name, value) in &claims {
            if !matches!(name.as_str(), "iss" | "sub" | "aud") {
                verified = verified.with_verified_claim(name, value);
            }
        }
        Ok(verified)
    }
}

/// The string claims of a compact JWS's payload segment, read without verifying anything.
fn claims(proof: &str) -> Option<BTreeMap<String, String>> {
    let mut segments = proof.split('.');
    let _header = segments.next()?;
    let payload = segments.next()?;
    segments.next()?;
    let decoded = base64url(payload)?;
    let document: serde_json::Value = serde_json::from_slice(&decoded).ok()?;
    let fields = document.as_object()?;
    Some(
        fields
            .iter()
            .filter_map(|(name, value)| value.as_str().map(|text| (name.clone(), text.to_owned())))
            .collect(),
    )
}

/// One unpadded base64url segment, decoded.
///
/// Written here rather than taken from a crate because this target's dependency ceiling
/// admits no encoder, and the alphabet is six lines.
fn base64url(text: &str) -> Option<Vec<u8>> {
    let mut bytes = Vec::with_capacity(text.len() * 3 / 4);
    let mut accumulator: u32 = 0;
    let mut bits = 0_u32;
    for character in text.bytes() {
        let value = match character {
            b'A'..=b'Z' => u32::from(character - b'A'),
            b'a'..=b'z' => u32::from(character - b'a') + 26,
            b'0'..=b'9' => u32::from(character - b'0') + 52,
            b'-' => 62,
            b'_' => 63,
            b'=' => break,
            _ => return None,
        };
        accumulator = (accumulator << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            let byte = u8::try_from((accumulator >> bits) & 0xff).ok()?;
            bytes.push(byte);
        }
    }
    Some(bytes)
}

#[cfg(test)]
mod tests {
    use super::{Armed, Ledger, NO_PORT, PORTS, ScenarioVerifier, port_of};
    use mandate_federation::FederationVerifier;
    use mandate_federation::record::{ConnectionState, FederationConnection};
    use mandate_model::TenantResolutionRule;
    use mandate_types::{
        Audience, ClientId, CredentialProof, FederationConnectionId, Issuer, OrganizationId, Uuid,
    };

    /// An arming applies to the next invocation of its command and then lapses (§12).
    #[test]
    fn an_arming_applies_once_to_the_command_it_named() {
        let mut armed = Armed::default();
        armed.arm("mandate.tenancy.CreateTeam");
        assert!(!armed.take("mandate.tenancy.CreateSpace"));
        assert!(armed.take("mandate.tenancy.CreateTeam"));
        assert!(
            !armed.take("mandate.tenancy.CreateTeam"),
            "the arming outlived the invocation it applied to"
        );
    }

    /// The ledger records one block per scenario and sorts for a byte comparison.
    #[test]
    fn the_ledger_records_one_block_per_scenario_in_canonical_order() {
        let mut ledger = Ledger::opened();
        ledger.block("b", "cmd", "unrealized-command", "story:one");
        ledger.block("b", "cmd", "unrealized-command", "story:two");
        ledger.block("a", "cmd", "unrealized-command", "story:three");
        let ledger = ledger.sorted();
        assert_eq!(ledger.blocked.len(), 2, "a scenario was recorded twice");
        assert_eq!(ledger.blocked[0].scenario, "a");
        assert_eq!(ledger.blocked[0].blocked_on, "story:three");
        assert_eq!(ledger.blocked[1].blocked_on, "story:one");
        assert!(!ledger.standing_doubles.is_empty());
    }

    /// The port table answers for every command it names, and the tenancy and graph
    /// registrations are the ones with no port to answer at.
    #[test]
    fn the_port_table_names_a_port_or_says_there_is_none() {
        assert_eq!(port_of("mandate.tenancy.CreateTeam"), Some(NO_PORT));
        assert_eq!(
            port_of("mandate.federation.AuthenticateFederation"),
            Some("mandate_federation::FederationVerifier")
        );
        assert_eq!(port_of("mandate.credential.ExchangeCredential"), None);
        let mut names: Vec<&str> = PORTS.iter().map(|(command, _)| *command).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(
            names.len(),
            PORTS.len(),
            "the port table names a command twice"
        );
    }

    /// The verifier reports what the proof claims, and the armed one refuses.
    ///
    /// The refusal half is what makes the arming at this port real: a verifier that
    /// answered the same thing armed and unarmed would make every injection a no-op.
    #[test]
    fn the_verifier_reads_the_claims_and_the_armed_one_refuses() {
        let connection = FederationConnection {
            id: FederationConnectionId::new(Uuid::from_bytes([1; 16])),
            organization_id: OrganizationId::new(Uuid::from_bytes([2; 16])),
            issuer: Issuer::new("https://issuer.example".to_owned()),
            client_id: ClientId::new("client".to_owned()),
            tenant_resolution: TenantResolutionRule {
                configured_organization: OrganizationId::new(Uuid::from_bytes([2; 16])),
                verified_claim_name: None,
                verified_claim_value: None,
            },
            jit_provisioning: false,
            state: ConnectionState::Enabled,
        };
        // {"iss":"https://issuer.example","sub":"subject","aud":"client"}
        let payload =
            "eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwic3ViIjoic3ViamVjdCIsImF1ZCI6ImNsaWVudCJ9";
        let proof = CredentialProof::from_bytes(format!("e30.{payload}.signature").into_bytes());
        let verified = ScenarioVerifier::reading()
            .verify(&connection, &proof)
            .expect("a well-formed proof is read");
        assert_eq!(verified.subject().as_str(), "subject");
        assert_eq!(verified.issuer().as_str(), "https://issuer.example");
        assert!(
            ScenarioVerifier::refusing()
                .verify(&connection, &proof)
                .is_err(),
            "the armed verifier admitted a proof"
        );
        assert!(
            ScenarioVerifier::reading()
                .verify(&connection, &CredentialProof::from_bytes(b"proof".to_vec()))
                .is_err(),
            "a proof that is not a compact JWS was read as a validated one"
        );
        let _ = Audience::new("a".to_owned());
    }
}

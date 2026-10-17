//! | `GET` | `/healthz/live` | the liveness document | The probe path a container platform polls; a wire document, not a command, and outside every versioned prefix so no generated projection can collide with it. `GET` because a probe issues nothing else. |
//! | `GET` | `/healthz/ready` | the readiness document | The same, answering `503` until a signing key is admitted. |
//! The product route table, as data.
//!
//! Twelve routes: the four the customer login road needs, the three documents RFC 8414 and
//! OpenID Connect Discovery 1.0 put a client's discovery on, the three steps of the
//! relying-party flow toward an external IdP, and the two health documents a deployment's
//! probes read.
//! `story:product-listener` dispatches this table and hardcodes no
//! path, so a path that is not here is a path nothing serves.
//!
//! # The paths, and why these
//!
//! `docs/sources/original-design.md:1866` — "Endpoint layout can differ, but metadata MUST
//! accurately advertise it" — so the layout is a choice, and these are the reasons for this
//! one. The coordinator reviews and fixes them at this unit's adversary pass
//! (`story:login-adapters`, ruling 3).
//!
//! | Method | Path | Binds | Why this path |
//! |---|---|---|---|
//! | `POST` | `/v1/federation/login` | `mandate.federation.AuthenticateFederation` | A control-plane product route, not an OAuth endpoint: it mints a session from an IdP proof and issues no credential. `original-design.md:1784-1796` puts every control-plane resource under `/v1/`, and `:1871-1875` puts federation under `/v1/identity-providers`. Naming the act (`login`) rather than the connection keeps the connection out of the path, where `federation.yaml:1` says the tenant must not be selectable from. |
//! | `GET` | `/oauth/authorize` | `mandate.federation.AuthorizeClient` | `original-design.md:1857` names it verbatim. RFC 6749 section 3.1 requires `GET` at the authorization endpoint. Unversioned, like the rest of the OAuth surface. |
//! | `POST` | `/oauth/token` | `mandate.credential.RedeemAuthorizationCode`, and `mandate.credential.ExchangeCredential` by `grant_type` | `original-design.md:1858`, verbatim. RFC 6749 section 3.2 requires `POST`, and RFC 8693 section 2.1 puts token exchange at the same endpoint. The row binds the code grant's command because one route binds one command; `crate::decode::token_request` reads the `grant_type` and reaches the exchange, so the endpoint the metadata advertises is the one both grants are served at. |
//! | `POST` | `/oauth/introspect` | `mandate.credential.IntrospectCredential` | `original-design.md:1860`, verbatim ("where supported/needed" — this deployment supports it; the command is declared and realized). RFC 7662 section 2 requires `POST`. |
//! | `GET` | `/.well-known/oauth-authorization-server` | the RFC 8414 metadata document | `original-design.md:1855`, verbatim, and RFC 8414 section 3 fixes it at the host root. |
//! | `GET` | `/.well-known/openid-configuration` | the OpenID Connect Discovery 1.0 document | OpenID Connect Discovery 1.0 section 4 fixes it under the issuer, and `original-design.md:1855-1862` lists it among the STS endpoints. Built by the same builder as the RFC 8414 document (`crate::metadata::openid_configuration`), so the two cannot disagree on a shared member. |
//! | `GET` | `/oauth/jwks` | the JWKS document | `original-design.md:1862`, verbatim. |
//! | `GET` | `/v1/federation/authorize` | [`RelyingPartyStep::Authorize`] | The relying-party half of an external IdP's code flow (`story:relying-party-code-flow`): a browser is sent to the IdP from here. Beside `/v1/federation/login` for the reason that route is under `/v1/`; `GET` because a browser follows it. |
//! | `GET` | `/v1/federation/callback` | [`RelyingPartyStep::Callback`] | Where the IdP returns the browser with its code (OIDC Core 3.1.2.5 puts the response in the query of a `GET`). The code is redeemed server-side and the ID token goes through `AuthenticateFederation`. |
//! | `POST` | `/v1/federation/handoff` | [`RelyingPartyStep::Handoff`] | The embedding application exchanges the callback's single-use code for the session here, server-to-server, so the bearer session proof never rides a browser navigation. `POST` because it is not idempotent. |
//!
//! Two paths `original-design.md:1855-1862` lists are deliberately **not** here:
//! `/oauth/revoke` (`mandate.credential.RevokeAccessCredential` is off the login road and is
//! `story:protocol-adapters`'), and the `/v1/...` control-plane resources of `:1784-1796`
//! (the same story's).
//!
//! # Disjointness
//!
//! `docs/public/contracts.md:29` says the generated command routes do not implement product
//! routes. [`is_generated_command_path`] is the predicate, and
//! `crates/mandate-server/tests/routes.rs` decides both halves: no path here is shaped like a
//! generated one, and the intersection with the 63 paths read from `generated/openapi/*.yaml`
//! at test time is empty.

/// The methods this table declares.
///
/// Two, because twelve routes need two. A method a route does not declare is a route a listener
/// does not answer, which is what `crates/mandate-server/tests/routes.rs` decides.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Method {
    /// `GET`.
    Get,
    /// `POST`.
    Post,
}

impl Method {
    /// The method's wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
        }
    }
}

impl core::fmt::Display for Method {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A document this deployment publishes rather than a command it serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Document {
    /// The RFC 8414 authorization server metadata document.
    AuthorizationServerMetadata,
    /// The OpenID Connect Discovery 1.0 provider configuration document.
    OpenIdConfiguration,
    /// The JWKS document RFC 8414's `jwks_uri` names.
    Jwks,
    /// The liveness document: the process answers.
    HealthLive,
    /// The readiness document: the configuration is admitted and a signing key is held.
    HealthReady,
}

/// A step of the relying-party flow toward an external OIDC IdP.
///
/// Neither step is a command of the contract. The callback ends in
/// `mandate.federation.AuthenticateFederation`, over the ID token the IdP's token endpoint
/// answered, and `/v1/federation/login` stays that command's route; the authorize step
/// records nothing durable at all (`story:relying-party-code-flow`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RelyingPartyStep {
    /// Send the browser to the IdP's authorization endpoint.
    Authorize,
    /// Receive the IdP's code, redeem it, open a session, and send the browser on with a
    /// single-use handoff code.
    Callback,
    /// Exchange a handoff code for the session, server-to-server, once.
    Handoff,
}

/// What a route binds to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Binding {
    /// The `operationId` of the command this route reaches, decoded by
    /// `crates/mandate-server/src/decode.rs`.
    Command(&'static str),
    /// A document built by `crates/mandate-server/src/metadata.rs`.
    Document(Document),
    /// A step of the relying-party flow, decoded by `crates/mandate-server/src/decode.rs`.
    RelyingParty(RelyingPartyStep),
}

/// One product route.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Route {
    /// The method this route answers, and the only one.
    pub method: Method,
    /// The path this route answers, exactly.
    pub path: &'static str,
    /// What it binds.
    pub binds: Binding,
}

/// The product route table. The whole served surface of the login road.
pub const ROUTES: &[Route] = &[
    Route {
        method: Method::Post,
        path: "/v1/federation/login",
        binds: Binding::Command("mandate.federation.AuthenticateFederation"),
    },
    Route {
        method: Method::Get,
        path: "/oauth/authorize",
        binds: Binding::Command("mandate.federation.AuthorizeClient"),
    },
    Route {
        method: Method::Post,
        path: "/oauth/token",
        binds: Binding::Command("mandate.credential.RedeemAuthorizationCode"),
    },
    Route {
        method: Method::Post,
        path: "/oauth/introspect",
        binds: Binding::Command("mandate.credential.IntrospectCredential"),
    },
    Route {
        method: Method::Get,
        path: "/.well-known/oauth-authorization-server",
        binds: Binding::Document(Document::AuthorizationServerMetadata),
    },
    Route {
        method: Method::Get,
        path: "/.well-known/openid-configuration",
        binds: Binding::Document(Document::OpenIdConfiguration),
    },
    Route {
        method: Method::Get,
        path: "/oauth/jwks",
        binds: Binding::Document(Document::Jwks),
    },
    Route {
        method: Method::Get,
        path: "/healthz/live",
        binds: Binding::Document(Document::HealthLive),
    },
    Route {
        method: Method::Get,
        path: "/healthz/ready",
        binds: Binding::Document(Document::HealthReady),
    },
    Route {
        method: Method::Get,
        path: "/v1/federation/authorize",
        binds: Binding::RelyingParty(RelyingPartyStep::Authorize),
    },
    Route {
        method: Method::Get,
        path: "/v1/federation/callback",
        binds: Binding::RelyingParty(RelyingPartyStep::Callback),
    },
    Route {
        method: Method::Post,
        path: "/v1/federation/handoff",
        binds: Binding::RelyingParty(RelyingPartyStep::Handoff),
    },
];

/// The segment that makes a path a generated command route.
pub const GENERATED_COMMAND_SEGMENT: &str = "commands";

/// The route this method and path reach, or `None` when nothing does.
#[must_use]
pub fn lookup(method: Method, path: &str) -> Option<&'static Route> {
    ROUTES
        .iter()
        .find(|route| route.method == method && route.path == path)
}

/// The route that reaches this command, or `None` when this table declares none.
#[must_use]
pub fn route_for_command(command: &str) -> Option<&'static Route> {
    ROUTES
        .iter()
        .find(|route| matches!(route.binds, Binding::Command(declared) if declared == command))
}

/// The route this document is published at.
#[must_use]
pub fn route_for_document(document: Document) -> Option<&'static Route> {
    ROUTES
        .iter()
        .find(|route| route.binds == Binding::Document(document))
}

/// Whether a path is one of the generated `/<domain>/commands/<Command>` projections.
///
/// The shape, not a list: exactly three non-empty segments whose middle one is
/// [`GENERATED_COMMAND_SEGMENT`]. A list would answer for the 63 that exist and not for the
/// 64th. `crates/mandate-server/tests/routes.rs` decides this predicate against every path the
/// four generated documents publish today.
#[must_use]
pub fn is_generated_command_path(path: &str) -> bool {
    let mut segments = path.split('/');
    segments.next() == Some("")
        && segments.next().is_some_and(|domain| !domain.is_empty())
        && segments.next() == Some(GENERATED_COMMAND_SEGMENT)
        && segments.next().is_some_and(|command| !command.is_empty())
        && segments.next().is_none()
}

//! The RFC 8414 authorization server metadata document, the OpenID Connect Discovery 1.0
//! provider configuration and the JWK Set document, as shapes.
//!
//! All three are built here and served nowhere: `story:product-listener` publishes them at the
//! routes [`crate::routes::ROUTES`] declares for them. The JWKS carries **no key material** —
//! [`Jwks::empty`] is what this crate can honestly produce, and the composition fills the list
//! from the signing keys the STS holds.
//!
//! # The endpoints are read, not restated
//!
//! Every URL in the metadata is `issuer` joined with a path taken from the route table at call
//! time. `docs/sources/original-design.md:1866` requires that "metadata MUST accurately
//! advertise" the endpoint layout; reading the layout from the same table the listener
//! dispatches is what makes that a property rather than a promise, and
//! `crates/mandate-server/tests/metadata.rs` decides it route by route.
//!
//! # What is advertised is what is enforced
//!
//! `code_challenge_methods_supported` is `["S256"]` because `mandate.core.PkceMethod` declares
//! exactly one variant and `crate::decode::authorize_client` refuses every other
//! `code_challenge_method`. `token_endpoint_auth_methods_supported` is
//! [`TOKEN_ENDPOINT_AUTH_METHODS`] because `crate::decode::redeem_authorization_code` reads a
//! secret from `Authorization: Basic` or from the `client_secret` parameter, and a public
//! client presents neither (RFC 6749 section 2.3.1); the STS decides which the client the code
//! is bound to must present. `response_types_supported` is the single value
//! the authorization decoder admits, and `grant_types_supported` is
//! `crate::decode::TOKEN_GRANTS`, the list `crate::decode::token_request` dispatches on — the
//! authorization code and RFC 8693 token exchange. A metadata document
//! advertising a method no decoder admits is a document that lies to every client that reads
//! it, which is the failure RFC 8414 exists to prevent.
//!
//! The discovery document's own four members run ahead of the runtime in two places, and are
//! held here so the runtime catches up to them rather than the reverse:
//! `scopes_supported` lists the OpenID Connect scopes `story:oidc-discovery-and-code-flow`'s
//! authorization half teaches the authorization decoder, and `claims_supported` and
//! `id_token_signing_alg_values_supported` describe the ID token
//! `story:oidc-signed-tokens-and-key-rotation` issues.

use mandate_proto::oauth::{self, Member};

use crate::routes::{self, Document};

/// RFC 8414 section 2: the authorization server metadata document.
///
/// The nine members this deployment can state truthfully, and no more. A member that names an
/// endpoint this deployment does not serve (`revocation_endpoint`, `registration_endpoint`,
/// `device_authorization_endpoint`) is absent rather than empty.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationServerMetadata {
    /// The issuer identifier this deployment is known by.
    pub issuer: String,
    /// The authorization endpoint, from the route table.
    pub authorization_endpoint: String,
    /// The token endpoint, from the route table.
    pub token_endpoint: String,
    /// The introspection endpoint (RFC 7662 section 2), from the route table.
    pub introspection_endpoint: String,
    /// The JWK Set document's URL, from the route table.
    pub jwks_uri: String,
    /// The response types the authorization endpoint admits.
    pub response_types_supported: Vec<String>,
    /// The grant types the token endpoint admits.
    pub grant_types_supported: Vec<String>,
    /// The PKCE challenge methods the authorization endpoint admits.
    pub code_challenge_methods_supported: Vec<String>,
    /// The client authentication methods the token endpoint admits.
    pub token_endpoint_auth_methods_supported: Vec<String>,
}

impl AuthorizationServerMetadata {
    /// The declared JSON rendering, with the members in sorted order.
    #[must_use]
    pub fn to_json(&self) -> String {
        oauth::object(&self.members())
    }

    /// The nine members, named as RFC 8414 section 2 names them.
    fn members(&self) -> Vec<(&'static str, Member)> {
        vec![
            ("issuer", Member::Text(self.issuer.clone())),
            (
                "authorization_endpoint",
                Member::Text(self.authorization_endpoint.clone()),
            ),
            ("token_endpoint", Member::Text(self.token_endpoint.clone())),
            (
                "introspection_endpoint",
                Member::Text(self.introspection_endpoint.clone()),
            ),
            ("jwks_uri", Member::Text(self.jwks_uri.clone())),
            (
                "response_types_supported",
                Member::List(self.response_types_supported.clone()),
            ),
            (
                "grant_types_supported",
                Member::List(self.grant_types_supported.clone()),
            ),
            (
                "code_challenge_methods_supported",
                Member::List(self.code_challenge_methods_supported.clone()),
            ),
            (
                "token_endpoint_auth_methods_supported",
                Member::List(self.token_endpoint_auth_methods_supported.clone()),
            ),
        ]
    }
}

/// OpenID Connect Discovery 1.0 section 3: the OpenID Provider configuration document.
///
/// The RFC 8414 document's nine members, held as that document and not restated, plus the
/// four OpenID Connect adds. The shared members come from [`authorization_server_metadata`],
/// the one builder both documents are made by, so the two published documents cannot
/// disagree on any of them.
///
/// `userinfo_endpoint` and `end_session_endpoint` are absent because no route serves them
/// (both are optional in section 3); the endpoint that serves one adds it here from the route
/// table, as every URL in this document is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenIdConfiguration {
    /// The members this document shares with the RFC 8414 document, with their values.
    pub authorization_server: AuthorizationServerMetadata,
    /// The subject identifier types: `public`, one `sub` per user for every client.
    pub subject_types_supported: Vec<String>,
    /// The algorithms an ID token is signed under. RS256 is mandatory to implement
    /// (OpenID Connect Core 15.1).
    pub id_token_signing_alg_values_supported: Vec<String>,
    /// The OpenID Connect scopes the authorization endpoint admits.
    pub scopes_supported: Vec<String>,
    /// The claims an ID token can carry.
    pub claims_supported: Vec<String>,
}

impl OpenIdConfiguration {
    /// The issuer identifier, byte-equal to the configured issuer without a trailing `/`.
    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.authorization_server.issuer
    }

    /// The declared JSON rendering, with the members in sorted order.
    #[must_use]
    pub fn to_json(&self) -> String {
        let mut members = self.authorization_server.members();
        members.extend([
            (
                "subject_types_supported",
                Member::List(self.subject_types_supported.clone()),
            ),
            (
                "id_token_signing_alg_values_supported",
                Member::List(self.id_token_signing_alg_values_supported.clone()),
            ),
            (
                "scopes_supported",
                Member::List(self.scopes_supported.clone()),
            ),
            (
                "claims_supported",
                Member::List(self.claims_supported.clone()),
            ),
        ]);
        oauth::object(&members)
    }
}

/// The OpenID Connect scopes, as their wire values: the variants of
/// `mandate.credential.IdentityScope` (`systems/mandate/domains/credential.yaml:18-27`).
pub const IDENTITY_SCOPES: [&str; 5] = ["openid", "email", "profile", "groups", "offline_access"];

/// The claims an ID token can carry: OpenID Connect Core 2 and 3.1.3.6, and the profile
/// claims `story:oidc-signed-tokens-and-key-rotation` names.
pub const IDENTITY_CLAIMS: [&str; 13] = [
    "iss",
    "sub",
    "aud",
    "exp",
    "iat",
    "auth_time",
    "nonce",
    "at_hash",
    "azp",
    "email",
    "email_verified",
    "name",
    "groups",
];

/// The ID-token signing algorithms advertised. RS256 is the default (fork F8).
pub const ID_TOKEN_SIGNING_ALGORITHMS: [&str; 1] = ["RS256"];

/// The token-endpoint client authentication methods advertised, in both documents: a
/// confidential client's two RFC 6749 section 2.3.1 presentations, and `none` for a public
/// client.
pub const TOKEN_ENDPOINT_AUTH_METHODS: [&str; 3] =
    ["client_secret_basic", "client_secret_post", "none"];

/// Build the OpenID Provider configuration document for an issuer.
///
/// # Panics
///
/// As [`authorization_server_metadata`], whose values this document carries.
#[must_use]
pub fn openid_configuration(issuer: &str) -> OpenIdConfiguration {
    let owned = |values: &[&str]| values.iter().map(|value| (*value).to_owned()).collect();
    OpenIdConfiguration {
        authorization_server: authorization_server_metadata(issuer),
        subject_types_supported: owned(&["public"]),
        id_token_signing_alg_values_supported: owned(&ID_TOKEN_SIGNING_ALGORITHMS),
        scopes_supported: owned(&IDENTITY_SCOPES),
        claims_supported: owned(&IDENTITY_CLAIMS),
    }
}

/// Build the metadata document for an issuer, from the route table.
///
/// # Panics
///
/// Panics when [`crate::routes::ROUTES`] declares no route for a command or document this
/// document must advertise. That is a table this crate owns and a test decides, not an input:
/// a deployment cannot reach this by configuration.
#[must_use]
pub fn authorization_server_metadata(issuer: &str) -> AuthorizationServerMetadata {
    let issuer = issuer.trim_end_matches('/').to_owned();
    AuthorizationServerMetadata {
        authorization_endpoint: endpoint(&issuer, "mandate.federation.AuthorizeClient"),
        token_endpoint: endpoint(&issuer, "mandate.credential.RedeemAuthorizationCode"),
        introspection_endpoint: endpoint(&issuer, "mandate.credential.IntrospectCredential"),
        jwks_uri: format!(
            "{issuer}{}",
            routes::route_for_document(Document::Jwks)
                .expect("the route table publishes the JWKS document")
                .path
        ),
        issuer,
        response_types_supported: vec![crate::decode::CODE_RESPONSE_TYPE.to_owned()],
        grant_types_supported: crate::decode::TOKEN_GRANTS
            .iter()
            .map(|grant| (*grant).to_owned())
            .collect(),
        code_challenge_methods_supported: vec![mandate_proto::oauth::S256_METHOD.to_owned()],
        token_endpoint_auth_methods_supported: TOKEN_ENDPOINT_AUTH_METHODS
            .iter()
            .map(|method| (*method).to_owned())
            .collect(),
    }
}

/// The issuer joined with the route table's path for a command.
fn endpoint(issuer: &str, command: &str) -> String {
    let path = routes::route_for_command(command)
        .expect("the route table serves every command the metadata advertises")
        .path;
    format!("{issuer}{path}")
}

/// Why a [`Jwk`], or a [`Jwks`] of them, was not carried.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum JwkRefusal {
    /// A parameter name is outside [`Jwk::ADMITTED_PARAMETERS`].
    ///
    /// Every RFC 7517 section 9.2 private member — `d`, `p`, `q`, `dp`, `dq`, `qi`, `k` — is
    /// outside it, which is the point.
    UndeclaredParameter,
    /// A parameter name collides with one of [`Jwk::DECLARED_MEMBERS`].
    DeclaredMemberCollision,
    /// A parameter name was given twice.
    DuplicateParameter,
    /// Two keys of one set carry the same `kid`.
    ///
    /// RFC 7517 section 4.5 is what a reader resolves a signature's key with, so a set naming
    /// one `kid` twice is a set in which that resolution is undefined. Refused at
    /// [`Jwks::new`] rather than resolved, for the reason every other repeat on this road is
    /// ([`crate::decode`], rule 4): whichever of the two a reader picks, another reader picks
    /// the other.
    RepeatedKeyId,
}

impl core::fmt::Display for JwkRefusal {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::UndeclaredParameter => "a JWK parameter is not an admitted public member",
            Self::DeclaredMemberCollision => "a JWK parameter collides with a declared member",
            Self::DuplicateParameter => "a JWK parameter name was given twice",
            Self::RepeatedKeyId => "two keys of the set carry the same kid",
        })
    }
}

impl std::error::Error for JwkRefusal {}

/// RFC 7517 section 4: one public JWK.
///
/// The four members every key in this deployment states, plus the algorithm-specific public
/// ones. Nothing here is private material and nothing here is constructed by this crate: the
/// type is a shape a composition fills.
///
/// # The member set is closed, in one place
///
/// Adversary pass 1 (F9, F10) drove an open `parameters` map two ways: RFC 7517 section 9.2's
/// private members (`d`, `p`, `q`, `dp`, `dq`, `qi`, `k`) rendered into the published document
/// exactly as `crv`/`x`/`y` did, and a parameter named `kid` silently replaced the declared
/// `kid` in the document a client reads a signing key's identity out of. Both are the same
/// defect — a published document assembled from names nobody checked — so the fix is a closed
/// set rather than a denylist of the seven private names: a JWK member RFC 7517 adds later is
/// refused until it is admitted here, which is the right way round for a document that
/// publishes key material's neighbours.
///
/// [`Jwk::new`] is the **only** place that refuses, and that is enough because it is the only
/// way to build one: `parameters` is private, so a struct literal outside this module does not
/// compile and the rendering cannot be handed a name the constructor never saw. Pass 1's fix
/// filtered a second time in [`Jwk::members`]; a rendering that drops what it cannot publish
/// is a rendering that publishes a *different* key than the one it was given, in silence, and
/// pass 2 (F7) is that the second filter had to go rather than be documented.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Jwk {
    /// `kty`, the key type.
    pub kty: String,
    /// `kid`, the key identifier.
    pub kid: String,
    /// `use`, the intended use. Named `key_use` because `use` is a Rust keyword; it is
    /// rendered as `use`.
    pub key_use: String,
    /// `alg`, the algorithm this key is used with.
    pub alg: String,
    /// The algorithm-specific public members, each named by [`Jwk::ADMITTED_PARAMETERS`].
    ///
    /// Private, so [`Jwk::new`] is the only way one is set and the rendering cannot see a name
    /// that constructor refused. [`Jwk::parameters`] reads them back.
    parameters: Vec<(String, String)>,
}

impl Jwk {
    /// The members the typed fields state, rendered under these names.
    pub const DECLARED_MEMBERS: &'static [&'static str] = &["kty", "kid", "use", "alg"];

    /// The algorithm-specific **public** members a parameter may name, and no others.
    ///
    /// RFC 7518 section 6.3.1 for RSA (`n`, `e`) and section 6.2.1 for elliptic curves (`crv`,
    /// `x`, `y`). Section 6.3.2's and 6.2.2's private members, and the symmetric `k` of section
    /// 6.4.1, are absent and are refused.
    pub const ADMITTED_PARAMETERS: &'static [&'static str] = &["n", "e", "crv", "x", "y"];

    /// Carry a public JWK.
    ///
    /// # Errors
    ///
    /// Returns [`JwkRefusal`] when a parameter names something outside
    /// [`Jwk::ADMITTED_PARAMETERS`], collides with one of [`Jwk::DECLARED_MEMBERS`], or is
    /// given twice.
    pub fn new(
        kty: &str,
        kid: &str,
        key_use: &str,
        alg: &str,
        parameters: &[(&str, &str)],
    ) -> Result<Self, JwkRefusal> {
        let mut carried: Vec<(String, String)> = Vec::new();
        for (name, value) in parameters {
            if Self::DECLARED_MEMBERS.contains(name) {
                return Err(JwkRefusal::DeclaredMemberCollision);
            }
            if !Self::ADMITTED_PARAMETERS.contains(name) {
                return Err(JwkRefusal::UndeclaredParameter);
            }
            if carried.iter().any(|(declared, _)| declared == name) {
                return Err(JwkRefusal::DuplicateParameter);
            }
            carried.push(((*name).to_owned(), (*value).to_owned()));
        }
        Ok(Self {
            kty: kty.to_owned(),
            kid: kid.to_owned(),
            key_use: key_use.to_owned(),
            alg: alg.to_owned(),
            parameters: carried,
        })
    }

    /// The admitted public parameters this key carries, as [`Jwk::new`] admitted them.
    #[must_use]
    pub fn parameters(&self) -> &[(String, String)] {
        &self.parameters
    }

    /// This key's members, rendered names included.
    ///
    /// The declared four first, then the parameters. There is no filter here: every name a
    /// `Jwk` carries came through [`Jwk::new`], which refused the private members, the
    /// collisions and the repeats — see the type's note on why one refusal is the whole of it.
    fn members(&self) -> Vec<(String, String)> {
        let mut members = vec![
            ("kty".to_owned(), self.kty.clone()),
            ("kid".to_owned(), self.kid.clone()),
            ("use".to_owned(), self.key_use.clone()),
            ("alg".to_owned(), self.alg.clone()),
        ];
        for (name, value) in &self.parameters {
            members.push((name.clone(), value.clone()));
        }
        members
    }
}

/// RFC 7517 section 5: the JWK Set document.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Jwks {
    /// The public keys this deployment publishes.
    pub keys: Vec<Jwk>,
}

impl Jwks {
    /// Carry a key set, refusing a repeated `kid`.
    ///
    /// The sanctioned constructor for a filled set: the composition holds the signing keys and
    /// this is where it hands them over. A `kid` names at most one key here, so a reader that
    /// resolves a signature's `kid` against this document resolves it to one key or to none.
    ///
    /// # Errors
    ///
    /// Returns [`JwkRefusal::RepeatedKeyId`] when two keys carry the same `kid`.
    pub fn new(keys: Vec<Jwk>) -> Result<Self, JwkRefusal> {
        for (position, key) in keys.iter().enumerate() {
            if keys[..position]
                .iter()
                .any(|carried| carried.kid == key.kid)
            {
                return Err(JwkRefusal::RepeatedKeyId);
            }
        }
        Ok(Self { keys })
    }

    /// The document with no key in it.
    ///
    /// What this crate can state on its own: it holds no signer, no key store and no
    /// configuration, so every key in a served document comes from the composition.
    #[must_use]
    pub const fn empty() -> Self {
        Self { keys: Vec::new() }
    }

    /// The declared JSON rendering.
    #[must_use]
    pub fn to_json(&self) -> String {
        oauth::object(&[(
            "keys",
            Member::Objects(self.keys.iter().map(Jwk::members).collect()),
        )])
    }
}

/// The health documents the two probe routes publish.
///
/// A wire document, not a contract command: it carries a status word and, when the answer is
/// not a success, the one reason, and nothing about the configuration, the keys or the
/// tenants behind it. A probe is unauthenticated and its answer is for a platform, so the
/// reason is a fixed phrase and never a value read from a document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Health {
    /// The process answers.
    Live,
    /// The deployment admitted its configuration and holds a signing key.
    Ready,
    /// The deployment has admitted no signing key, so it can publish none and sign none.
    NotReady,
}

impl Health {
    /// The liveness answer: the process is answering, so it is live.
    #[must_use]
    pub const fn live() -> Self {
        Self::Live
    }

    /// The readiness answer for a deployment whose signer `signs` or does not.
    ///
    /// The composition answers for the key it signs with: ready while its signer holds an
    /// active key whose `SigningKey` record admits signing now, and not ready otherwise — no
    /// key mounted, or the one it holds retired, revoked or outside its window.
    #[must_use]
    pub const fn ready(signs: bool) -> Self {
        if signs { Self::Ready } else { Self::NotReady }
    }

    /// The HTTP status this answer is served with.
    #[must_use]
    pub const fn status(self) -> u16 {
        match self {
            Self::Live | Self::Ready => 200,
            Self::NotReady => 503,
        }
    }

    /// The declared JSON rendering.
    #[must_use]
    pub fn to_json(self) -> String {
        match self {
            Self::Live | Self::Ready => oauth::object(&[("status", Member::Text("ok".to_owned()))]),
            Self::NotReady => oauth::object(&[
                ("reason", Member::Text("no signing key admitted".to_owned())),
                ("status", Member::Text("unavailable".to_owned())),
            ]),
        }
    }
}

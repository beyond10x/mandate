//! The RFC 8414 authorization server metadata document and the JWK Set document, as shapes.
//!
//! Both are built here and served nowhere: `story:product-listener` publishes them at the two
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
//! exactly one variant and `crate::decode::authorize_public_client` refuses every other
//! `code_challenge_method`. `token_endpoint_auth_methods_supported` is `["none"]` because the
//! login road is the public-client road and `crate::decode::redeem_authorization_code` refuses
//! `client_secret` as an undeclared parameter. `response_types_supported` and
//! `grant_types_supported` are the single values those two decoders admit. A metadata document
//! advertising a method no decoder admits is a document that lies to every client that reads
//! it, which is the failure RFC 8414 exists to prevent.

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
        oauth::object(&[
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
        ])
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
        authorization_endpoint: endpoint(&issuer, "mandate.federation.AuthorizePublicClient"),
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
        grant_types_supported: vec![crate::decode::AUTHORIZATION_CODE_GRANT.to_owned()],
        code_challenge_methods_supported: vec![mandate_proto::oauth::S256_METHOD.to_owned()],
        token_endpoint_auth_methods_supported: vec!["none".to_owned()],
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

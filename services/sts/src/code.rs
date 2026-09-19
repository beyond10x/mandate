//! `mandate.credential.IssueAuthorizationCode`.
//!
//! # The call the control plane assembles and never makes
//!
//! `mandate.federation.AuthorizePublicClient` validates the authorization request and stops
//! at an `IssueAuthorizationCodeInput` it carries on its candidate
//! (`crates/mandate-federation/src/authorize.rs`): "this crate declares no port for that
//! command, and the call belongs to the STS transaction". This is that command, satisfied
//! by value through the composition. `mandate-sts` gains no `mandate-federation`
//! dependency, and the adapter that carries one crate's value to the other's input is the
//! composition's (`story:product-listener`).
//!
//! # Only the verifier is stored
//!
//! "STS stores only a non-reversible verifier bound to the validated client, session, exact
//! redirect, S256 challenge, registered target, narrowed scope and bounded expiry. Only the
//! transient code is returned to the public-client adapter" (`credential.yaml`, the accepted
//! summary). The verifier is derived in
//! [`mandate_token::verifier::CredentialDomain::AuthorizationCodeVerifier`], its own digest
//! space, so a code presented where a credential proof is expected resolves to nothing —
//! and the code itself cannot reach a record at all: `mandate.core.CredentialSecret` is not
//! a `PersistedValue`, which `crate::store` makes the compiler's business.
//!
//! # What is decided here, and what is decided elsewhere
//!
//! The **target** rule is wave B's, landed for an issuance
//! ([`crate::issue`], `admitted_target`): the registration resolves, it belongs to the
//! caller's verified organization, it is enabled, and its published profile issues the
//! family a redemption returns. It deliberately does not ask whether the registration still
//! *holds* its audience: `services/sts/tests/adversary_profiles_2.rs` is the case that shows
//! what that costs, and issuance and introspection ask the same question at the same
//! instant because neither asks it.
//!
//! The **client** rule is this command's own — a registered, enabled public client of the
//! caller's organization — read through [`OAuthClientReads`] because
//! `mandate.federation.OAuthClient` is another domain's record and this crate holds no fold
//! of it.
//!
//! "Trusted control-plane caller/session context" is the adapter's: the `VerifiedContext`
//! this handler is given is what that validation produced. Authority narrowing is
//! `mandate-authz`'s, which is outside this crate's ceiling, so the `scope` recorded is the
//! one the caller presents, already narrowed — the reading [`crate::issue`] takes for the
//! same clause.
//!
//! # What "bounded expiry" bounds, and who names the bound
//!
//! The contract declares no maximum code lifetime: no entity invariant on
//! `mandate.credential.AuthorizationCode`, no field of `mandate.core.CredentialProfile`, no
//! `mandate.core` type. Without one, "bounded expiry validation" bounds a code only from
//! below — an instant after the request's — and a caller may name an instant a thousand
//! years ahead, which `services/sts/tests/adversary_transaction_1.rs` characterized.
//!
//! So the ceiling is **the deployment's**, and [`CodeIssuance`] takes it as a constructor
//! argument ([`CodeLifetime`]) with no default, the way
//! [`crate::keys::SigningKeyAdministration`] takes the admitted algorithm set. A default
//! here would be this crate inventing a policy the contract does not carry and no caller
//! could reproduce; a required argument is the deployment stating one. RFC 6749 section
//! 4.1.2 recommends a maximum of ten minutes, and this crate names no number.

use mandate_token::projection::{DenialClause, Denied};
use mandate_token::verifier::{CredentialDigest, CredentialDomain, verifier_in};
use mandate_types::{
    AuthorityScope, AuthorizationCodeId, CredentialProof, CredentialSecret, DenialReason, Duration,
    OAuthClientId, OrganizationId, PkceChallenge, PkceMethod, RedirectUri, ResourceServerId,
    SessionId, Timestamp, Transient, VerifiedContext,
};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::registry::ResourceServerReads;
use crate::store::AuthorizationCodeEvent;
use crate::{IdentityAllocator, RequestContext, SecretSource, instant};

/// The `mandate.federation.OAuthClient` read model, behind a port.
///
/// `mandate-sts` has no `mandate-federation` dependency (`dependency-boundaries.json`), and
/// the client a code is bound to is that crate's record. This is the two questions this
/// domain asks of it, and nothing more: a port that answered more would be this crate
/// holding another domain's record.
///
/// The adapter over `mandate_federation::record::Projection` is the composition's, the way
/// `mandate_federation::authorize::TargetRegistry` over [`ResourceServerReads`] is.
pub trait OAuthClientReads {
    /// The organization a registered client belongs to, or `None` when no event registered
    /// it.
    fn client_organization(&self, id: &OAuthClientId) -> Option<OrganizationId>;

    /// Whether a registered client is enabled, or `None` when the reader cannot answer.
    ///
    /// Three answers, not two, and [`admitted_client`] keeps them apart: `Some(false)` is
    /// "registered and disabled", which is a different refusal from "not registered"
    /// ([`OAuthClientReads::client_organization`] answering `None`), and `None` here is a
    /// reader that holds no answer — which has decided neither. It fails closed with
    /// `DenialReason::Unavailable`, the same crate-wide reading [`OAuthClientReads::is_public`]
    /// and [`OAuthClientReads::redirect_registered`] take, and
    /// `mandate_federation::authorize::TargetRegistry::can_answer` established.
    fn is_enabled(&self, id: &OAuthClientId) -> Option<bool>;

    /// Whether a registered client is a **public** one, or `None` when the reader cannot
    /// answer.
    ///
    /// `mandate.federation.OAuthClient` declares `public` (`federation.yaml:85-98`), and
    /// `IssueAuthorizationCode`'s denial names a "registered public client". `None` is not
    /// "yes": a reader that holds no answer has not decided that this client is public, and
    /// [`admitted_client`] fails closed on it with `DenialReason::Unavailable` — the reading
    /// `mandate_federation::authorize::TargetRegistry::can_answer` established for a
    /// registry that cannot see its own set.
    fn is_public(&self, id: &OAuthClientId) -> Option<bool>;

    /// Whether a registered client's redirect set carries this URI, **byte for byte**, or
    /// `None` when the reader cannot answer.
    ///
    /// `mandate.federation.OAuthClient.redirect_uris` (`federation.yaml:85-98`) is the
    /// registered set, and `IssueAuthorizationCode`'s denial names an "exact redirect URI".
    /// The comparison is the one [`crate::binding::authorized_redirect`] makes at
    /// redemption: nothing is normalized, because a registration that carries
    /// `https://client.example/callback` does not carry `https://client.example/callback/`.
    /// `None` fails closed for the reason [`OAuthClientReads::is_public`] does.
    fn redirect_registered(&self, id: &OAuthClientId, redirect_uri: &RedirectUri) -> Option<bool>;
}

/// An [`OAuthClientReads`] that answers for the clients it was told about.
///
/// **A double, never a shipped implementation**: a deployment answers this port from
/// `mandate-federation`'s own fold. It is `pub` and lives here because every file under
/// `tests/` compiles as its own crate.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RecordedClients {
    clients: Vec<RecordedClient>,
}

/// One client this double was told about.
///
/// `public` is an `Option` because the double answers the port honestly: a client recorded
/// without saying whether it is public answers `None`, which is a reader that cannot answer
/// and not a "yes". `redirects` is a set and not an `Option` for the same reason read the
/// other way — a client recorded with no redirect at all has an empty *known* set, and the
/// double reports that it cannot answer for it, because an empty set and an unknown set are
/// the same thing to a fixture that was told nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RecordedClient {
    id: OAuthClientId,
    organization: OrganizationId,
    enabled: bool,
    public: Option<bool>,
    redirects: Vec<RedirectUri>,
}

impl RecordedClients {
    /// A double that knows no client.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an enabled, public client of an organization, with no redirect yet.
    #[must_use]
    pub fn enabled(self, id: OAuthClientId, organization: OrganizationId) -> Self {
        self.record(id, organization, true, Some(true))
    }

    /// Record a disabled, public client of an organization.
    #[must_use]
    pub fn disabled(self, id: OAuthClientId, organization: OrganizationId) -> Self {
        self.record(id, organization, false, Some(true))
    }

    /// Record an enabled client this deployment registered as **confidential**.
    #[must_use]
    pub fn confidential(self, id: OAuthClientId, organization: OrganizationId) -> Self {
        self.record(id, organization, true, Some(false))
    }

    /// Record an enabled client the reader can say nothing about beyond its registration:
    /// neither that it is public nor that it is not.
    #[must_use]
    pub fn unanswerable(self, id: OAuthClientId, organization: OrganizationId) -> Self {
        self.record(id, organization, true, None)
    }

    /// Add one redirect URI to a recorded client's registered set.
    ///
    /// A client with no redirect recorded is one this double cannot answer the redirect
    /// question for; see [`RecordedClient`].
    #[must_use]
    pub fn redirect(mut self, id: OAuthClientId, redirect_uri: RedirectUri) -> Self {
        if let Some(client) = self.clients.iter_mut().find(|client| client.id == id) {
            client.redirects.push(redirect_uri);
        }
        self
    }

    fn record(
        mut self,
        id: OAuthClientId,
        organization: OrganizationId,
        enabled: bool,
        public: Option<bool>,
    ) -> Self {
        self.clients.push(RecordedClient {
            id,
            organization,
            enabled,
            public,
            redirects: Vec::new(),
        });
        self
    }

    fn recorded(&self, id: &OAuthClientId) -> Option<&RecordedClient> {
        self.clients.iter().find(|client| client.id == *id)
    }
}

impl OAuthClientReads for RecordedClients {
    fn client_organization(&self, id: &OAuthClientId) -> Option<OrganizationId> {
        self.recorded(id).map(|client| client.organization)
    }

    fn is_enabled(&self, id: &OAuthClientId) -> Option<bool> {
        self.recorded(id).map(|client| client.enabled)
    }

    fn is_public(&self, id: &OAuthClientId) -> Option<bool> {
        self.recorded(id).and_then(|client| client.public)
    }

    fn redirect_registered(&self, id: &OAuthClientId, redirect_uri: &RedirectUri) -> Option<bool> {
        let client = self.recorded(id)?;
        if client.redirects.is_empty() {
            return None;
        }
        Some(
            client.redirects.iter().any(|registered| {
                registered.as_str().as_bytes() == redirect_uri.as_str().as_bytes()
            }),
        )
    }
}

/// `mandate.credential.IssueAuthorizationCode`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IssueAuthorizationCode {
    /// The declared `context`.
    pub context: VerifiedContext,
    /// The declared `client_id`.
    pub client_id: OAuthClientId,
    /// The declared `session_id`.
    pub session_id: SessionId,
    /// The declared `target`.
    pub target: ResourceServerId,
    /// The declared `requested_scope`.
    pub requested_scope: AuthorityScope,
    /// The declared `challenge`.
    pub challenge: PkceChallenge,
    /// The declared `method`.
    pub method: PkceMethod,
    /// The declared `redirect_uri`.
    pub redirect_uri: RedirectUri,
    /// The declared `expires_at`.
    pub expires_at: Timestamp,
}

/// The accepted outcome of [`IssueAuthorizationCode`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationCodeIssuance {
    /// The declared `code_id` response, which the event's `code_id` is sourced from.
    pub code_id: AuthorizationCodeId,
    /// The declared `code` response: the transient code, returned once and never recorded.
    pub code: CredentialSecret,
    /// The event the accepted outcome emits.
    pub event: AuthorizationCodeEvent,
}

/// The deployment's ports for a code issuance.
///
/// Bundled rather than passed one by one, the way [`crate::issue::ReferenceParts`] is: a
/// signature that spelled the deployment out would be three more arguments that always
/// travel together.
pub struct AuthorizationCodeParts<'a, D: CredentialDigest, S: SecretSource, A: IdentityAllocator> {
    /// The digest the verifier is derived through.
    pub digest: &'a D,
    /// The source the returned code is minted from.
    pub secrets: &'a mut S,
    /// The allocator the response identity is minted from.
    pub allocator: &'a mut A,
}

/// The length of an S256 digest, in bytes (RFC 7636 section 4.2).
pub const DIGEST_LENGTH: usize = 32;

/// The length of an S256 challenge: a [`DIGEST_LENGTH`]-byte digest in unpadded base64url.
pub const CHALLENGE_LENGTH: usize = 43;

/// RFC 7636 section 4.1: a code verifier is at least 43 characters.
pub const VERIFIER_MINIMUM_LENGTH: usize = 43;

/// RFC 7636 section 4.1: a code verifier is at most 128 characters.
pub const VERIFIER_MAXIMUM_LENGTH: usize = 128;

/// Whether a challenge is in the declared S256 form.
///
/// The decode is what decides: the value must be the unpadded base64url encoding of exactly
/// [`DIGEST_LENGTH`] bytes. Length and alphabet alone are not the form — RFC 4648 section
/// 3.5 requires the pad bits of the final quantum to be zero, and a 43-character base64url
/// string whose last character carries either pad bit is the encoding of no value at all
/// (three of every four are), so it is the S256 challenge of no verifier that exists.
/// Recording one would put a code into the log that no redemption could ever satisfy.
///
/// `crates/mandate-federation/src/pkce.rs` decides the same form for the same reason, for
/// the non-consuming validation that runs before this command. Two copies of one rule is
/// the cost of the dependency direction — `mandate-sts` may not see `mandate-federation`,
/// and the shared home is `mandate-types`, which this story may not edit — and it is named
/// here as residue rather than left to be found.
#[must_use]
pub fn challenge_is_well_formed(challenge: &PkceChallenge) -> bool {
    let text = challenge.as_str();
    text.len() == CHALLENGE_LENGTH
        && decode_base64url(text).is_some_and(|digest| digest.len() == DIGEST_LENGTH)
}

/// Whether a presented code verifier is in the form RFC 7636 section 4.1 declares.
///
/// Between [`VERIFIER_MINIMUM_LENGTH`] and [`VERIFIER_MAXIMUM_LENGTH`] characters of the
/// unreserved set `[A-Za-z0-9-._~]`.
#[must_use]
pub fn verifier_is_well_formed(verifier: &CredentialProof) -> bool {
    let material = verifier.expose_material();
    (VERIFIER_MINIMUM_LENGTH..=VERIFIER_MAXIMUM_LENGTH).contains(&material.len())
        && material.iter().copied().all(is_unreserved)
}

/// `BASE64URL-ENCODE(SHA256(ASCII(verifier)))`, RFC 7636 section 4.2.
///
/// This is the real digest and not a stand-in: `sha2` is in this crate's dependency ceiling
/// (`dependency-boundaries.json`), which is why the S256 half of PKCE is decided here rather
/// than behind the port `mandate-federation` needs.
#[must_use]
pub fn s256_challenge(verifier: &CredentialProof) -> PkceChallenge {
    PkceChallenge::new(encode_base64url(&Sha256::digest(
        verifier.expose_material(),
    )))
}

/// Whether a byte is in RFC 3986's unreserved set.
const fn is_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

/// The base64url alphabet, in order (RFC 4648 section 5).
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// The value a base64url character carries, or `None` when it carries none.
fn alphabet_index(byte: u8) -> Option<u8> {
    ALPHABET
        .iter()
        .position(|entry| *entry == byte)
        .and_then(|index| u8::try_from(index).ok())
}

/// Decode unpadded base64url, answering `None` for text that is the encoding of no value.
fn decode_base64url(text: &str) -> Option<Vec<u8>> {
    let mut accumulator: u32 = 0;
    let mut bits: u32 = 0;
    let mut decoded = Vec::with_capacity(text.len() / 4 * 3);
    for byte in text.bytes() {
        accumulator = (accumulator << 6) | u32::from(alphabet_index(byte)?);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            decoded.push(u8::try_from((accumulator >> bits) & 0xff).ok()?);
        }
    }
    if bits >= 6 || accumulator & ((1 << bits) - 1) != 0 {
        return None;
    }
    Some(decoded)
}

/// Encode bytes as unpadded base64url (RFC 4648 section 5).
fn encode_base64url(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let mut accumulator = 0_u32;
        for (index, byte) in chunk.iter().enumerate() {
            accumulator |= u32::from(*byte) << (16 - 8 * index);
        }
        for index in 0..=chunk.len() {
            let shift = 18 - 6 * index;
            text.push(char::from(ALPHABET[((accumulator >> shift) & 63) as usize]));
        }
    }
    text
}

/// The registered client a code may be bound to, or the declared refusal.
///
/// Four questions, and the declared denial names all four: the client is registered
/// ("registered public client"), it belongs to the caller's organization ("tenant/target
/// agreement"), it is enabled ("the client the code would be bound to is disabled"), and it
/// is a **public** client ("registered public client"). A redirect, when one is presented,
/// is the fifth ("exact redirect URI") and is checked by [`admitted_redirect`].
///
/// Its own function because a redemption asks the first three again, against the record
/// rather than the input ([`crate::binding::bound_client`]). The public-client question is
/// issuance's alone: it decides whether a code may exist, and a code that exists was already
/// decided.
///
/// # Errors
///
/// Returns [`Denied`] when the client resolves to no registration, belongs to another
/// organization, is disabled, or is not one the registry answers "public" for. A reader that
/// cannot answer either of the last two refuses with `DenialReason::Unavailable` rather than
/// with the positive refusal: it has decided neither that the client is disabled nor that it
/// is confidential.
pub fn admitted_client(
    client_id: &OAuthClientId,
    organization: &OrganizationId,
    clients: &impl OAuthClientReads,
    public_client_required: bool,
) -> Result<(), Denied> {
    let registered = clients
        .client_organization(client_id)
        .ok_or_else(|| Denied::new(DenialReason::Denied, DenialClause::ClientUnregistered))?;
    if registered != *organization {
        return Err(Denied::new(
            DenialReason::TenantMismatch,
            DenialClause::ClientOutsideOrganization,
        ));
    }
    match clients.is_enabled(client_id) {
        Some(true) => {}
        Some(false) => {
            return Err(Denied::new(
                DenialReason::Denied,
                DenialClause::ClientDisabled,
            ));
        }
        // A reader that holds no answer has not decided that the client is disabled, and
        // reporting the positive refusal for it would report a registration fact this crate
        // cannot see.
        None => {
            return Err(Denied::new(
                DenialReason::Unavailable,
                DenialClause::ClientDisabled,
            ));
        }
    }
    if public_client_required {
        match clients.is_public(client_id) {
            Some(true) => {}
            Some(false) => {
                return Err(Denied::new(
                    DenialReason::Denied,
                    DenialClause::ClientNotPublic,
                ));
            }
            // A reader that holds no answer has decided nothing, and answering "public" for
            // it would be this crate deciding a registration fact it cannot see.
            None => {
                return Err(Denied::new(
                    DenialReason::Unavailable,
                    DenialClause::ClientNotPublic,
                ));
            }
        }
    }
    Ok(())
}

/// The redirect a code may be bound to is one the client's registration carries, byte for
/// byte.
///
/// "exact redirect URI" (`credential.yaml`; `docs/architecture/command-obligations.md:13`).
/// Before this the STS recorded whatever redirect it was handed and honoured it byte for
/// byte at redemption, so a code could be minted bound to a redirect no registration was
/// consulted for — `services/sts/tests/adversary_transaction_1.rs` characterizes that gap.
/// `mandate.federation.OAuthClient` declares the registered set and
/// `crates/mandate-federation/src/publicclient.rs:100` compares against it for the
/// control-plane half; this is the STS's own half of the same clause, through the port,
/// because that record is another domain's.
///
/// # Errors
///
/// Returns [`Denied`] when the registration does not carry this exact URI, and
/// `DenialReason::Unavailable` when the reader cannot answer for that client at all.
pub fn admitted_redirect(
    client_id: &OAuthClientId,
    redirect_uri: &RedirectUri,
    clients: &impl OAuthClientReads,
) -> Result<(), Denied> {
    match clients.redirect_registered(client_id, redirect_uri) {
        Some(true) => Ok(()),
        Some(false) => Err(Denied::new(
            DenialReason::Denied,
            DenialClause::RedirectUnregistered,
        )),
        None => Err(Denied::new(
            DenialReason::Unavailable,
            DenialClause::RedirectUnregistered,
        )),
    }
}

/// The longest lifetime this deployment issues an authorization code for.
///
/// A `mandate.core`-shaped span and not a number: the contract's `duration` form, read by
/// [`crate::instant::span_of`], so a deployment states it the way every other span in this
/// contract is stated. There is no default and no constant here; see the module
/// documentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeLifetime(Duration);

impl CodeLifetime {
    /// The ceiling a deployment names.
    #[must_use]
    pub const fn new(bound: Duration) -> Self {
        Self(bound)
    }

    /// The declared span.
    #[must_use]
    pub const fn as_duration(&self) -> &Duration {
        &self.0
    }
}

/// `mandate.credential.IssueAuthorizationCode`, over the deployment's code-lifetime ceiling.
///
/// A type rather than a free function for the reason
/// [`crate::keys::SigningKeyAdministration`] is one: the command's decision depends on a
/// policy value the contract does not carry, and a deployment supplies it once rather than
/// at every call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeIssuance {
    lifetime: CodeLifetime,
}

impl CodeIssuance {
    /// Issuance under a deployment's code-lifetime ceiling.
    #[must_use]
    pub const fn new(lifetime: CodeLifetime) -> Self {
        Self { lifetime }
    }

    /// The ceiling this issuance bounds a code by.
    #[must_use]
    pub const fn lifetime(&self) -> &CodeLifetime {
        &self.lifetime
    }

    /// Realize `mandate.credential.IssueAuthorizationCode`.
    ///
    /// The code is minted, returned once, and never recorded: what the log carries is the
    /// verifier it derives, in the authorization code's own digest domain.
    ///
    /// # Errors
    ///
    /// Returns [`Denied`] through the declared `denied` outcome when the target is
    /// unregistered, disabled, outside the caller's verified organization or published under
    /// a profile that does not issue the family a redemption returns; when the client the
    /// code would be bound to is unregistered, outside that organization, disabled or not a
    /// public client; when the redirect is not one that client's registration carries; when
    /// the challenge is not in the declared S256 form; and when the expiry is not after the
    /// request instant or is beyond this deployment's ceiling. A refusal mints no code and
    /// no identity.
    pub fn issue<D, S, A>(
        &self,
        input: &IssueAuthorizationCode,
        request: &RequestContext,
        servers: &impl ResourceServerReads,
        clients: &impl OAuthClientReads,
        parts: AuthorizationCodeParts<'_, D, S, A>,
    ) -> Result<AuthorizationCodeIssuance, Denied>
    where
        D: CredentialDigest,
        S: SecretSource,
        A: IdentityAllocator,
    {
        issue_authorization_code(input, request, servers, clients, &self.lifetime, parts)
    }
}

/// The deciding body, over an explicit ceiling.
///
/// Crate-private: the ceiling is a deployment policy and [`CodeIssuance`] is how a caller
/// states it, so there is no way to reach this command without naming one.
fn issue_authorization_code<D, S, A>(
    input: &IssueAuthorizationCode,
    request: &RequestContext,
    servers: &impl ResourceServerReads,
    clients: &impl OAuthClientReads,
    lifetime: &CodeLifetime,
    parts: AuthorizationCodeParts<'_, D, S, A>,
) -> Result<AuthorizationCodeIssuance, Denied>
where
    D: CredentialDigest,
    S: SecretSource,
    A: IdentityAllocator,
{
    let server = servers
        .resource_server(&input.target)
        .ok_or_else(|| Denied::new(DenialReason::Denied, DenialClause::TargetUnregistered))?;
    if server.organization_id != input.context.organization {
        return Err(Denied::new(
            DenialReason::TenantMismatch,
            DenialClause::OrganizationMismatch,
        ));
    }
    if servers.is_enabled(&input.target) != Some(true) {
        return Err(Denied::new(
            DenialReason::Denied,
            DenialClause::TargetDisabled,
        ));
    }
    // The credential a redemption of this code returns is a reference credential — the
    // outcome responds with a `CredentialSecret` and records its `reference_verifier`
    // (`credential.yaml`, `RedeemAuthorizationCode`) — so a registration published under the
    // other family issues no code here rather than issuing one that could never be redeemed.
    if server.credential_profile.kind != mandate_types::CredentialKind::Reference {
        return Err(Denied::new(
            DenialReason::Denied,
            DenialClause::ProfileUnadmitted,
        ));
    }
    // "registered public client": at issuance the STS asks for the public half as well, as
    // the second line behind the control-plane adapter that has already decided it.
    admitted_client(&input.client_id, &input.context.organization, clients, true)?;
    // "exact redirect URI": the redirect the code would be bound to is one the client's
    // registration carries, byte for byte.
    admitted_redirect(&input.client_id, &input.redirect_uri, clients)?;
    match input.method {
        // Exhaustive and without a wildcard: `mandate.core.PkceMethod` declares exactly one
        // variant, so RFC 7636's `plain` has no Rust value here and a second declared method
        // would fail to compile rather than fall through to the S256 branch.
        PkceMethod::S256 => {}
    }
    if !challenge_is_well_formed(&input.challenge) {
        return Err(Denied::new(
            DenialReason::InvalidCredential,
            DenialClause::ChallengeMalformed,
        ));
    }
    // "bounded expiry validation": after the request instant, and no later than the request
    // instant plus the ceiling this deployment named. A ceiling that names no span is a
    // bound this handler cannot apply, and it fails closed rather than issuing an unbounded
    // code.
    let unbounded = || Denied::new(DenialReason::Denied, DenialClause::ExpiryUnbounded);
    if instant::is_before(&request.at, &input.expires_at) != Some(true) {
        return Err(unbounded());
    }
    let issued_at = instant::seconds_of(&request.at).ok_or_else(unbounded)?;
    let ceiling = instant::span_of(lifetime.as_duration())
        .filter(|span| *span > 0)
        .and_then(|span| issued_at.checked_add(span))
        .ok_or_else(unbounded)?;
    if instant::seconds_of(&input.expires_at).ok_or_else(unbounded)? > ceiling {
        return Err(unbounded());
    }

    // Nothing above this line mints anything: a refusal leaves the deployment exactly as it
    // was.
    let code = parts.secrets.next_secret();
    let verifier = verifier_in(
        parts.digest,
        CredentialDomain::AuthorizationCodeVerifier,
        &code,
    );
    let code_id = parts.allocator.next_authorization_code_id();
    Ok(AuthorizationCodeIssuance {
        code_id,
        code,
        event: AuthorizationCodeEvent::AuthorizationCodeIssued {
            context: input.context.clone(),
            code_id,
            client_id: input.client_id,
            session_id: input.session_id,
            verifier,
            challenge: input.challenge.clone(),
            method: input.method,
            redirect_uri: input.redirect_uri.clone(),
            expires_at: input.expires_at.clone(),
            target: input.target,
            // The declared `scope` is `generated: true`: it is the narrowed authority the
            // outcome records, and narrowing is an authorization decision no crate in this
            // crate's ceiling makes, so what is recorded is the scope the adapter presents,
            // already narrowed — the reading `crate::issue` takes for the same clause.
            scope: input.requested_scope.clone(),
        },
    })
}

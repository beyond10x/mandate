//! `verify(token) -> identity`: the token guard's check of one bearer token.
//!
//! The clauses are decided in the order `systems/mandate/domains/guard.yaml` states:
//! malformed, issuer, key, signature, audience, expiry, not-yet-valid, allow rule. The
//! issuer is read before the signature is checked, so a token from a foreign issuer is
//! refused before its `kid` can cause a JWK Set refetch; nothing else is decided on an
//! unverified claim. The limits and the queue are the guard sidecar's, not this check's.

use std::sync::{Mutex, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use jsonwebtoken::dangerous::insecure_decode;
use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::jwk::{Jwk, JwkSet};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::Deserialize;

use mandate_contract::types::{
    MandateCoreAudience, MandateCoreExternalSubject, MandateGuardEmailAddress,
    MandateGuardGroupName, Presence,
};

use crate::{GuardPolicy, Identity, Refusal, RefusalReason};

/// The largest clock skew a policy may name: five minutes.
pub const MAX_CLOCK_SKEW: Duration = Duration::from_secs(300);

/// How often any JWK Set refetch may happen, unless the caller sets another bound: an unknown
/// `kid` cannot cause more than one fetch per interval, whatever the request rate.
pub const DEFAULT_REFRESH_INTERVAL: Duration = Duration::from_secs(30);

/// How old the held JWK Set may grow before the next lookup refetches it, unless the caller
/// sets another bound. A key the issuer withdraws stops verifying within this age, even while
/// every token names a `kid` the held set still carries.
pub const DEFAULT_MAX_AGE: Duration = Duration::from_secs(15 * 60);

/// The signature algorithms the guard admits: asymmetric only, so a published key can
/// never be used as a shared secret.
const ADMITTED: [Algorithm; 9] = [
    Algorithm::RS256,
    Algorithm::RS384,
    Algorithm::RS512,
    Algorithm::PS256,
    Algorithm::PS384,
    Algorithm::PS512,
    Algorithm::ES256,
    Algorithm::ES384,
    Algorithm::EdDSA,
];

/// Where the issuer's JWK Set comes from: an HTTP fetch in the guard, a fixed set in a test.
pub trait JwksSource {
    /// The issuer's current JWK Set.
    ///
    /// # Errors
    ///
    /// [`FetchError`] when the set cannot be obtained; the verifier keeps the set it holds.
    fn fetch(&self) -> Result<JwkSet, FetchError>;
}

/// A JWK Set fetch that did not produce a set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FetchError(pub String);

/// A policy the verifier cannot run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolicyError {
    /// `clock_skew` is not an ISO 8601 duration of whole hours, minutes and seconds.
    ClockSkew(String),
    /// `clock_skew` is longer than [`MAX_CLOCK_SKEW`].
    ClockSkewTooLarge,
    /// The policy names no audience, so no token could ever be admitted.
    NoAudience,
    /// A limit is negative or not a whole number.
    NegativeLimit(&'static str),
}

/// The JWK Set the verifier holds, when it last obtained one, and when it last asked.
struct Cache {
    set: JwkSet,
    /// The last fetch that produced a set: the held set's age is counted from here.
    fetched_at: Option<SystemTime>,
    /// The last fetch attempted, successful or not: the refresh interval is counted from here.
    attempted_at: Option<SystemTime>,
}

/// Verifies bearer tokens for one [`GuardPolicy`] against one issuer's JWK Set.
pub struct Verifier<S> {
    policy: GuardPolicy,
    skew: i64,
    refresh: Duration,
    max_age: Duration,
    source: S,
    cache: Mutex<Cache>,
}

/// The claims the guard reads. Any other claim is ignored.
#[derive(Deserialize)]
struct Claims {
    iss: Option<String>,
    sub: Option<String>,
    aud: Option<Audiences>,
    exp: Option<i64>,
    nbf: Option<i64>,
    email: Option<String>,
    email_verified: Option<serde_json::Value>,
    groups: Option<Vec<String>>,
}

/// `aud` is one string or a list of them (RFC 7519 §4.1.3).
#[derive(Deserialize)]
#[serde(untagged)]
enum Audiences {
    One(String),
    Many(Vec<String>),
}

impl Audiences {
    fn values(&self) -> &[String] {
        match self {
            Self::One(one) => std::slice::from_ref(one),
            Self::Many(many) => many,
        }
    }
}

fn refuse<T>(reason: RefusalReason) -> Result<T, Refusal> {
    Err(Refusal { reason })
}

/// Reads `PT[nH][nM][nS]`, whole units only.
fn parse_skew(text: &str) -> Result<Duration, PolicyError> {
    let invalid = || PolicyError::ClockSkew(text.to_owned());
    let body = text.strip_prefix("PT").ok_or_else(invalid)?;
    if body.is_empty() {
        return Err(invalid());
    }
    let mut seconds: u64 = 0;
    let mut digits = String::new();
    let mut last_rank = 0;
    for character in body.chars() {
        if character.is_ascii_digit() {
            digits.push(character);
            continue;
        }
        let (rank, unit) = match character {
            'H' => (1, 3600),
            'M' => (2, 60),
            'S' => (3, 1),
            _ => return Err(invalid()),
        };
        if digits.is_empty() || rank <= last_rank {
            return Err(invalid());
        }
        let value: u64 = digits.parse().map_err(|_| invalid())?;
        seconds = value
            .checked_mul(unit)
            .and_then(|part| seconds.checked_add(part))
            .ok_or_else(invalid)?;
        digits.clear();
        last_rank = rank;
    }
    if !digits.is_empty() {
        return Err(invalid());
    }
    Ok(Duration::from_secs(seconds))
}

/// A validation that checks only the signature and the algorithm; every claim is the guard's.
fn signature_only(algorithm: Algorithm) -> Validation {
    let mut validation = Validation::new(algorithm);
    validation.validate_exp = false;
    validation.validate_nbf = false;
    validation.validate_aud = false;
    validation.required_spec_claims.clear();
    validation
}

fn seconds(now: SystemTime) -> i64 {
    now.duration_since(UNIX_EPOCH).map_or(0, |since| {
        i64::try_from(since.as_secs()).unwrap_or(i64::MAX)
    })
}

impl<S: JwksSource> Verifier<S> {
    /// A verifier for `policy`, reading keys from `source`.
    ///
    /// # Errors
    ///
    /// [`PolicyError`] when the policy cannot be run.
    pub fn new(policy: GuardPolicy, source: S) -> Result<Self, PolicyError> {
        let skew = parse_skew(&policy.clock_skew)?;
        if skew > MAX_CLOCK_SKEW {
            return Err(PolicyError::ClockSkewTooLarge);
        }
        if policy.audiences.is_empty() {
            return Err(PolicyError::NoAudience);
        }
        for (name, value) in [
            ("per_minute", &policy.limits.per_minute),
            ("burst", &policy.limits.burst),
            ("queue", &policy.limits.queue),
        ] {
            if value.as_u64().is_none() {
                return Err(PolicyError::NegativeLimit(name));
            }
        }
        Ok(Self {
            skew: i64::try_from(skew.as_secs()).unwrap_or(i64::MAX),
            policy,
            refresh: DEFAULT_REFRESH_INTERVAL,
            max_age: DEFAULT_MAX_AGE,
            source,
            cache: Mutex::new(Cache {
                set: JwkSet { keys: Vec::new() },
                fetched_at: None,
                attempted_at: None,
            }),
        })
    }

    /// The same verifier with another bound on how often the set may be refetched.
    #[must_use]
    pub fn with_refresh_interval(mut self, interval: Duration) -> Self {
        self.refresh = interval;
        self
    }

    /// The same verifier with another bound on how old the held set may grow before a lookup
    /// refetches it.
    #[must_use]
    pub fn with_max_age(mut self, age: Duration) -> Self {
        self.max_age = age;
        self
    }

    /// The policy this verifier decides by.
    pub fn policy(&self) -> &GuardPolicy {
        &self.policy
    }

    /// Verify `token` at the current time.
    ///
    /// # Errors
    ///
    /// A [`Refusal`] naming the clause that refused the token.
    pub fn verify(&self, token: &str) -> Result<Identity, Refusal> {
        self.verify_at(token, SystemTime::now())
    }

    /// Verify `token` as if the clock read `now`.
    ///
    /// # Errors
    ///
    /// A [`Refusal`] naming the clause that refused the token.
    pub fn verify_at(&self, token: &str, now: SystemTime) -> Result<Identity, Refusal> {
        let Ok(header) = decode_header(token) else {
            return refuse(RefusalReason::Malformed);
        };
        if !ADMITTED.contains(&header.alg) {
            return refuse(RefusalReason::Malformed);
        }
        let Some(kid) = header.kid.as_deref() else {
            return refuse(RefusalReason::Malformed);
        };

        // The issuer, read before any key is looked up; the signature is checked below.
        let Ok(claimed) = insecure_decode::<Claims>(token) else {
            return refuse(RefusalReason::Malformed);
        };
        let (Some(issuer), Some(_), Some(_), Some(_)) = (
            &claimed.claims.iss,
            &claimed.claims.sub,
            &claimed.claims.aud,
            claimed.claims.exp,
        ) else {
            return refuse(RefusalReason::Malformed);
        };
        if issuer != &self.policy.issuer.0 {
            return refuse(RefusalReason::IssuerMismatch);
        }

        let Some(jwk) = self.key(kid, now) else {
            return refuse(RefusalReason::UnknownKey);
        };
        if jwk.common.key_algorithm.is_some_and(|published| {
            published.to_string().parse::<Algorithm>().ok() != Some(header.alg)
        }) {
            return refuse(RefusalReason::InvalidSignature);
        }
        let Ok(decoding) = DecodingKey::from_jwk(&jwk) else {
            return refuse(RefusalReason::InvalidSignature);
        };
        let claims = match decode::<Claims>(token, &decoding, &signature_only(header.alg)) {
            Ok(data) => data.claims,
            Err(error) => {
                return refuse(match error.kind() {
                    ErrorKind::InvalidSignature
                    | ErrorKind::InvalidAlgorithm
                    | ErrorKind::InvalidEcdsaKey
                    | ErrorKind::InvalidRsaKey(_)
                    | ErrorKind::InvalidEddsaKey
                    | ErrorKind::InvalidKeyFormat => RefusalReason::InvalidSignature,
                    _ => RefusalReason::Malformed,
                });
            }
        };
        let (Some(subject), Some(audiences), Some(expiry)) = (claims.sub, claims.aud, claims.exp)
        else {
            return refuse(RefusalReason::Malformed);
        };
        if subject.is_empty() {
            return refuse(RefusalReason::Malformed);
        }

        let Some(audience) = audiences.values().iter().find(|value| {
            self.policy
                .audiences
                .iter()
                .any(|admitted| &admitted.0 == *value)
        }) else {
            return refuse(RefusalReason::AudienceMismatch);
        };

        let now = seconds(now);
        if now >= expiry.saturating_add(self.skew) {
            return refuse(RefusalReason::Expired);
        }
        if claims
            .nbf
            .is_some_and(|not_before| now.saturating_add(self.skew) < not_before)
        {
            return refuse(RefusalReason::NotYetValid);
        }

        // `email_verified` speaks for an email; without one there is nothing it verified.
        let verified =
            claims.email.is_some() && claims.email_verified == Some(serde_json::Value::Bool(true));
        if !self.allowed(claims.email.as_deref(), verified) {
            return refuse(RefusalReason::IdentityNotAllowed);
        }

        Ok(Identity {
            subject: MandateCoreExternalSubject(subject),
            email: claims.email.map_or(Presence::Absent, |email| {
                Presence::Present(MandateGuardEmailAddress(email))
            }),
            email_verified: verified,
            groups: claims
                .groups
                .unwrap_or_default()
                .into_iter()
                .map(MandateGuardGroupName)
                .collect(),
            audience: MandateCoreAudience(audience.clone()),
        })
    }

    /// The allow rule: an empty rule admits every verified token; otherwise a verified
    /// email that is listed, or whose domain is listed, without regard to ASCII case.
    fn allowed(&self, email: Option<&str>, verified: bool) -> bool {
        let rule = &self.policy.allow;
        if rule.emails.is_empty() && rule.domains.is_empty() {
            return true;
        }
        let Some(email) = email.filter(|_| verified) else {
            return false;
        };
        if rule
            .emails
            .iter()
            .any(|listed| listed.0.eq_ignore_ascii_case(email))
        {
            return true;
        }
        let Some((local, domain)) = email.rsplit_once('@') else {
            return false;
        };
        !local.is_empty()
            && !domain.is_empty()
            && rule
                .domains
                .iter()
                .any(|listed| listed.0.eq_ignore_ascii_case(domain))
    }

    /// The published key `kid` names, from a set no older than the maximum age.
    ///
    /// A held set younger than the maximum age answers a `kid` it carries. Otherwise the set is
    /// refetched, at most once per refresh interval whatever the cause, and the `kid` is looked
    /// up in what that fetch returned, so a key absent from a fresh set is refused. A failed
    /// fetch keeps the held set; the next attempt waits out the refresh interval.
    fn key(&self, kid: &str, now: SystemTime) -> Option<Jwk> {
        let elapsed = |since: Option<SystemTime>, bound: Duration| {
            since.is_none_or(|at| now.duration_since(at).map_or(true, |age| age >= bound))
        };
        let mut cache = self.cache.lock().unwrap_or_else(PoisonError::into_inner);
        if !elapsed(cache.fetched_at, self.max_age)
            && let Some(jwk) = cache.set.find(kid)
        {
            return Some(jwk.clone());
        }
        if elapsed(cache.attempted_at, self.refresh) {
            cache.attempted_at = Some(now);
            if let Ok(set) = self.source.fetch() {
                cache.set = set;
                cache.fetched_at = Some(now);
            }
        }
        cache.set.find(kid).cloned()
    }
}

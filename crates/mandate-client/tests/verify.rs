//! `verify(token) -> identity`, decided by real signatures.
//!
//! Every key is generated at test time with `aws-lc-rs`; no private key material is
//! committed. The JWK Set is a [`Rotating`] source the case can rotate under a running
//! verifier, which is what "picked up without a restart" means.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair};
use jsonwebtoken::jwk::{Jwk, JwkSet};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::{Value, json};

use mandate_client::verify::{FetchError, JwksSource, PolicyError, Verifier};
use mandate_client::{AllowRule, GuardLimits, GuardPolicy, Refusal, RefusalReason};
use mandate_contract::types::{MandateCoreAudience, MandateCoreIssuer, Presence};
use mandate_contract::types::{MandateGuardEmailAddress, MandateGuardEmailDomain};

const ISSUER: &str = "https://idp.example.test";
const AUDIENCE: &str = "orders";

/// 2026-01-05T09:00:00Z, the instant the `guard-*` scenarios run at.
const NOW: u64 = 1_767_603_600;

fn at(seconds: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(seconds)
}

/// One P-256 key: what signs, and the JWK a verifier is published.
struct Key {
    encoding: EncodingKey,
    published: Jwk,
}

fn key(kid: &str) -> Key {
    let pkcs8 =
        EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new())
            .expect("P-256 generation");
    let encoding = EncodingKey::from_ec_der(pkcs8.as_ref());
    let mut published =
        Jwk::from_encoding_key(&encoding, Algorithm::ES256).expect("a JWK from the key");
    published.common.key_id = Some(kid.to_owned());
    Key {
        encoding,
        published,
    }
}

fn sign(key: &Key, kid: &str, claims: &Value) -> String {
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(kid.to_owned());
    encode(&header, claims, &key.encoding).expect("a signed token")
}

fn claims() -> Value {
    json!({
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "u-1",
        "email": "ada@example.test",
        "email_verified": true,
        "groups": ["staff"],
        "iat": NOW - 600,
        "nbf": NOW - 600,
        "exp": NOW + 3600,
    })
}

fn with(mut base: Value, field: &str, value: Value) -> Value {
    base[field] = value;
    base
}

fn policy() -> GuardPolicy {
    GuardPolicy {
        issuer: MandateCoreIssuer(ISSUER.to_owned()),
        audiences: vec![
            MandateCoreAudience("billing-admin".to_owned()),
            MandateCoreAudience(AUDIENCE.to_owned()),
        ],
        allow: AllowRule {
            emails: vec![MandateGuardEmailAddress("grace@partner.test".to_owned())],
            domains: vec![MandateGuardEmailDomain("example.test".to_owned())],
        },
        limits: GuardLimits {
            per_minute: 60.into(),
            burst: 10.into(),
            queue: 32.into(),
        },
        clock_skew: "PT30S".to_owned(),
    }
}

/// A JWK Set the case can rotate, counting how often the verifier fetches it.
#[derive(Clone, Default)]
struct Rotating {
    set: Arc<Mutex<Vec<Jwk>>>,
    fetches: Arc<AtomicUsize>,
}

impl Rotating {
    fn holding(keys: &[&Key]) -> Self {
        let source = Self::default();
        source.rotate(keys);
        source
    }

    fn rotate(&self, keys: &[&Key]) {
        *self.set.lock().expect("the set lock") =
            keys.iter().map(|key| key.published.clone()).collect();
    }

    fn fetches(&self) -> usize {
        self.fetches.load(Ordering::SeqCst)
    }
}

impl JwksSource for Rotating {
    fn fetch(&self) -> Result<JwkSet, FetchError> {
        self.fetches.fetch_add(1, Ordering::SeqCst);
        Ok(JwkSet {
            keys: self.set.lock().expect("the set lock").clone(),
        })
    }
}

fn refused(reason: RefusalReason) -> Result<(), Refusal> {
    Err(Refusal { reason })
}

fn outcome(verifier: &Verifier<Rotating>, token: &str, now: u64) -> Result<(), Refusal> {
    verifier.verify_at(token, at(now)).map(|_| ())
}

#[test]
fn jwks_rotation_picked_up_without_restart() {
    let first = key("k1");
    let second = key("k2");
    let source = Rotating::holding(&[&first]);
    let verifier = Verifier::new(policy(), source.clone())
        .expect("a runnable policy")
        .with_refresh_interval(Duration::from_secs(30));

    let identity = verifier
        .verify_at(&sign(&first, "k1", &claims()), at(NOW))
        .expect("a token signed by the published key is admitted");
    assert_eq!(identity.subject.0, "u-1");
    assert_eq!(source.fetches(), 1, "the first token fetches the set once");

    // The same key again is answered from the cache.
    assert_eq!(
        outcome(&verifier, &sign(&first, "k1", &claims()), NOW + 1),
        Ok(())
    );
    assert_eq!(
        source.fetches(),
        1,
        "a known kid is answered from the cached set"
    );

    // The issuer rotates: k2 replaces k1. Past the refresh bound, the new kid is fetched
    // and admitted by the same verifier, with no restart.
    source.rotate(&[&second]);
    assert_eq!(
        outcome(&verifier, &sign(&second, "k2", &claims()), NOW + 31),
        Ok(())
    );
    assert_eq!(source.fetches(), 2, "an unknown kid refetches the set");

    // The retired k1 is gone from the refetched set, so a token it signs is refused.
    assert_eq!(
        outcome(&verifier, &sign(&first, "k1", &claims()), NOW + 32),
        refused(RefusalReason::UnknownKey)
    );
    assert_eq!(
        source.fetches(),
        2,
        "within the refresh bound, an unknown kid does not refetch"
    );
}

#[test]
fn unknown_kid_refetch_is_rate_bounded() {
    let first = key("k1");
    let source = Rotating::holding(&[&first]);
    let verifier = Verifier::new(policy(), source.clone())
        .expect("a runnable policy")
        .with_refresh_interval(Duration::from_secs(30));
    assert_eq!(
        outcome(&verifier, &sign(&first, "k1", &claims()), NOW),
        Ok(())
    );

    for offset in 1..20 {
        assert_eq!(
            outcome(&verifier, &sign(&first, "k9", &claims()), NOW + offset),
            refused(RefusalReason::UnknownKey)
        );
    }
    assert_eq!(
        source.fetches(),
        1,
        "nineteen unknown kids inside the bound fetch nothing"
    );

    assert_eq!(
        outcome(&verifier, &sign(&first, "k9", &claims()), NOW + 30),
        refused(RefusalReason::UnknownKey)
    );
    assert_eq!(
        source.fetches(),
        2,
        "past the bound, one unknown kid refetches once"
    );
}

#[test]
fn refusal_is_typed() {
    let signer = key("k1");
    let impostor = key("k1");
    let verifier =
        Verifier::new(policy(), Rotating::holding(&[&signer])).expect("a runnable policy");
    let good = claims();
    let hs256 = encode(
        &{
            let mut header = Header::new(Algorithm::HS256);
            header.kid = Some("k1".to_owned());
            header
        },
        &good,
        &EncodingKey::from_secret(b"a shared secret the guard never admits"),
    )
    .expect("an HS256 token");

    let cases: Vec<(&str, String, RefusalReason)> = vec![
        (
            "not a JWS",
            "not.a.token".to_owned(),
            RefusalReason::Malformed,
        ),
        (
            "an algorithm the guard does not admit",
            hs256,
            RefusalReason::Malformed,
        ),
        (
            "no sub",
            sign(&signer, "k1", &with(good.clone(), "sub", Value::Null)),
            RefusalReason::Malformed,
        ),
        (
            "another issuer",
            sign(
                &signer,
                "k1",
                &with(good.clone(), "iss", json!("https://other.example.test")),
            ),
            RefusalReason::IssuerMismatch,
        ),
        (
            "another issuer, under a kid the set lacks",
            sign(
                &signer,
                "k7",
                &with(good.clone(), "iss", json!("https://other.example.test")),
            ),
            RefusalReason::IssuerMismatch,
        ),
        (
            "an unknown key",
            sign(&signer, "k9", &good),
            RefusalReason::UnknownKey,
        ),
        (
            "signed by another key under a published kid",
            sign(&impostor, "k1", &good),
            RefusalReason::InvalidSignature,
        ),
        (
            "another audience",
            sign(
                &signer,
                "k1",
                &with(good.clone(), "aud", json!(["billing"])),
            ),
            RefusalReason::AudienceMismatch,
        ),
        (
            "expired past the skew",
            sign(&signer, "k1", &with(good.clone(), "exp", json!(NOW - 31))),
            RefusalReason::Expired,
        ),
        (
            "not yet valid past the skew",
            sign(&signer, "k1", &with(good.clone(), "nbf", json!(NOW + 31))),
            RefusalReason::NotYetValid,
        ),
        (
            "an email in no listed domain",
            sign(
                &signer,
                "k1",
                &with(good.clone(), "email", json!("eve@elsewhere.test")),
            ),
            RefusalReason::IdentityNotAllowed,
        ),
        (
            "an unverified email in a listed domain",
            sign(
                &signer,
                "k1",
                &with(good.clone(), "email_verified", json!(false)),
            ),
            RefusalReason::IdentityNotAllowed,
        ),
        (
            "no email at all",
            sign(&signer, "k1", &with(good.clone(), "email", Value::Null)),
            RefusalReason::IdentityNotAllowed,
        ),
    ];
    for (name, token, reason) in cases {
        let refusal = verifier
            .verify_at(&token, at(NOW))
            .expect_err(&format!("{name} is refused"));
        assert_eq!(refusal.reason, reason, "{name}");
        // The refusal is the contract's `mandate.guard.Refused`, on the wire as the
        // scenarios name it.
        assert_eq!(
            serde_json::to_value(&refusal).expect("a serializable refusal"),
            json!({ "reason": serde_json::to_value(&reason).expect("a reason") }),
            "{name}"
        );
    }

    // The skew admits what is just inside it.
    assert_eq!(
        outcome(
            &verifier,
            &sign(&signer, "k1", &with(good.clone(), "exp", json!(NOW - 29))),
            NOW
        ),
        Ok(())
    );
    assert_eq!(
        outcome(
            &verifier,
            &sign(&signer, "k1", &with(good, "nbf", json!(NOW + 29))),
            NOW
        ),
        Ok(())
    );
}

#[test]
fn allowed_identity_reaches_the_service() {
    let signer = key("k1");
    let verifier =
        Verifier::new(policy(), Rotating::holding(&[&signer])).expect("a runnable policy");

    // Listed by email, outside every listed domain, with the matched audience in a list.
    let listed = with(
        with(claims(), "email", json!("Grace@Partner.test")),
        "aud",
        json!(["billing", AUDIENCE]),
    );
    let identity = verifier
        .verify_at(&sign(&signer, "k1", &listed), at(NOW))
        .expect("a listed email is admitted");
    assert_eq!(identity.subject.0, "u-1");
    assert_eq!(
        identity.email,
        Presence::Present(MandateGuardEmailAddress("Grace@Partner.test".to_owned()))
    );
    assert!(identity.email_verified);
    assert_eq!(identity.audience.0, AUDIENCE);
    assert_eq!(
        identity
            .groups
            .iter()
            .map(|group| group.0.as_str())
            .collect::<Vec<_>>(),
        ["staff"]
    );

    // Admitted by its domain.
    let by_domain = verifier
        .verify_at(
            &sign(
                &signer,
                "k1",
                &with(claims(), "email", json!("ada@EXAMPLE.test")),
            ),
            at(NOW),
        )
        .expect("an email in a listed domain is admitted");
    assert_eq!(by_domain.subject.0, "u-1");
}

#[test]
fn an_empty_allow_rule_admits_every_verified_token() {
    let signer = key("k1");
    let mut open = policy();
    open.allow = AllowRule {
        emails: Vec::new(),
        domains: Vec::new(),
    };
    let verifier = Verifier::new(open, Rotating::holding(&[&signer])).expect("a runnable policy");
    let identity = verifier
        .verify_at(
            &sign(&signer, "k1", &with(claims(), "email", Value::Null)),
            at(NOW),
        )
        .expect("an empty rule admits a token with no email");
    assert_eq!(identity.email, Presence::Absent);
    assert!(!identity.email_verified);
}

#[test]
fn a_policy_that_cannot_run_is_refused() {
    let source = Rotating::default;
    let mut skew = policy();
    skew.clock_skew = "PT10M".to_owned();
    assert_eq!(
        Verifier::new(skew, source()).err(),
        Some(PolicyError::ClockSkewTooLarge)
    );

    let mut spelled = policy();
    spelled.clock_skew = "thirty seconds".to_owned();
    assert!(matches!(
        Verifier::new(spelled, source()).err(),
        Some(PolicyError::ClockSkew(_))
    ));

    let mut deaf = policy();
    deaf.audiences.clear();
    assert_eq!(
        Verifier::new(deaf, source()).err(),
        Some(PolicyError::NoAudience)
    );

    let mut negative = policy();
    negative.limits.burst = (-1).into();
    assert_eq!(
        Verifier::new(negative, source()).err(),
        Some(PolicyError::NegativeLimit("burst"))
    );
}

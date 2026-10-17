//! Security review of the token guard: a signing key the issuer withdrew from its JWK Set.
//!
//! An OpenID Provider retires a key for rotation and revokes one in an emergency
//! (`systems/mandate/domains/credential.yaml`, header). Either way the key leaves the issuer's
//! JWK Set. A guard that keeps admitting tokens signed by it, for as long as the process runs,
//! makes the emergency revocation ineffective at every service door it guards.
//!
//! The verifier refetches the set only for an unknown `kid`, so a withdrawn key whose `kid`
//! is already cached is never looked up again while every other token names a cached `kid`
//! too. This case states the bound: a day after the issuer withdrew a key, a token it signs
//! is refused.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair};
use jsonwebtoken::jwk::{Jwk, JwkSet};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::{Value, json};

use mandate_client::verify::{FetchError, JwksSource, Verifier};
use mandate_client::{AllowRule, GuardLimits, GuardPolicy, Refusal, RefusalReason};
use mandate_contract::types::{MandateCoreAudience, MandateCoreIssuer};

const ISSUER: &str = "https://idp.example.test";
const AUDIENCE: &str = "orders";
const NOW: u64 = 1_767_603_600;
const DAY: u64 = 86_400;

fn at(seconds: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(seconds)
}

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

fn sign(key: &Key, kid: &str, now: u64) -> String {
    let claims: Value = json!({
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "u-1",
        "iat": now,
        "nbf": now,
        "exp": now + 3600,
    });
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(kid.to_owned());
    encode(&header, &claims, &key.encoding).expect("a signed token")
}

fn policy() -> GuardPolicy {
    GuardPolicy {
        issuer: MandateCoreIssuer(ISSUER.to_owned()),
        audiences: vec![MandateCoreAudience(AUDIENCE.to_owned())],
        allow: AllowRule {
            emails: Vec::new(),
            domains: Vec::new(),
        },
        limits: GuardLimits {
            per_minute: 60.into(),
            burst: 10.into(),
            queue: 32.into(),
        },
        clock_skew: "PT30S".to_owned(),
    }
}

#[derive(Clone, Default)]
struct Published {
    set: Arc<Mutex<Vec<Jwk>>>,
    fetches: Arc<AtomicUsize>,
}

impl Published {
    fn publish(&self, keys: &[&Key]) {
        *self.set.lock().expect("the set lock") =
            keys.iter().map(|key| key.published.clone()).collect();
    }
}

impl JwksSource for Published {
    fn fetch(&self) -> Result<JwkSet, FetchError> {
        self.fetches.fetch_add(1, Ordering::SeqCst);
        Ok(JwkSet {
            keys: self.set.lock().expect("the set lock").clone(),
        })
    }
}

fn outcome(verifier: &Verifier<Published>, token: &str, now: u64) -> Result<(), Refusal> {
    verifier.verify_at(token, at(now)).map(|_| ())
}

#[test]
fn a_key_the_issuer_withdrew_is_refused_within_a_day() {
    let withdrawn = key("k1");
    let current = key("k2");
    let source = Published::default();
    source.publish(&[&withdrawn, &current]);
    let verifier = Verifier::new(policy(), source.clone())
        .expect("a runnable policy")
        .with_refresh_interval(Duration::from_secs(30));

    // Both published keys are in use: the guard holds both.
    assert_eq!(
        outcome(&verifier, &sign(&withdrawn, "k1", NOW), NOW),
        Ok(())
    );
    assert_eq!(outcome(&verifier, &sign(&current, "k2", NOW), NOW), Ok(()));

    // The issuer revokes k1 in an emergency: the set it publishes holds k2 alone.
    source.publish(&[&current]);

    // Ordinary traffic signed by k2 keeps flowing for a day.
    for hour in 1..=24 {
        let now = NOW + hour * 3600;
        assert_eq!(outcome(&verifier, &sign(&current, "k2", now), now), Ok(()));
    }

    // A day later, a token signed by the withdrawn key is not admitted.
    let later = NOW + DAY;
    assert_eq!(
        outcome(&verifier, &sign(&withdrawn, "k1", later), later),
        Err(Refusal {
            reason: RefusalReason::UnknownKey
        }),
        "a key the issuer withdrew a day ago still verifies; the cached set was fetched {} time(s)",
        source.fetches.load(Ordering::SeqCst)
    );
}

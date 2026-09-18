//! The canonical type conformance suite.
//!
//! A realized type declares its samples and the wire forms it must refuse; [`check`]
//! decides serialization, decoding and determinism for it. The crate-level suites in
//! `tests/` decide the result against `generated/schema/types`, so a case here cannot
//! drift from the ESS projection without a test failing.

use serde::Serialize;
use serde::de::DeserializeOwned;

/// A realized `mandate.core` type, with the samples its conformance case uses.
pub trait Canonical: Serialize + DeserializeOwned + PartialEq + core::fmt::Debug + Sized {
    /// The ESS model name this type realizes.
    const ESS_NAME: &'static str;
    /// Wire forms the contract does not declare, which decoding must refuse.
    const REJECTED_WIRE: &'static [&'static str];
    /// At least one sample; a type with variants or optional fields declares each.
    fn samples() -> Vec<Self>;

    /// The declared wire form of this value.
    ///
    /// The default is the serde serialization, which is what the projection declares for
    /// every accepted type but two. A transient credential type overrides it: its
    /// `Serialize` is redacted, so that no container can carry its material onto the wire
    /// by accident, and its declared form is reachable only through this named call.
    ///
    /// # Errors
    ///
    /// Returns the serializer's error when the value cannot be rendered.
    fn encode(&self) -> serde_json::Result<String> {
        serde_json::to_string(self)
    }

    /// Read the declared wire form.
    ///
    /// # Errors
    ///
    /// Returns the deserializer's error when `text` is not the declared form.
    fn decode(text: &str) -> serde_json::Result<Self> {
        serde_json::from_str(text)
    }
}

/// The first declared sample of a canonical type.
///
/// # Panics
///
/// Panics when a type declares no sample, which [`check`] also refuses.
#[must_use]
pub fn first_sample<T: Canonical>() -> T {
    T::samples()
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("{}: no sample declared", T::ESS_NAME))
}

/// The outcome of one type's conformance case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Case {
    /// The ESS model name the case covers.
    pub ess_name: &'static str,
    /// The canonical wire form of each declared sample, in declaration order.
    pub encoded: Vec<String>,
}

/// One type's entry in a crate's conformance registry.
#[derive(Debug, Clone, Copy)]
pub struct Entry {
    /// The ESS model name the entry covers.
    pub ess_name: &'static str,
    produce: fn() -> Case,
}

impl Entry {
    /// The registry entry for a canonical type.
    #[must_use]
    pub fn of<T: Canonical>() -> Self {
        Self {
            ess_name: <T as Canonical>::ESS_NAME,
            produce: check::<T>,
        }
    }

    /// Run the entry's case.
    #[must_use]
    pub fn run(&self) -> Case {
        (self.produce)()
    }
}

/// Serialize, decode and re-serialize every declared sample, and refuse every wire form
/// the contract does not declare.
///
/// # Panics
///
/// Panics with the ESS model name when a type declares no sample, when serialization is
/// not deterministic, when a round trip loses a value, or when an undeclared wire form
/// is accepted.
#[must_use]
pub fn check<T: Canonical>() -> Case {
    let name = <T as Canonical>::ESS_NAME;
    let samples = T::samples();
    assert!(!samples.is_empty(), "{name}: no sample declared");

    let mut encoded = Vec::with_capacity(samples.len());
    for sample in &samples {
        let first = sample
            .encode()
            .unwrap_or_else(|error| panic!("{name}: serialization failed: {error}"));
        let second = sample
            .encode()
            .unwrap_or_else(|error| panic!("{name}: serialization failed: {error}"));
        assert_eq!(first, second, "{name}: serialization is not deterministic");

        let decoded = T::decode(&first)
            .unwrap_or_else(|error| panic!("{name}: decoding {first} failed: {error}"));
        assert!(
            decoded == *sample,
            "{name}: decoding {first} did not recover the sample"
        );

        let again = decoded
            .encode()
            .unwrap_or_else(|error| panic!("{name}: serialization failed: {error}"));
        assert_eq!(first, again, "{name}: the wire form is not a fixed point");

        encoded.push(first);
    }

    for wire in <T as Canonical>::REJECTED_WIRE {
        assert!(
            T::decode(wire).is_err(),
            "{name}: accepted the undeclared wire form {wire}"
        );
    }

    reject_null_for_every_declared_field::<T>(&encoded);

    Case {
        ess_name: name,
        encoded,
    }
}

/// No field the projection declares is nullable: each is a `$ref` to a non-nullable type,
/// and an optional field says "no value" by being absent from the object.
///
/// This walks the keys of each encoded sample rather than a hand-written list, so a record
/// cannot gain a field that tolerates `null` without a case appearing for it. A record with
/// optional fields declares samples for both the absent and the present state, so every
/// declared field of that record is reached.
fn reject_null_for_every_declared_field<T: Canonical>(encoded: &[String]) {
    let name = <T as Canonical>::ESS_NAME;
    for sample in encoded {
        let Ok(serde_json::Value::Object(object)) = serde_json::from_str(sample) else {
            continue;
        };
        for key in object.keys() {
            let mut mutated = object.clone();
            mutated.insert(key.clone(), serde_json::Value::Null);
            let wire = serde_json::Value::Object(mutated).to_string();
            assert!(
                T::decode(&wire).is_err(),
                "{name}: accepted an explicit null for the declared field {key}: {wire}"
            );
        }
    }
}

/// Every conformance entry this crate declares.
#[must_use]
pub fn entries() -> Vec<Entry> {
    let mut all = Vec::new();
    all.extend(crate::identifier::entries());
    all.extend(crate::text::entries());
    all.extend(crate::credential::entries());
    all.extend(crate::enumeration::entries());
    all.extend(crate::record::entries());
    all.extend(crate::union::entries());
    all
}

/// Run every conformance entry this crate declares.
#[must_use]
pub fn cases() -> Vec<Case> {
    entries().iter().map(Entry::run).collect()
}

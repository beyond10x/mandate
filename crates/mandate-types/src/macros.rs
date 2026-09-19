//! The declaration forms for the accepted `mandate.core` types.
//!
//! Each form emits the type, its persistence marking and its conformance entry
//! together. A type therefore cannot be declared without being accounted for, and the
//! transient form is the only one that omits [`crate::PersistedValue`].

/// Declare the accepted `newtype of Uuid` identifiers.
macro_rules! canonical_uuid_identifiers {
    ($($name:ident),+ $(,)?) => {
        $(
            #[doc = concat!("`mandate.core.", stringify!($name), "`.")]
            #[doc = ""]
            #[doc = "A distinct identifier over a UUID value. It shares its wire form with"]
            #[doc = "every other UUID identifier and its Rust type with none of them."]
            #[derive(
                Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash,
                ::serde::Serialize, ::serde::Deserialize,
            )]
            #[serde(transparent)]
            pub struct $name($crate::value::Uuid);

            impl $name {
                #[doc = "Wrap a UUID value that is already parsed."]
                #[must_use]
                pub const fn new(value: $crate::value::Uuid) -> Self {
                    Self(value)
                }

                #[doc = "The wrapped UUID value."]
                #[must_use]
                pub const fn as_uuid(&self) -> &$crate::value::Uuid {
                    &self.0
                }

                #[doc = "Parse the lexical form declared by the contract."]
                #[doc = ""]
                #[doc = "# Errors"]
                #[doc = ""]
                #[doc = "Returns [`crate::ParseError::Uuid`] when the form is not declared."]
                pub fn parse(text: &str) -> ::core::result::Result<Self, $crate::ParseError> {
                    ::core::result::Result::Ok(Self($crate::value::Uuid::parse(text)?))
                }
            }

            impl ::core::fmt::Display for $name {
                fn fmt(&self, formatter: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                    ::core::fmt::Display::fmt(&self.0, formatter)
                }
            }

            impl ::core::str::FromStr for $name {
                type Err = $crate::ParseError;

                fn from_str(text: &str) -> ::core::result::Result<Self, Self::Err> {
                    Self::parse(text)
                }
            }

            impl $crate::PersistedValue for $name {}

            impl $crate::conformance::Canonical for $name {
                const ESS_NAME: &'static str = concat!("mandate.core.", stringify!($name));
                const REJECTED_WIRE: &'static [&'static str] = &[
                    "\"not-a-uuid\"",
                    "\"\"",
                    "\"1b4e28ba2fa14d8eb1b08c1d4e5f6a7b\"",
                    "\"1b4e28ba-2fa1-4d8e-b1b0-8c1d4e5f6a7\"",
                    "0",
                    "null",
                    "[]",
                ];

                fn samples() -> ::std::vec::Vec<Self> {
                    ::std::vec![Self($crate::value::Uuid::from_bytes([
                        0x1b, 0x4e, 0x28, 0xba, 0x2f, 0xa1, 0x4d, 0x8e,
                        0xb1, 0xb0, 0x8c, 0x1d, 0x4e, 0x5f, 0x6a, 0x7b,
                    ]))]
                }
            }
        )+

        pub(crate) fn entries() -> ::std::vec::Vec<$crate::conformance::Entry> {
            ::std::vec![$($crate::conformance::Entry::of::<$name>()),+]
        }
    };
}

/// Declare the accepted `newtype of String` types.
macro_rules! canonical_text_newtypes {
    ($($name:ident),+ $(,)?) => {
        $(
            #[doc = concat!("`mandate.core.", stringify!($name), "`.")]
            #[doc = ""]
            #[doc = "The projection declares an unconstrained string; no pattern is enforced"]
            #[doc = "because none is declared."]
            #[derive(
                Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash,
                ::serde::Serialize, ::serde::Deserialize,
            )]
            #[serde(transparent)]
            pub struct $name(String);

            impl $name {
                #[doc = "Carry a value of this type."]
                #[must_use]
                pub fn new(text: impl Into<String>) -> Self {
                    Self(text.into())
                }

                #[doc = "The carried value."]
                #[must_use]
                pub fn as_str(&self) -> &str {
                    &self.0
                }
            }

            impl ::core::fmt::Display for $name {
                fn fmt(&self, formatter: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                    formatter.write_str(&self.0)
                }
            }

            impl $crate::PersistedValue for $name {}

            impl $crate::conformance::Canonical for $name {
                const ESS_NAME: &'static str = concat!("mandate.core.", stringify!($name));
                const REJECTED_WIRE: &'static [&'static str] =
                    &["0", "null", "[]", "{}", "true"];

                fn samples() -> ::std::vec::Vec<Self> {
                    ::std::vec![Self(String::from(stringify!($name))), Self(String::new())]
                }
            }
        )+

        pub(crate) fn entries() -> ::std::vec::Vec<$crate::conformance::Entry> {
            ::std::vec![$($crate::conformance::Entry::of::<$name>()),+]
        }
    };
}

/// Declare the transient `newtype of Bytes` types.
///
/// This form is the only one that does not implement [`crate::PersistedValue`]. It
/// marks [`crate::Transient`] instead, renders a redacted `Debug`, and offers no
/// `Display`.
macro_rules! canonical_transient_bytes {
    ($($name:ident),+ $(,)?) => {
        $(
            #[doc = concat!("`mandate.core.", stringify!($name), "`, a transient boundary value.")]
            #[doc = ""]
            #[doc = "It is returned at a boundary and never stored. Two separate things hold"]
            #[doc = "it there, and neither is the whole guarantee on its own:"]
            #[doc = ""]
            #[doc = "- It does not implement [`crate::PersistedValue`], and no other crate can"]
            #[doc = "  add that impl for it, so a record declared through"]
            #[doc = "  [`crate::canonical_record`] cannot name it as a field type, nor as"]
            #[doc = "  `Option<_>` or `Vec<_>` of it. A downstream crate can still define its"]
            #[doc = "  own wrapper over it and implement [`crate::PersistedValue`] for that"]
            #[doc = "  wrapper; the orphan rule permits it and the compile-time half does not"]
            #[doc = "  reach it."]
            #[doc = "- Its `Serialize` renders [`crate::REDACTED`] rather than the material,"]
            #[doc = "  so a container that does launder it past the first half still cannot"]
            #[doc = "  put the material on a record's wire form."]
            #[doc = ""]
            #[doc = "The declared base64 form is reachable, and these are all the routes to"]
            #[doc = "it. None is derived; each has to be named:"]
            #[doc = ""]
            #[doc = "- [`crate::conformance::Canonical::encode`], the conformance suite's"]
            #[doc = "  rendering."]
            #[doc = "- `mandate_proto::WireContract::to_wire`, which delegates to it. Both"]
            #[doc = "  transient types are among the 74 contracts `mandate-proto` declares,"]
            #[doc = "  because the projection names them from commands and responses, and"]
            #[doc = "  `mandate-client` and `mandate-server` depend on that crate."]
            #[doc = "- [`crate::value::declared_credential_form`], named at a field with"]
            #[doc = "  `#[serde(serialize_with = ...)]` by a container that must carry the"]
            #[doc = "  material."]
            #[doc = ""]
            #[doc = "An earlier revision claimed the first was the only one. It was not."]
            #[derive(Clone, PartialEq, Eq)]
            pub struct $name(Vec<u8>);

            impl $name {
                #[doc = "Carry material across a boundary."]
                #[must_use]
                pub fn from_bytes(bytes: Vec<u8>) -> Self {
                    Self(bytes)
                }

                #[doc = "Read the carried material. Named for what it does."]
                #[must_use]
                pub fn expose_bytes(&self) -> &[u8] {
                    &self.0
                }

                #[doc = "Parse the base64 lexical form declared by the contract."]
                #[doc = ""]
                #[doc = "# Errors"]
                #[doc = ""]
                #[doc = "Returns [`crate::ParseError::Base64`] when the form is not declared."]
                pub fn parse_base64(text: &str) -> ::core::result::Result<Self, $crate::ParseError> {
                    ::core::result::Result::Ok(Self($crate::value::decode_base64(text)?))
                }
            }

            impl ::core::fmt::Debug for $name {
                fn fmt(&self, formatter: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                    formatter.write_str(concat!(stringify!($name), "(<redacted>)"))
                }
            }

            impl ::serde::Serialize for $name {
                #[doc = "Renders the redaction marker, never the material."]
                #[doc = ""]
                #[doc = "`Serialize` is reached by every container that derives it, including"]
                #[doc = "one declared outside this crate over a type parameter. It therefore"]
                #[doc = "cannot tell a boundary from a record, and a transient value that"]
                #[doc = "reaches it is by definition on a path this crate did not sanction."]
                #[doc = "The declared base64 form is reached instead by naming one of the"]
                #[doc = "three routes listed on this type, none of which is derived."]
                fn serialize<S: ::serde::Serializer>(
                    &self,
                    serializer: S,
                ) -> ::core::result::Result<S::Ok, S::Error> {
                    serializer.serialize_str($crate::REDACTED)
                }
            }

            impl<'de> ::serde::Deserialize<'de> for $name {
                fn deserialize<D: ::serde::Deserializer<'de>>(
                    deserializer: D,
                ) -> ::core::result::Result<Self, D::Error> {
                    let text = String::deserialize(deserializer)?;
                    Self::parse_base64(&text).map_err(::serde::de::Error::custom)
                }
            }

            impl $crate::Transient for $name {
                fn expose_material(&self) -> &[u8] {
                    &self.0
                }
            }

            impl $crate::conformance::Canonical for $name {
                const ESS_NAME: &'static str = concat!("mandate.core.", stringify!($name));
                const REJECTED_WIRE: &'static [&'static str] =
                    &["\"not base64!\"", "\"A\"", "\"=AAA\"", "\"AAAB\\u0021\"", "0", "null"];

                fn samples() -> ::std::vec::Vec<Self> {
                    ::std::vec![
                        Self(::std::vec::Vec::new()),
                        Self(b"abc".to_vec()),
                        Self(::std::vec![0xff, 0xfe]),
                    ]
                }

                fn encode(&self) -> ::serde_json::Result<String> {
                    ::serde_json::to_string(&$crate::value::encode_base64(&self.0))
                }
            }
        )+

        pub(crate) fn entries() -> ::std::vec::Vec<$crate::conformance::Entry> {
            ::std::vec![$($crate::conformance::Entry::of::<$name>()),+]
        }
    };
}

/// Declare the accepted `enum` types.
macro_rules! canonical_enums {
    ($($name:ident { $($variant:ident),+ $(,)? }),+ $(,)?) => {
        $(
            #[doc = concat!("`mandate.core.", stringify!($name), "`.")]
            #[derive(
                Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash,
                ::serde::Serialize, ::serde::Deserialize,
            )]
            pub enum $name {
                $(
                    #[doc = concat!("The declared `", stringify!($variant), "` variant.")]
                    $variant,
                )+
            }

            impl $name {
                #[doc = "Every variant the contract declares, in declaration order."]
                pub const VARIANTS: &'static [Self] = &[$(Self::$variant),+];
            }

            impl $crate::PersistedValue for $name {}

            impl $crate::conformance::Canonical for $name {
                const ESS_NAME: &'static str = concat!("mandate.core.", stringify!($name));
                const REJECTED_WIRE: &'static [&'static str] =
                    &["\"MandateUndeclaredVariant\"", "\"\"", "0", "null", "{}"];

                fn samples() -> ::std::vec::Vec<Self> {
                    Self::VARIANTS.to_vec()
                }
            }
        )+

        pub(crate) fn entries() -> ::std::vec::Vec<$crate::conformance::Entry> {
            ::std::vec![$($crate::conformance::Entry::of::<$name>()),+]
        }
    };
}

/// Declare the accepted `union` types as the tagged value the contract declares.
macro_rules! canonical_unions {
    ($($name:ident { $($tag:literal => $variant:ident($inner:ty)),+ $(,)? }),+ $(,)?) => {
        $(
            #[doc = concat!("`mandate.core.", stringify!($name), "`, a tagged union.")]
            #[doc = ""]
            #[doc = "The wire form is the declared `kind`/`value` pair. The tag selects a"]
            #[doc = "referenced type; it never carries a number."]
            #[derive(Debug, Clone, PartialEq, Eq, ::serde::Serialize, ::serde::Deserialize)]
            #[serde(tag = "kind", content = "value", deny_unknown_fields)]
            pub enum $name {
                $(
                    #[doc = concat!("The declared `", $tag, "` variant.")]
                    #[serde(rename = $tag)]
                    $variant($inner),
                )+
            }

            impl $crate::PersistedValue for $name {}

            impl $crate::conformance::Canonical for $name {
                const ESS_NAME: &'static str = concat!("mandate.core.", stringify!($name));
                const REJECTED_WIRE: &'static [&'static str] = &[
                    "{\"kind\":\"mandate-undeclared\",\"value\":\"1b4e28ba-2fa1-4d8e-b1b0-8c1d4e5f6a7b\"}",
                    "{\"kind\":\"generation\",\"value\":7}",
                    "\"principal\"",
                    "0",
                    "null",
                ];

                fn samples() -> ::std::vec::Vec<Self> {
                    ::std::vec![
                        $(Self::$variant($crate::conformance::first_sample::<$inner>())),+
                    ]
                }
            }
        )+

        pub(crate) fn entries() -> ::std::vec::Vec<$crate::conformance::Entry> {
            ::std::vec![$($crate::conformance::Entry::of::<$name>()),+]
        }
    };
}

/// Account for a canonical record and prove every field of it may be persisted.
///
/// The struct itself is written out, because the field order and the optional-field
/// attributes follow the contract. This form supplies what the contract decides about
/// it: the ESS name, the [`crate::PersistedValue`] marking, the conformance samples,
/// and a check that each field is itself persistable.
///
/// The field list is destructured without `..`, so a field added to the struct and not
/// named here does not compile, and a field named here whose type is transient does not
/// compile either.
///
/// What that guarantees, exactly: no field of a record declared this way can be
/// [`crate::CredentialSecret`] or [`crate::CredentialProof`], nor `Option` or `Vec` of
/// one, because [`crate::PersistedValue`] is not implemented for them and the orphan rule
/// stops any other crate adding it *for those types*. It does not stop a crate declaring
/// its own wrapper — `struct Envelope<T>(T)` — and implementing [`crate::PersistedValue`]
/// for `Envelope<CredentialSecret>`: that is a local type, so the impl is permitted and
/// this macro admits the field. The material still does not reach the record's wire form,
/// because the transient types serialize as [`crate::REDACTED`]; that is the half of the
/// boundary a wrapper cannot route around.
///
/// ```
/// use mandate_types::{Audience, PrincipalId};
///
/// #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
/// pub struct Ticket {
///     pub subject: PrincipalId,
///     pub audience: Audience,
/// }
///
/// mandate_types::canonical_record!(Ticket { subject, audience }, samples: vec![Ticket {
///     subject: PrincipalId::parse("1b4e28ba-2fa1-4d8e-b1b0-8c1d4e5f6a7b").unwrap(),
///     audience: Audience::new("mandate"),
/// }]);
/// ```
#[macro_export]
macro_rules! canonical_record {
    ($name:ident { $($field:ident),+ $(,)? }, samples: $samples:expr) => {
        impl $crate::PersistedValue for $name {}

        const _: () = {
            fn persistable<T: $crate::PersistedValue + ?Sized>(_: &T) {}

            #[allow(dead_code)]
            fn every_field_is_persistable(record: &$name) {
                let $name { $($field),+ } = record;
                $( persistable($field); )+
            }
        };

        impl $crate::conformance::Canonical for $name {
            const ESS_NAME: &'static str = concat!("mandate.core.", stringify!($name));
            const REJECTED_WIRE: &'static [&'static str] =
                &["{\"mandate-undeclared-field\":true}", "0", "null", "[]", "\"\""];

            fn samples() -> ::std::vec::Vec<Self> {
                $samples
            }
        }
    };
}

/// Record which ESS elements a crate realizes, and prove each named symbol still exists.
///
/// A crate invokes this once, at its root, listing every element of the contract it
/// implements against the Rust item that implements it:
///
/// ```text
/// mandate_types::realizes! {
///     "mandate.federation.AuthenticateFederation" => crate::authenticate::authenticate_federation,
///     "mandate.federation.FederationAuthenticated" => crate::record::FederationEvent,
/// }
/// ```
///
/// It expands to two things. Each entry becomes an anonymous `const` that imports the
/// named symbol and discards it, so **a registry entry whose symbol was renamed, moved or
/// deleted does not compile**. And the whole list becomes
///
/// ```text
/// pub const ESS_REALIZATIONS: &[(&str, &str)];
/// ```
///
/// pairing each ESS element with the written path of the symbol, which is what
/// `cargo xtask coverage` (a later story) reads out of each crate through that crate's own
/// lib test. The coverage step compares the union of these registries against the elements
/// the compiled model declares and reports what nothing realizes.
///
/// # Why the registry is checked by the compiler and not by the reader
///
/// A hand-maintained list of names is a list that drifts, and it drifts silently in the one
/// direction that matters: an entry survives the deletion of what it names, so coverage
/// reports an element as realized by a symbol that is no longer there. Nothing downstream
/// can tell that from a real realization, because both are strings. Touching the symbol at
/// compile time makes that specific drift a build failure rather than an overstated
/// coverage report. It says nothing about whether the symbol is *correct* for the element —
/// that is what `story:conformance-target` measures, by running the contract's own suite.
///
/// # What may appear on the right
///
/// Any item path: a function, a type, a constant, a static, a trait. The entry is expanded
/// into a `use`, so an associated item — `Type::method` — is not a path this accepts, and
/// neither is a path that is private to another module. Both are compile errors at the
/// invocation, naming the entry.
///
/// ```
/// mandate_types::realizes! {
///     "mandate.core.PrincipalId" => mandate_types::PrincipalId,
///     "mandate.core.Audience" => mandate_types::Audience,
/// }
///
/// assert_eq!(
///     ESS_REALIZATIONS,
///     [
///         ("mandate.core.PrincipalId", "mandate_types::PrincipalId"),
///         ("mandate.core.Audience", "mandate_types::Audience"),
///     ]
/// );
/// ```
#[macro_export]
macro_rules! realizes {
    ($($entry:tt)*) => {
        $crate::__realizes!(@accumulate [] $($entry)*);
    };
}

/// The entry-by-entry reader behind [`realizes!`]: an entry written `@ Type::method` names an
/// associated function, which `use` cannot name, so the compiler proves it by taking it as a
/// value; every other entry is a type, an enum variant or a free function and is proven by a
/// `use`. The pairs accumulate into the one `ESS_REALIZATIONS` constant.
#[doc(hidden)]
#[macro_export]
macro_rules! __realizes {
    (@accumulate [$($acc:tt)*] $element:literal => @ $method:path, $($rest:tt)*) => {
        const _: () = {
            let _ = $method;
        };
        $crate::__realizes!(@accumulate [$($acc)* ($element, stringify!($method)),] $($rest)*);
    };
    (@accumulate [$($acc:tt)*] $element:literal => @ $method:path) => {
        $crate::__realizes!(@accumulate [$($acc)*] $element => @ $method,);
    };
    (@accumulate [$($acc:tt)*] $element:literal => $symbol:path, $($rest:tt)*) => {
        const _: () = {
            #[allow(unused_imports)]
            use $symbol as _;
        };
        $crate::__realizes!(@accumulate [$($acc)* ($element, stringify!($symbol)),] $($rest)*);
    };
    (@accumulate [$($acc:tt)*] $element:literal => $symbol:path) => {
        $crate::__realizes!(@accumulate [$($acc)*] $element => $symbol,);
    };
    (@accumulate [$($acc:tt)*]) => {
        #[doc = "Every ESS element this crate realizes, paired with the symbol that realizes it."]
        #[doc = ""]
        #[doc = "Written by [`mandate_types::realizes!`](mandate_types::realizes); read by"]
        #[doc = "`cargo xtask coverage` through this crate's own lib test. An entry written"]
        #[doc = "`@ Type::method` names an associated function as the realization."]
        pub const ESS_REALIZATIONS: &[(&str, &str)] = &[$($acc)*];
    };
}

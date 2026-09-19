//! The representation seam: ESS [`Node`] values in, the crates' own types out.
//!
//! Everything crossing the target interface crosses here, and the whole point of the
//! module is what it refuses to do. It builds **no** payload by hand. An event reaches the
//! runner by being serialized through the `Serialize` derive its own crate wrote — the
//! same derive `crates/*/tests/emitted_events.rs` validates against the closed schema — so
//! a field the crate renamed, dropped or spelled differently reaches the report renamed,
//! dropped or spelled differently. A payload assembled here from the handler's return
//! values would agree with the suite for as long as this file and the crate agreed, which
//! is the one failure a conformance run cannot detect from its own output.
//!
//! The same rule runs the other way. An input is not read field by field into a loosely
//! typed bag: each declared field is deserialized into the *declared field's own Rust
//! type* ([`field`]), which is what refuses a uuid that is not one and a timestamp that
//! names no instant before any handler sees it. The input struct the handler is then
//! called with is the crate's own.

use std::collections::BTreeMap;

use ess_conformance::scenario::{CommandRef, ErrorRef, EventRef, OutcomeRef};
use ess_conformance::target::{ObservedEvent, TargetError};
use ess_primitives::ids::CorrelationId;
use ess_primitives::node::Node;
use serde::Serialize;
use serde::de::DeserializeOwned;

/// A [`Node`] as the JSON value `serde` reads and writes.
///
/// `Node` is `#[serde(untagged)]`, so this is the identity on the document and not a
/// translation table that could drift from one.
///
/// # Errors
///
/// Returns [`TargetError::Unavailable`] when the node holds a number no JSON value can
/// carry.
pub fn to_json(node: &Node) -> Result<serde_json::Value, TargetError> {
    // An integral number is written as the integer it names, and the reason is a real
    // reading of a real suite: `--suite-format 5` compiles `generation: 0` on an ESS
    // `Integer` field to the JSON token `0.0`, which `Node` carries as a number and
    // `serde_json` will not deserialize into an `i64`. The contract declares the field an
    // integer, the suite means the integer, and a decoder that refused it would report a
    // schema refusal for a value the specification admits. A number with a fractional part
    // is left exactly as it is, so nothing is rounded into a different value.
    if let Node::Number(number) = node
        && number.is_integral()
        && let Some(exact) = number.as_i64()
    {
        return Ok(serde_json::Value::from(exact));
    }
    serde_json::to_value(node).map_err(|error| {
        TargetError::unavailable("reading a suite value", format!("{node:?}: {error}"))
    })
}

/// A JSON value as the [`Node`] the runner compares against the suite.
///
/// # Errors
///
/// Returns [`TargetError::Unavailable`] when the value holds a number the domain node
/// cannot carry.
pub fn to_node(value: serde_json::Value) -> Result<Node, TargetError> {
    serde_json::from_value(value)
        .map_err(|error| TargetError::unavailable("rendering a value", error.to_string()))
}

/// One declared input field, as the declared field's own Rust type.
///
/// # Errors
///
/// Returns [`TargetError::Unavailable`] when the field is absent or when its value is not
/// one the declared type admits — a uuid that is not canonical, an enumeration variant the
/// contract does not declare. Not a [`TargetError::Unsupported`]: the target supports the
/// command, and not a declared refusal either, because the suite handed it something the
/// contract's own schema refuses.
pub fn field<T: DeserializeOwned>(
    input: &BTreeMap<String, Node>,
    name: &str,
) -> Result<T, TargetError> {
    let node = input
        .get(name)
        .ok_or_else(|| absent(name))
        .and_then(to_json)?;
    serde_json::from_value(node).map_err(|error| {
        TargetError::unavailable(format!("reading the input `{name}`"), error.to_string())
    })
}

/// One declared input field that the contract makes optional.
///
/// An absent field and a present `null` are the same answer here and only here: the
/// contract's optionals are written `skip_serializing_if`, so a producer may spell an
/// absent value either way and a target that read them differently would deny for the
/// spelling rather than for the value.
///
/// # Errors
///
/// Returns [`TargetError::Unavailable`] when a present value is not one the declared type
/// admits.
pub fn optional<T: DeserializeOwned>(
    input: &BTreeMap<String, Node>,
    name: &str,
) -> Result<Option<T>, TargetError> {
    match input.get(name) {
        None | Some(Node::Null) => Ok(None),
        Some(node) => {
            let value = to_json(node)?;
            serde_json::from_value(value).map(Some).map_err(|error| {
                TargetError::unavailable(format!("reading the input `{name}`"), error.to_string())
            })
        }
    }
}

/// The payload of one emitted event, through the emitting crate's own `Serialize`.
///
/// # Errors
///
/// Returns [`TargetError::Unavailable`] when the event does not serialize as an object,
/// which would mean the crate's derive no longer renders a declared payload.
pub fn payload(event: &impl Serialize) -> Result<BTreeMap<String, Node>, TargetError> {
    let value = serde_json::to_value(event).map_err(|error| {
        TargetError::unavailable("serializing an emitted event", error.to_string())
    })?;
    let serde_json::Value::Object(fields) = value else {
        return Err(TargetError::unavailable(
            "serializing an emitted event",
            "the crate's own `Serialize` did not render a declared payload object",
        ));
    };
    fields
        .into_iter()
        .map(|(name, value)| to_node(value).map(|node| (name, node)))
        .collect()
}

/// One occurrence of a declared event, as the crate that emitted it renders it.
///
/// # Errors
///
/// Returns [`TargetError::Unavailable`] when the name is not a declared event reference or
/// the payload does not serialize.
pub fn observed(
    name: &str,
    event: &impl Serialize,
    correlation: &CorrelationId,
    sequence: u64,
) -> Result<ObservedEvent, TargetError> {
    let mut observed = ObservedEvent::new(event_ref(name)?)
        .in_activity(correlation.clone())
        .at(sequence);
    observed.payload = payload(event)?;
    Ok(observed)
}

/// One declared response field, rendered from the value the handler returned.
///
/// # Errors
///
/// Returns [`TargetError::Unavailable`] when the value does not serialize.
pub fn response_field(value: &impl Serialize) -> Result<Node, TargetError> {
    let value = serde_json::to_value(value).map_err(|error| {
        TargetError::unavailable("serializing a command response", error.to_string())
    })?;
    to_node(value)
}

/// A declared response, by field name.
///
/// # Errors
///
/// Returns [`TargetError::Unavailable`] when a value does not serialize.
pub fn response(
    fields: &[(&str, &dyn erased::Value)],
) -> Result<BTreeMap<String, Node>, TargetError> {
    fields
        .iter()
        .map(|(name, value)| value.node().map(|node| ((*name).to_owned(), node)))
        .collect()
}

/// Rendering one response field without naming its type at the call site.
///
/// `response` takes a list of differently typed values, and a generic parameter cannot
/// carry a heterogeneous list. The trait is object-safe and has one blanket implementation,
/// so every `Serialize` the crates publish is admitted and nothing here decides how a value
/// is written.
pub mod erased {
    use ess_conformance::target::TargetError;
    use ess_primitives::node::Node;

    /// A value a declared response field carries.
    pub trait Value {
        /// The value, rendered exactly as its own `Serialize` writes it.
        ///
        /// # Errors
        ///
        /// Returns [`TargetError::Unavailable`] when the value does not serialize.
        fn node(&self) -> Result<Node, TargetError>;
    }

    impl<T: serde::Serialize> Value for T {
        fn node(&self) -> Result<Node, TargetError> {
            super::response_field(self)
        }
    }
}

/// The declared event reference a name denotes.
///
/// # Errors
///
/// Returns [`TargetError::Unavailable`] when the name is not a well-formed reference,
/// which is a defect in this crate rather than a condition a caller can act on — and is
/// reported rather than panicked, because a target that aborts the process reports nothing
/// at all.
pub fn event_ref(name: &str) -> Result<EventRef, TargetError> {
    name.parse().map_err(|error: ess_primitives::ParseError| {
        TargetError::unavailable(format!("naming the event `{name}`"), error.to_string())
    })
}

/// The declared command reference a name denotes.
///
/// # Errors
///
/// Returns [`TargetError::Unavailable`] when the name is not a well-formed reference.
pub fn command_ref(name: &str) -> Result<CommandRef, TargetError> {
    name.parse().map_err(|error: ess_primitives::ParseError| {
        TargetError::unavailable(format!("naming the command `{name}`"), error.to_string())
    })
}

/// The declared error reference a name denotes.
///
/// # Errors
///
/// Returns [`TargetError::Unavailable`] when the name is not a well-formed reference.
pub fn error_ref(name: &str) -> Result<ErrorRef, TargetError> {
    name.parse().map_err(|error: ess_primitives::ParseError| {
        TargetError::unavailable(format!("naming the error `{name}`"), error.to_string())
    })
}

/// One branch of one command.
///
/// # Errors
///
/// Returns [`TargetError::Unavailable`] when either name is not well formed.
pub fn outcome_ref(command: &str, branch: &str) -> Result<OutcomeRef, TargetError> {
    let branch = branch
        .parse()
        .map_err(|error: ess_primitives::ParseError| {
            TargetError::unavailable(format!("naming the outcome `{branch}`"), error.to_string())
        })?;
    Ok(OutcomeRef::new(command_ref(command)?, branch))
}

/// The refusal for an input field the suite did not supply.
fn absent(name: &str) -> TargetError {
    TargetError::unavailable(
        format!("reading the input `{name}`"),
        "the suite supplied no value for a field the contract declares",
    )
}

#[cfg(test)]
mod tests {
    use super::{field, observed, optional, payload, to_json, to_node};
    use ess_primitives::ids::CorrelationId;
    use ess_primitives::node::Node;
    use mandate_types::{OrganizationId, Timestamp};
    use std::collections::BTreeMap;

    /// A field is read as the declared type, and a value that type refuses is refused here
    /// rather than reaching a handler.
    ///
    /// The second half is the one that matters: a target that passed an unparseable uuid
    /// through would report the handler's refusal of it as the declared denial the suite
    /// asserts, which is a pass for the wrong reason.
    #[test]
    fn an_input_field_is_read_as_the_type_the_contract_declares() {
        let mut input = BTreeMap::new();
        input.insert(
            "organization".to_owned(),
            Node::Text("00000000-0000-4000-8000-d6e5803f2cb9".to_owned()),
        );
        input.insert("bad".to_owned(), Node::Text("not-a-uuid".to_owned()));
        let organization: OrganizationId =
            field(&input, "organization").expect("a canonical uuid is read");
        assert_eq!(
            organization.to_string(),
            "00000000-0000-4000-8000-d6e5803f2cb9"
        );
        assert!(
            field::<OrganizationId>(&input, "bad").is_err(),
            "a value the declared type refuses was admitted"
        );
        assert!(
            field::<OrganizationId>(&input, "absent").is_err(),
            "an absent field was admitted"
        );
        assert_eq!(
            optional::<OrganizationId>(&input, "absent").expect("an absent optional reads"),
            None
        );
        assert_eq!(
            optional::<OrganizationId>(&BTreeMap::from([("x".to_owned(), Node::Null)]), "x")
                .expect("a null optional reads"),
            None
        );
    }

    /// An event's payload is whatever its own `Serialize` writes, field for field.
    #[test]
    fn an_event_payload_is_its_own_serialization() {
        let event = mandate_identity::SecurityEpochRecorded {
            target: mandate_types::SecurityEpochTarget::Organization(OrganizationId::new(
                mandate_types::Uuid::from_bytes([7; 16]),
            )),
            generation: mandate_identity::Generation::ZERO,
        };
        let payload = payload(&event).expect("the crate's derive renders its payload");
        assert!(
            payload.contains_key("generation") && payload.contains_key("target"),
            "the payload lost a declared field: {payload:?}"
        );
        let correlation = CorrelationId::new("c").expect("a correlation");
        let occurrence = observed(
            "mandate.identity.SecurityEpochRecorded",
            &event,
            &correlation,
            3,
        )
        .expect("the occurrence renders");
        assert_eq!(occurrence.sequence, Some(3));
        assert_eq!(occurrence.payload, payload);
    }

    /// The node bridge is the identity on a document, both ways.
    #[test]
    fn the_node_bridge_round_trips_a_document() {
        let timestamp = Timestamp::new("2026-01-01T00:00:00Z");
        let node = to_node(serde_json::to_value(&timestamp).expect("a timestamp serializes"))
            .expect("a timestamp is a node");
        assert_eq!(node, Node::Text("2026-01-01T00:00:00Z".to_owned()));
        assert_eq!(
            to_json(&node).expect("a node is a value"),
            serde_json::json!("2026-01-01T00:00:00Z")
        );
    }
}

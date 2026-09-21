//! Adversary pass 2 against `story:conformance-target`, after correction round 1.
//!
//! Correction round 1 answered the pass-1 finding "21 of 23 `armed` rows are inert" by
//! giving every substituted reader a consultation counter and deriving the row's `kind`
//! from it. The module documentation of `crates/mandate-conformance/src/external.rs` is
//! where that answer is written down, and it is the document these cases are driven
//! against — the unit wrote both the document and the reader, and nothing in
//! `tests/target.rs` compares the two.
//!
//! Three sentences of that document are the subject:
//!
//! 1. ":33" — "Every substituted reader therefore counts its own consultations and its own
//!    refusals".
//! 2. ":46" — "a substituted reader answers **absence** for every read whose signature can
//!    express one ... which is exactly what the standing fold answers when it is empty".
//! 3. ":750" — of [`Substituted`]'s `GraphRead::check`: "The answer
//!    `mandate_graph::double::GraphDouble` gives for a resource it holds no entry for — an
//!    absence, not a decision about the caller".
//!
//! Each case calls the reader the sentence is about and compares it with the standing
//! reader the sentence names. Nothing here is constructed: every reader is the one
//! `Live::open` builds, at the value `Live::open` builds it with.

use mandate_conformance::FIXED_INSTANT;
use mandate_conformance::external::{ScenarioKeys, Substituted};
use mandate_federation::ConnectionStore;
use mandate_graph::double::GraphDouble;
use mandate_graph::port::{GraphError, GraphQuery, GraphRead};
use mandate_identity::{IdentityLog, IdentityRead};
use mandate_sts::keys::{KeyMaterialResolver, SigningKeyReads};
use mandate_types::{
    Audience, AuthoritySubject, AuthzRevision, CorrelationId, CredentialId, Issuer, KeyReference,
    OrganizationId, PrincipalId, ResourceId, ResourceRef, ResourceType, SessionId, Timestamp, Uuid,
    VerifiedContext,
};

/// A canonical identity from one byte, so two runs of a case name the same thing.
fn identity(tag: u8) -> Uuid {
    let mut bytes = [tag; 16];
    bytes[6] = 0x40 | (bytes[6] & 0x0f);
    bytes[8] = 0x80 | (bytes[8] & 0x3f);
    Uuid::from_bytes(bytes)
}

/// The verified context the synthesized `Check` scenario carries, in the shape the suite
/// hands it over: a subject and an organization no fold was ever told about.
fn context() -> VerifiedContext {
    VerifiedContext {
        subject: PrincipalId::new(identity(0x11)),
        actor: None,
        organization: OrganizationId::new(identity(0x12)),
        audience: Audience::new("context.audience".to_owned()),
        credential: CredentialId::new(identity(0x13)),
        delegation: None,
        execution: None,
        correlation: CorrelationId::new("context.correlation".to_owned()),
    }
}

/// The resource reference the synthesized `Check` scenario names.
fn resource() -> ResourceRef {
    ResourceRef {
        resource_type: ResourceType::new("resource.resource_type"),
        resource_id: ResourceId::new(identity(0x14)),
    }
}

/// Every read this reader answers is counted, which is what the row's `consulted` means.
///
/// `external.rs:33` — "Every substituted reader therefore counts its own consultations and
/// its own refusals, and the row carries both in its `kind` and its `consulted`" — and
/// `external.rs:41`, which defines `armed-unreached` as "the arming lapsed without a reader
/// ever being consulted: the command refused, or decided, before reading anything".
///
/// A port method that answers without counting makes those two sentences disagree with the
/// document they produce: the reader answered, the handler acted on the answer, and the row
/// reports that nothing was ever asked. `injections.json` in a run of the frozen suite
/// carries nine `armed-unreached` rows, and no reader of that file can tell an arming that
/// reached nothing from one that reached a method which does not count.
#[test]
fn every_port_method_of_the_substituted_reader_counts_the_read_it_answered() {
    let mut uncounted: Vec<&str> = Vec::new();

    let reader = Substituted::new();
    let _ = ConnectionStore::enabled_for_issuer(
        &reader,
        &Issuer::new("https://issuer.example".to_owned()),
    );
    if reader.consulted() == 0 {
        uncounted.push("mandate_federation::ConnectionStore::enabled_for_issuer");
    }

    let reader = Substituted::new();
    let _ = IdentityRead::resolve(&reader, &SessionId::new(identity(0x21)));
    if reader.consulted() == 0 {
        uncounted.push("mandate_identity::IdentityRead::resolve");
    }

    let reader = Substituted::new();
    let _ = SigningKeyReads::signing_keys(&reader);
    if reader.consulted() == 0 {
        uncounted.push("mandate_sts::keys::SigningKeyReads::signing_keys");
    }

    let reader = Substituted::new();
    let _ = KeyMaterialResolver::thumbprint(&reader, &KeyReference::new("key_reference"));
    if reader.consulted() == 0 {
        uncounted.push("mandate_sts::keys::KeyMaterialResolver::thumbprint");
    }

    assert!(
        uncounted.is_empty(),
        "these port methods of `Substituted` answer a handler without counting the read, \
         so a command that consults only them leaves its `injections.json` row at \
         `armed-unreached` and `consulted: 0` — which `external.rs:41` defines as an arming \
         that reached nothing: {uncounted:#?}"
    );
}

/// `mandate.credential.RegisterSigningKey` is the reachable instance of the uncounted read.
///
/// The port `injections.json` names for this command is
/// `mandate_sts::keys::KeyMaterialResolver`, and `services/sts/src/keys.rs:204` is the one
/// call: `material.thumbprint(&input.key_reference).ok_or_else(|| …
/// KeyReferenceUnresolvable)?`. Armed, `commands::credential::register_signing_key` passes
/// `&Substituted` there; unarmed it passes `live.key_material`, which is [`ScenarioKeys`].
///
/// So the arming decides the clause — and the reader that decided it reports that it was
/// never consulted. The row reads `armed-unreached`, `consulted: 0`.
#[test]
fn the_key_material_resolver_the_arming_substitutes_counts_the_read_that_decides_the_clause() {
    let reference = KeyReference::new("key_reference");
    let standing = KeyMaterialResolver::thumbprint(&ScenarioKeys, &reference);
    let reader = Substituted::new();
    let armed = KeyMaterialResolver::thumbprint(&reader, &reference);

    assert!(
        standing.is_some(),
        "the standing resolver answered nothing, so this case is not about the port it \
         claims to be about"
    );
    assert_ne!(
        standing, armed,
        "the substitution did not change the answer, so there is nothing to count"
    );
    assert!(
        reader.consulted() > 0,
        "`Substituted` answered `{armed:?}` where the standing `ScenarioKeys` answers \
         `{standing:?}` — the arming alone produces `KeyReferenceUnresolvable` at \
         `services/sts/src/keys.rs:204` — and counted no read, so \
         `mandate.credential.RegisterSigningKey`'s row is written `armed-unreached` with \
         `consulted: 0`: the document says the reader was never asked"
    );
}

/// The substituted reader answers what the standing reader answers, or the row's label is
/// unsound.
///
/// `external.rs:46` states the rule the `armed` / `armed-standing` split rests on: absence
/// wherever the signature expresses one, a refusal only where it cannot, "which is exactly
/// what the standing fold answers when it is empty". `Ledger::consulted`
/// (`external.rs:171`) then derives `armed-standing` from `refused == 0` alone — it never
/// consults the standing reader — so the label "every answer it gave was one the standing
/// reader gives too" is true only if that rule holds at every port.
///
/// It does not hold at the two ports whose standing reader is not an empty fold.
#[test]
fn the_substituted_reader_answers_what_the_standing_reader_of_that_port_answers() {
    let mut diverged: Vec<String> = Vec::new();

    // `mandate_sts::keys::KeyMaterialResolver`, whose standing double is `ScenarioKeys` —
    // named as such in `external.rs`'s own `STANDING` table. It resolves every reference.
    //
    // Coordinator amendment (pass 2 ruling on F2): `ScenarioKeys` is a standing double that
    // is *not* an empty store, so the rule "a substituted absence is what an empty real store
    // answers" does not compare against it. The substituted resolver keeps answering absence
    // — that absence is the arming (`KeyReferenceUnresolvable`) — and the divergence from the
    // standing double is declared, in `external.rs`'s doc and here, rather than closed. The
    // sibling case above asserts the same inequality from the other side.
    let reference = KeyReference::new("key_reference");
    let standing = KeyMaterialResolver::thumbprint(&ScenarioKeys, &reference);
    let substituted = KeyMaterialResolver::thumbprint(&Substituted::new(), &reference);
    assert_ne!(
        standing, substituted,
        "the standing `ScenarioKeys` resolves every reference and the substituted resolver \
         answers absence; were they equal, arming `RegisterSigningKey` would inject nothing"
    );

    // `mandate_identity::IdentityRead::as_of`, which `mandate_identity::refresh_session`
    // fails closed on (`session.rs:331`). The standing log is the one `Live::open` builds:
    // `IdentityLog::new().with_as_of(FIXED_INSTANT)`.
    let log = IdentityLog::new().with_as_of(Timestamp::new(FIXED_INSTANT));
    let standing = IdentityRead::as_of(&log);
    let substituted = IdentityRead::as_of(&Substituted::new());
    if standing != substituted {
        diverged.push(format!(
            "mandate_identity::IdentityRead::as_of: the standing log answers \
             `{standing:?}`, substituted answers `{substituted:?}`"
        ));
    }

    assert!(
        diverged.is_empty(),
        "a substituted reader's absence is what an empty real store answers; at these ports \
         the substituted answer is one the empty standing reader never gives: {diverged:#?}"
    );
}

/// The graph answer the module documents is the one the standing double gives.
///
/// `external.rs:750` justifies `Substituted`'s `GraphRead::check` answering
/// `CouldNotAnswer(ResourceUnresolved)` as "The answer `mandate_graph::double::GraphDouble`
/// gives for a resource it holds no entry for — an absence, not a decision about the caller
/// — so a `Check` armed at this port is recorded `armed-standing` when the standing double
/// held nothing, which is what it means."
///
/// `GraphDouble::new()` opens at revision `0` (`double.rs:71`), so `require_revision` passes
/// for the `AuthzRevision("0")` floor `commands::authz` states, and `check` then refuses at
/// `admits` (`double.rs:357`) with `GraphError::Denied(DenialReason::Denied)` — a decision,
/// which `double.rs:483` says in as many words. The two answers carry different declared
/// reasons: `GraphError::denial_reason` maps `CouldNotAnswer` to `Unavailable` and `Denied`
/// to the reason it carries (`port.rs:121`).
#[test]
fn the_substituted_graph_read_answers_what_the_standing_graph_double_answers() {
    let context = context();
    let resource = resource();
    let subject = AuthoritySubject::Principal(context.subject);
    let query = GraphQuery {
        context: &context,
        subject: &subject,
        resource: &resource,
        relation: "action",
    };
    let minimum = AuthzRevision::new("0".to_owned());

    let standing = GraphRead::check(&GraphDouble::new(), &query, &minimum);
    let substituted = GraphRead::check(&Substituted::new(), &query, &minimum);

    let reason = |answer: &Result<mandate_graph::port::Observed, GraphError>| match answer {
        Ok(_) => "allowed".to_owned(),
        Err(refusal) => format!("{:?} -> {:?}", refusal, refusal.denial_reason()),
    };

    assert_eq!(
        reason(&standing),
        reason(&substituted),
        "`external.rs:750` says the substituted `check` answers what an empty \
         `GraphDouble` answers for a resource it holds no entry for, and that the answer is \
         \"an absence, not a decision about the caller\". The standing double decides \
         against the caller and the substituted reader reports an outage, so an armed \
         `Check` that reached this port would be answered with a declared reason the \
         standing run never produces — and `Ledger::consulted` would still write the row \
         `armed-standing`, because `Substituted::check` counts no refusal"
    );
}

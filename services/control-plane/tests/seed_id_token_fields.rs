//! The deployment documents carry the two ID-token choices into the records they seed: a
//! connection's subject format (fork F1) and a client's ID-token signing algorithm (fork F8).
//!
//! Each document is read the way `serve` reads it and admitted through the seeding the binary
//! uses, so what is asserted is the event the fold would record, not the reader's struct.

use std::path::Path;

use mandate_control_plane::adapters::{
    ClientSeed, ClientSeeding, ConnectionSeed, ConnectionSeeding, SeedRefused,
};
use mandate_federation::record::FederationEvent;
use mandate_types::{DexConnectorId, IdTokenSigningAlgorithm, SubjectFormat, Uuid};

const CONNECTION: &str = "c0c0c0c0-c0c0-4c0c-8c0c-c0c0c0c0c0c0";
const CLIENT: &str = "c1c1c1c1-c1c1-4c1c-8c1c-c1c1c1c1c1c1";
const ORGANIZATION: &str = "0a0a0a0a-0a0a-4a0a-8a0a-0a0a0a0a0a0a";

fn connection(extra: &str) -> ConnectionSeed {
    serde_json::from_str(&format!(
        r#"{{"connection_id":"{CONNECTION}","organization":"{ORGANIZATION}",
          "issuer":"https://idp.example","client_id":"mandate-at-idp",
          "tenant_resolution":{{"configured_organization":"{ORGANIZATION}"}},
          "jit_provisioning":false{extra}}}"#
    ))
    .expect("a connection document serve reads")
}

fn client_document(extra: &str) -> String {
    format!(
        r#"{{"client_id":"{CLIENT}","organization":"{ORGANIZATION}","client_type":"public",
          "redirect_uris":["https://client.example/callback"],"pkce_method":"S256"{extra}}}"#
    )
}

fn allocate() -> Uuid {
    unreachable!("every document states its identity")
}

/// The subject format and replaced connector id the seeded creation event records.
fn seeded_subject(
    seed: &ConnectionSeed,
) -> Result<(SubjectFormat, Option<DexConnectorId>), SeedRefused> {
    let seeded =
        ConnectionSeeding::new().admit(Path::new("connection.json"), seed, &mut allocate)?;
    match seeded.events.as_slice() {
        [
            FederationEvent::FederationConnectionCreated {
                subject_format,
                replaced_connector_id,
                ..
            },
        ] => Ok((*subject_format, replaced_connector_id.clone())),
        other => panic!("one creation event: {other:?}"),
    }
}

/// The ID-token algorithm the seeded registration event records.
fn seeded_algorithm(body: &str) -> Option<IdTokenSigningAlgorithm> {
    let seed: ClientSeed = serde_json::from_str(body).expect("a client document serve reads");
    let seeded = ClientSeeding::new()
        .admit(Path::new("client.json"), &seed, &mut allocate)
        .expect("a public client is admitted");
    match seeded.events.as_slice() {
        [
            FederationEvent::OAuthClientRegistered {
                id_token_signed_response_alg,
                ..
            },
        ] => *id_token_signed_response_alg,
        other => panic!("one registration event: {other:?}"),
    }
}

#[test]
fn a_connection_document_stating_no_subject_format_seeds_the_mandate_principal_format() {
    assert_eq!(
        seeded_subject(&connection("")).ok(),
        Some((SubjectFormat::MandatePrincipal, None))
    );
}

#[test]
fn a_dex_compatible_connection_document_seeds_its_format_and_replaced_connector() {
    let seed = connection(r#","subject_format":"DexCompatible","replaced_connector_id":"mock""#);

    assert_eq!(
        seeded_subject(&seed).ok(),
        Some((
            SubjectFormat::DexCompatible,
            Some(DexConnectorId::new("mock"))
        ))
    );
}

#[test]
fn a_dex_compatible_connection_document_without_a_replaced_connector_is_refused() {
    let refused = seeded_subject(&connection(r#","subject_format":"DexCompatible""#))
        .expect_err("the command refuses a DexCompatible format with no connector id");
    let SeedRefused::Unregistrable { denied, .. } = &refused else {
        panic!("the command's own refusal, got {refused:?}");
    };
    assert_eq!(format!("{:?}", denied.clause), "SubjectFormatMismatch");
}

#[test]
fn a_mandate_principal_connection_document_naming_a_replaced_connector_is_refused() {
    let refused = seeded_subject(&connection(r#","replaced_connector_id":"mock""#))
        .expect_err("the command refuses a replaced connector id without DexCompatible");
    let SeedRefused::Unregistrable { denied, .. } = &refused else {
        panic!("the command's own refusal, got {refused:?}");
    };
    assert_eq!(format!("{:?}", denied.clause), "SubjectFormatMismatch");
}

#[test]
fn a_subject_format_the_contract_does_not_declare_is_not_read() {
    let read = serde_json::from_str::<ConnectionSeed>(&format!(
        r#"{{"connection_id":"{CONNECTION}","organization":"{ORGANIZATION}",
          "issuer":"https://idp.example","client_id":"mandate-at-idp",
          "tenant_resolution":{{"configured_organization":"{ORGANIZATION}"}},
          "jit_provisioning":false,"subject_format":"Pairwise"}}"#
    ));
    assert!(read.is_err(), "an undeclared subject format is refused");
}

#[test]
fn a_client_document_stating_no_algorithm_seeds_none_and_es256_seeds_es256() {
    assert_eq!(seeded_algorithm(&client_document("")), None);
    assert_eq!(
        seeded_algorithm(&client_document(
            r#","id_token_signed_response_alg":"ES256""#
        )),
        Some(IdTokenSigningAlgorithm::ES256)
    );
    assert_eq!(
        seeded_algorithm(&client_document(
            r#","id_token_signed_response_alg":"RS256""#
        )),
        Some(IdTokenSigningAlgorithm::RS256)
    );
}

#[test]
fn an_id_token_algorithm_the_contract_does_not_declare_is_not_read() {
    for undeclared in ["HS256", "none", "es256"] {
        let body = client_document(&format!(
            r#","id_token_signed_response_alg":"{undeclared}""#
        ));
        assert!(
            serde_json::from_str::<ClientSeed>(&body).is_err(),
            "`{undeclared}` is refused"
        );
    }
}

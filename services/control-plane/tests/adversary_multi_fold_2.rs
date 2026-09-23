//! Adversarial pass 2 on `story:control-plane-multi-fold-writes`.
//!
//! The correction makes `ConnectionSeeding::admit` fold a document into a copy and swap it in
//! only once every event is accepted. The first case attacks the swap itself: a refused
//! document between two admitted ones must keep what the earlier one seeded, and the
//! refusals that name an incumbent file must still name it. The second case attacks the
//! document contract `src/main.rs` states for `--connection` — a set this process cannot
//! serve is refused before the socket, not seeded and printed as seeded — with the one link
//! identity the seeding never compares across documents.

use std::path::{Path, PathBuf};

use mandate_control_plane::adapters::{ConnectionSeed, ConnectionSeeding, SeedRefused};
use mandate_federation::record::Projection;

const ORG_X: &str = "0a0a0a0a-0a0a-0a0a-0a0a-0a0a0a0a0a0a";
const ORG_Y: &str = "0b0b0b0b-0b0b-0b0b-0b0b-0b0b0b0b0b0b";
const CONN_A: &str = "c0c0c0c0-c0c0-c0c0-c0c0-c0c0c0c0c0c0";
const CONN_B: &str = "c1c1c1c1-c1c1-c1c1-c1c1-c1c1c1c1c1c1";
const CONN_C: &str = "c2c2c2c2-c2c2-c2c2-c2c2-c2c2c2c2c2c2";
const CONN_D: &str = "c3c3c3c3-c3c3-c3c3-c3c3-c3c3c3c3c3c3";
const PRINCIPAL_P: &str = "51515151-5151-5151-5151-515151515151";
const PRINCIPAL_Q: &str = "52525252-5252-5252-5252-525252525252";
const LINK: &str = "e0e0e0e0-e0e0-e0e0-e0e0-e0e0e0e0e0e0";

fn document(
    connection: &str,
    organization: &str,
    issuer: &str,
    principal: &str,
    subject: &str,
    external_principal_id: Option<&str>,
) -> ConnectionSeed {
    let stated_link = external_principal_id
        .map(|id| format!(r#""external_principal_id":"{id}","#))
        .unwrap_or_default();
    serde_json::from_str(&format!(
        r#"{{"connection_id":"{connection}","organization":"{organization}",
          "issuer":"{issuer}","client_id":"mandate-at-idp",
          "tenant_resolution":{{"configured_organization":"{organization}"}},
          "jit_provisioning":false,
          "link":{{"principal_id":"{principal}",{stated_link}"subject":"{subject}",
                   "linked_at":"2026-09-01T00:00:00Z"}}}}"#
    ))
    .expect("a connection document serve reads")
}

fn allocator() -> impl FnMut() -> mandate_types::Uuid {
    let mut minted = 0xd0_u8;
    move || {
        minted = minted.wrapping_add(1);
        mandate_types::Uuid::from_bytes([minted; 16])
    }
}

/// A refused document between two admitted ones loses nothing the first seeded, keeps
/// nothing of its own, and leaves both incumbent-naming refusals naming `a.json`.
#[test]
fn a_refused_document_keeps_what_earlier_documents_seeded() {
    let mut allocate = allocator();
    let mut seeding = ConnectionSeeding::new();

    seeding
        .admit(
            Path::new("a.json"),
            &document(CONN_A, ORG_X, "https://a.example", PRINCIPAL_P, "p", None),
            &mut allocate,
        )
        .expect("the first document is admitted");
    let refused = seeding
        .admit(
            Path::new("b.json"),
            &document(CONN_B, ORG_X, "https://b.example", PRINCIPAL_Q, " q", None),
            &mut allocate,
        )
        .expect_err("an untrimmed subject is not a history the fold reads");
    assert!(
        matches!(refused, SeedRefused::Unseedable { .. }),
        "{refused:?}"
    );

    let repeated = seeding
        .admit(
            Path::new("c.json"),
            &document(CONN_A, ORG_X, "https://c.example", PRINCIPAL_Q, "q", None),
            &mut allocate,
        )
        .expect_err("a.json's connection survives b.json's refusal");
    assert!(
        matches!(
            &repeated,
            SeedRefused::RepeatedConnectionId { path, incumbent, .. }
                if path == &PathBuf::from("c.json") && incumbent == &PathBuf::from("a.json")
        ),
        "{repeated:?}"
    );

    let across = seeding
        .admit(
            Path::new("d.json"),
            &document(CONN_C, ORG_Y, "https://d.example", PRINCIPAL_P, "p", None),
            &mut allocate,
        )
        .expect_err("a.json's link survives b.json's refusal");
    assert!(
        matches!(
            &across,
            SeedRefused::PrincipalAcrossOrganizations { incumbent, .. }
                if incumbent == &PathBuf::from("a.json")
        ),
        "{across:?}"
    );

    // b.json placed Q in ORG_X only in the copy it was refused with.
    seeding
        .admit(
            Path::new("e.json"),
            &document(CONN_D, ORG_Y, "https://e.example", PRINCIPAL_Q, "q", None),
            &mut allocate,
        )
        .expect("b.json's refused link placed its principal nowhere");
    seeding
        .admit(
            Path::new("b-corrected.json"),
            &document(CONN_B, ORG_Y, "https://b.example", PRINCIPAL_Q, "q", None),
            &mut allocate,
        )
        .expect("b.json's refused connection was not kept");
}

/// Two documents stating one `external_principal_id` are both admitted today, and the
/// second document's link is recorded nowhere: the fold writes a link insert-if-absent at
/// its own identity. Every other stated identity a seeding reads (`connection_id`,
/// `client_id`, `resource_server_id`, `kid`) is refused naming both files; this one is
/// seeded, printed, and denied at every login through the second connection.
///
/// **This pins the open defect, not the wanted behaviour.** It is filed as
/// `story:seeding-repeated-external-principal-id`; when that story lands, the second
/// document must be refused naming both files, and this case must flip to assert that.
#[test]
fn two_documents_stating_one_link_identity_are_both_admitted_until_refused() {
    let mut allocate = allocator();
    let mut seeding = ConnectionSeeding::new();

    let first = seeding
        .admit(
            Path::new("a.json"),
            &document(
                CONN_A,
                ORG_X,
                "https://a.example",
                PRINCIPAL_P,
                "p",
                Some(LINK),
            ),
            &mut allocate,
        )
        .expect("the first document is admitted");
    let second = seeding.admit(
        Path::new("b.json"),
        &document(
            CONN_B,
            ORG_X,
            "https://b.example",
            PRINCIPAL_Q,
            "q",
            Some(LINK),
        ),
        &mut allocate,
    );

    // What the deployment would hold if both were admitted: main.rs records every event of
    // every admitted document into one federation fold.
    let mut fold = Projection::default();
    for event in first
        .events
        .iter()
        .chain(second.iter().flat_map(|seeded| seeded.events.iter()))
    {
        fold.apply(event)
            .expect("each event is a history the fold reads");
    }
    let held: Vec<String> = fold
        .links()
        .iter()
        .map(|link| format!("{}@{}", link.subject.as_str(), link.connection_id))
        .collect();

    const PENDING: &str = "today's state until story:seeding-repeated-external-principal-id \
                           lands; then b.json must be refused and this case must flip to \
                           assert the refusal";
    assert!(second.is_ok(), "b.json is admitted ({PENDING}): {second:?}");
    assert_eq!(
        fold.links()
            .iter()
            .map(|link| (link.subject.as_str().to_owned(), link.connection_id))
            .collect::<Vec<_>>(),
        vec![("p".to_owned(), first.connection_id)],
        "the fold holds only a.json's link ({PENDING}); held {held:?}"
    );
}

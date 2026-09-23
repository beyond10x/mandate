//! Adversarial pass 1 on `story:control-plane-multi-fold-writes`.
//!
//! A fourth multi-event write site in `services/control-plane/src/adapters.rs` that the story
//! does not list: `ConnectionSeeding::admit` applies the connection's creation and then its
//! link to the seeding's mirror fold one event at a time, so a link the fold refuses
//! (`FoldError::SubjectNotTrimmed`) leaves the connection applied behind a refused document.

use std::path::Path;

use mandate_control_plane::adapters::{ConnectionSeed, ConnectionSeeding, SeedRefused};

const CONNECTION: &str = "c0c0c0c0-c0c0-c0c0-c0c0-c0c0c0c0c0c0";
const ORGANIZATION: &str = "0a0a0a0a-0a0a-0a0a-0a0a-0a0a0a0a0a0a";
const PRINCIPAL: &str = "51515151-5151-5151-5151-515151515151";

fn document(subject: &str) -> ConnectionSeed {
    serde_json::from_str(&format!(
        r#"{{"connection_id":"{CONNECTION}","organization":"{ORGANIZATION}",
          "issuer":"https://idp.example","client_id":"mandate-at-idp",
          "tenant_resolution":{{"configured_organization":"{ORGANIZATION}"}},
          "jit_provisioning":false,
          "link":{{"principal_id":"{PRINCIPAL}","subject":"{subject}",
                   "linked_at":"2026-09-01T00:00:00Z"}}}}"#
    ))
    .expect("a connection document serve reads")
}

/// A document the seeding refuses leaves the seeding as it found it: the corrected document,
/// stating the same `connection_id`, is admitted rather than refused as a repeat of a
/// connection no admitted document seeded.
#[test]
fn a_refused_connection_document_seeds_no_connection() {
    let mut minted = 0xd0_u8;
    let mut allocate = || {
        minted = minted.wrapping_add(1);
        mandate_types::Uuid::from_bytes([minted; 16])
    };
    let mut seeding = ConnectionSeeding::new();

    let refused = seeding
        .admit(
            Path::new("untrimmed.json"),
            &document(" subject-1"),
            &mut allocate,
        )
        .expect_err("a link whose subject is not its own trim is not a history the fold reads");
    assert!(
        matches!(refused, SeedRefused::Unseedable { .. }),
        "{refused:?}"
    );

    let corrected = seeding.admit(
        Path::new("corrected.json"),
        &document("subject-1"),
        &mut allocate,
    );
    assert!(
        corrected.is_ok(),
        "a refused document left its connection in the seeding's fold: {corrected:?}"
    );
}

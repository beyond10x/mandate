//! The product route table, and the proof it meets the generated command surface nowhere.
//!
//! `docs/public/contracts.md:29`: generated command routes are contract projections and "do
//! not implement product routes, OAuth token exchange, authorization-code/PKCE,
//! introspection, SCIM, or federation protocols". `docs/architecture/unmapped.md` reads that
//! as a rule with teeth: no path of the form `/<domain>/commands/<Command>` may appear in the
//! product route table. `decision-blocker:guards`' fifth item is evidence that generated
//! command routes are not reachable as product endpoints, and this file is the table half of
//! it — `story:product-listener` serves this table and hardcodes no path, so what is decided
//! here is what its listener answers.
//!
//! The generated paths are read from `generated/openapi/*.yaml` at test time rather than
//! copied, so the proof is against the projection the contract actually publishes.

use std::collections::BTreeSet;
use std::fs;

use mandate_server::routes::{self, Binding, Document, Method, ROUTES, RelyingPartyStep};

const OPENAPI: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../generated/openapi");

#[test]
fn the_table_carries_the_four_road_routes_the_two_documents_and_the_three_relying_party_steps() {
    assert_eq!(ROUTES.len(), 9);
    let commands: Vec<&str> = ROUTES
        .iter()
        .filter_map(|route| match route.binds {
            Binding::Command(command) => Some(command),
            Binding::Document(_) | Binding::RelyingParty(_) => None,
        })
        .collect();
    assert_eq!(
        commands,
        vec![
            "mandate.federation.AuthenticateFederation",
            "mandate.federation.AuthorizePublicClient",
            "mandate.credential.RedeemAuthorizationCode",
            "mandate.credential.IntrospectCredential",
        ]
    );
    let documents: Vec<Document> = ROUTES
        .iter()
        .filter_map(|route| match route.binds {
            Binding::Document(document) => Some(document),
            Binding::Command(_) | Binding::RelyingParty(_) => None,
        })
        .collect();
    assert_eq!(
        documents,
        vec![Document::AuthorizationServerMetadata, Document::Jwks]
    );
    let steps: Vec<(Method, &str, RelyingPartyStep)> = ROUTES
        .iter()
        .filter_map(|route| match route.binds {
            Binding::RelyingParty(step) => Some((route.method, route.path, step)),
            Binding::Command(_) | Binding::Document(_) => None,
        })
        .collect();
    assert_eq!(
        steps,
        vec![
            (
                Method::Get,
                "/v1/federation/authorize",
                RelyingPartyStep::Authorize
            ),
            (
                Method::Get,
                "/v1/federation/callback",
                RelyingPartyStep::Callback
            ),
            (
                Method::Post,
                "/v1/federation/handoff",
                RelyingPartyStep::Handoff
            ),
        ]
    );
}

#[test]
fn every_road_route_is_reachable_by_its_command_and_by_its_method_and_path() {
    for route in ROUTES {
        assert_eq!(
            routes::lookup(route.method, route.path),
            Some(route),
            "{}",
            route.path
        );
        if let Binding::Command(command) = route.binds {
            assert_eq!(routes::route_for_command(command), Some(route), "{command}");
        }
        if let Binding::Document(document) = route.binds {
            assert_eq!(routes::route_for_document(document), Some(route));
        }
    }
    assert_eq!(routes::lookup(Method::Get, "/oauth/token"), None);
    assert_eq!(routes::lookup(Method::Post, "/nowhere"), None);
    assert_eq!(
        routes::route_for_command("mandate.tenancy.CreateTeam"),
        None
    );
}

#[test]
fn no_method_and_path_pair_is_declared_twice() {
    let pairs: BTreeSet<(Method, &str)> = ROUTES
        .iter()
        .map(|route| (route.method, route.path))
        .collect();
    assert_eq!(pairs.len(), ROUTES.len());
}

#[test]
fn the_two_document_paths_are_entries_of_this_table() {
    // Correction (c) at the wave D opening: the served documents' paths are entries of this
    // table, so the disjointness proof below covers them too.
    assert_eq!(
        routes::route_for_document(Document::AuthorizationServerMetadata)
            .unwrap()
            .path,
        "/.well-known/oauth-authorization-server"
    );
    assert_eq!(
        routes::route_for_document(Document::Jwks).unwrap().path,
        "/oauth/jwks"
    );
}

#[test]
fn the_generated_projection_publishes_sixty_one_command_routes() {
    let generated = generated_paths();
    assert_eq!(generated.len(), 61);
    for path in &generated {
        let segments: Vec<&str> = path.split('/').collect();
        assert_eq!(segments.len(), 4, "{path}");
        assert_eq!(segments[0], "", "{path}");
        assert_eq!(segments[2], "commands", "{path}");
        assert!(!segments[1].is_empty(), "{path}");
        assert!(!segments[3].is_empty(), "{path}");
    }
}

#[test]
fn the_product_table_intersects_the_generated_command_routes_nowhere() {
    let generated = generated_paths();
    let product: BTreeSet<&str> = ROUTES.iter().map(|route| route.path).collect();
    let shared: Vec<&str> = product
        .iter()
        .copied()
        .filter(|path| generated.contains(*path))
        .collect();
    assert!(
        shared.is_empty(),
        "a product route is also a generated command route: {shared:?}"
    );
}

#[test]
fn no_product_route_is_shaped_like_a_generated_command_route() {
    // Stronger than the intersection: the intersection is empty for the 61 that exist today,
    // and this holds for the ones a later contract adds.
    for route in ROUTES {
        assert!(
            !routes::is_generated_command_path(route.path),
            "{}",
            route.path
        );
    }
    assert!(routes::is_generated_command_path(
        "/federation/commands/AuthenticateFederation"
    ));
    assert!(routes::is_generated_command_path(
        "/credential/commands/RedeemAuthorizationCode"
    ));
    assert!(!routes::is_generated_command_path("/oauth/token"));
    assert!(!routes::is_generated_command_path("/commands/X"));
    assert!(!routes::is_generated_command_path("/a/commands/"));
}

#[test]
fn the_predicate_answers_for_every_generated_path_the_projection_publishes() {
    for path in generated_paths() {
        assert!(routes::is_generated_command_path(&path), "{path}");
    }
}

/// Every path the four generated OpenAPI documents publish.
fn generated_paths() -> BTreeSet<String> {
    let mut paths = BTreeSet::new();
    let mut documents = 0;
    for entry in fs::read_dir(OPENAPI).expect("the generated openapi directory") {
        let path = entry.expect("a generated document").path();
        if path.extension().is_none_or(|extension| extension != "yaml") {
            continue;
        }
        documents += 1;
        let text = fs::read_to_string(&path).expect("a generated document");
        let body = text
            .split_once("\npaths:\n")
            .expect("the paths section")
            .1
            .split_once("\ncomponents:")
            .expect("the components section")
            .0;
        for line in body.lines() {
            if let Some(route) = line.strip_prefix("  /").and_then(|r| r.strip_suffix(':')) {
                assert!(paths.insert(format!("/{route}")), "{route} twice");
            }
        }
    }
    assert_eq!(documents, 4, "the four generated documents");
    paths
}

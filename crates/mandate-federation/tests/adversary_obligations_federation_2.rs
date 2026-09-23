//! Adversary pass 2 against `story:obligations-federation`, after correction 1.
//!
//! One defect. `contracts/obligations/federation.json:575-606` publishes **all three**
//! clauses of `mandate.federation.RegisterOAuthClient` as decided on the `real` path, and
//! not one of the three refusals is decided by `mandate-federation` code.
//!
//! `crates/mandate-federation/src/register_client.rs:85-90` says so itself: the three
//! phrases of the declared denial "are judgements no crate in this crate's dependency
//! ceiling can make" and are "admitted through [`ClientRegistrationAdmission`]". The
//! handler does not compare anything; it calls the port and turns `false` into a
//! `Denied`. The implementation the three bound cases call is
//! [`ConfiguredAdmission`], which `register_client.rs:181` documents as "A fixture,
//! never a shipped implementation", and which
//! `crates/mandate-conformance/src/external.rs:248-253` registers in the workspace's own
//! `STANDING` table as **the standing double for that port** — the same table, in the
//! same terms, that carries `mandate_graph::port::GraphRead` → `GraphDouble` and
//! `mandate_policy::port::PolicyEvaluator` → `PolicyDouble`, whose clauses in
//! `contracts/obligations/graph.json` and `policy.json` carry `path: "double"`.
//!
//! `contracts/obligations/README.md` decides which column that is, and decides it against
//! the *decider* and not against the handler that reports it:
//!
//! > `double` is a stand-in **for the deciding code itself** […] An in-memory port that
//! > merely *supplies* input to a real handler leaves the row `real`: what is classified
//! > is the code that makes the decision, not the code that holds the data.
//!
//! > **A `double` row never covers a clause** […] a double refuses because it was written
//! > to refuse, so a clause whose only evidence is a double has no evidence that the
//! > shipped path refuses at all.
//!
//! [`the_three_register_o_auth_client_refusals_are_the_ports_answer_and_not_this_crates`]
//! settles which side of that line these three sit on mechanically rather than by reading:
//! it supplies a *second* implementation of the same port from this file, keeps the
//! command input and every line of `mandate-federation` byte-identical, and the three
//! refusals become acceptances. Nothing in this crate decided them.
//!
//! [`a_clause_a_standing_double_decides_is_not_published_on_the_real_path`] is the
//! failing half: the document publishes them `real`, so
//! `contracts/conformance/obligations-report.json:5` counts three double-backed clauses
//! in `real_covered`, which is the one column this registry exists to make fall.
//!
//! `xtask/src/obligations_registry.rs:876-897` reads `path` as stated and cross-checks it
//! against nothing, so the gate is green while the two documents disagree.
//!
//! # What this file does not claim
//!
//! Nothing here says the handler is wrong. `register_client.rs` keeps the right boundary:
//! an authorization decision is not this crate's to make. The claim is only about which
//! column the registry publishes the three clauses in, and therefore about whether
//! `real_covered: 79` is true.

use std::fs;
use std::path::PathBuf;

use mandate_federation::register_client::{
    ClientRegistrationAdmission, ConfiguredAdmission, RegisterOAuthClient, register_o_auth_client,
};
use mandate_federation::{DenialClause, SequentialAllocator};
use mandate_types::value::Uuid;
use mandate_types::{
    Audience, CorrelationId, CredentialId, DenialReason, OrganizationId, PkceMethod, PrincipalId,
    RedirectUri, VerifiedContext,
};

const REGISTERED: &str = "https://app.example/callback";

/// The clause rows of `mandate.federation.RegisterOAuthClient`, in document order, each
/// decided by a [`ClientRegistrationAdmission`] answer and by nothing else.
const PORT_DECIDED: [&str; 3] = [
    "Caller lacks client-administration authority",
    "a redirect URI is unadmitted",
    "organization binding is invalid",
];

// ------------------------------------------------------------------ the arrangement
//
// Identical to `crates/mandate-federation/tests/obligations.rs:479-545`, which is what
// `contracts/obligations/federation.json` names for these three clauses.

fn uuid(tag: u8) -> Uuid {
    Uuid::from_bytes([tag; 16])
}

fn organization() -> OrganizationId {
    OrganizationId::new(uuid(10))
}

fn administrator() -> PrincipalId {
    PrincipalId::new(uuid(0x51))
}

fn context() -> VerifiedContext {
    VerifiedContext {
        subject: administrator(),
        actor: None,
        organization: organization(),
        audience: Audience::new("mandate"),
        credential: CredentialId::new(uuid(0xcd)),
        delegation: None,
        execution: None,
        correlation: CorrelationId::new("adversary-obligations-federation-2"),
    }
}

fn a_registration(redirect_uris: Vec<RedirectUri>) -> RegisterOAuthClient {
    RegisterOAuthClient {
        context: context(),
        public: true,
        redirect_uris,
        pkce_method: PkceMethod::S256,
    }
}

fn one_redirect() -> Vec<RedirectUri> {
    vec![RedirectUri::new(REGISTERED)]
}

/// The set `obligations::a_redirect_uri_the_deployment_does_not_admit_is_refused` presents:
/// admitted except for its second entry.
fn two_redirects() -> Vec<RedirectUri> {
    vec![
        RedirectUri::new(REGISTERED),
        RedirectUri::new("https://app.example/other"),
    ]
}

/// A second implementation of [`ClientRegistrationAdmission`], written here and owing
/// nothing to `ConfiguredAdmission`: it admits every caller, every organization and every
/// redirect URI.
///
/// A deployment's admission is a real one of these — the port is what a deployment
/// implements — so this is not a contrived shape. It is the same port, answering the
/// other way.
struct AdmitsEverything;

impl ClientRegistrationAdmission for AdmitsEverything {
    fn admits_client_administration(&self, _context: &VerifiedContext) -> bool {
        true
    }

    fn admits_organization(&self, _organization_id: &OrganizationId) -> bool {
        true
    }

    fn admits_redirect_uri(&self, _organization_id: &OrganizationId, _uri: &RedirectUri) -> bool {
        true
    }
}

// ==================================================================================
// The premise, settled mechanically
// ==================================================================================

/// Each of the three refusals `contracts/obligations/federation.json` publishes as decided
/// on this crate's shipped path is a function of the [`ClientRegistrationAdmission`]
/// implementation alone: hold the command input and every line of `mandate-federation`
/// fixed, change only which implementation of the port is passed, and the refusal becomes
/// an acceptance.
///
/// That is the README's own test for a `double`: what is classified is "the code that
/// makes the decision, not the code that holds the data", and here the code that makes the
/// decision is outside this crate's shipped path in all three.
#[test]
fn the_three_register_o_auth_client_refusals_are_the_ports_answer_and_not_this_crates() {
    // "Caller lacks client-administration authority": the admission holds the organization
    // and the redirect and does not hold this caller.
    let missing_administrator = ConfiguredAdmission::new()
        .with_organization(organization())
        .with_redirect_uri(organization(), RedirectUri::new(REGISTERED));
    // "organization binding is invalid": no organization is admitted.
    let missing_organization = ConfiguredAdmission::new()
        .with_administrator(administrator())
        .with_redirect_uri(organization(), RedirectUri::new(REGISTERED));
    // "a redirect URI is unadmitted": the second entry of the set is not admitted.
    let missing_redirect = ConfiguredAdmission::new()
        .with_administrator(administrator())
        .with_organization(organization())
        .with_redirect_uri(organization(), RedirectUri::new(REGISTERED));

    let arranged: [(&str, &ConfiguredAdmission, Vec<RedirectUri>, DenialClause); 3] = [
        (
            PORT_DECIDED[0],
            &missing_administrator,
            one_redirect(),
            DenialClause::ClientAdministrationAuthority,
        ),
        (
            PORT_DECIDED[1],
            &missing_redirect,
            two_redirects(),
            DenialClause::RedirectUriUnadmitted,
        ),
        (
            PORT_DECIDED[2],
            &missing_organization,
            one_redirect(),
            DenialClause::OrganizationMismatch,
        ),
    ];

    for (clause, admission, redirect_uris, expected) in arranged {
        let input = a_registration(redirect_uris);

        // What the bound case in `tests/obligations.rs` asserts.
        let denied = register_o_auth_client(&input, admission, &mut SequentialAllocator::new())
            .expect_err("the fixture admission was built without this admission");
        assert_eq!(denied.clause, expected, "{clause}");
        assert!(
            matches!(
                denied.reason,
                DenialReason::Denied | DenialReason::TenantMismatch
            ),
            "{clause}"
        );

        // The same input, the same handler, the same crate — a different implementation of
        // the same port. No refusal survives.
        let registered =
            register_o_auth_client(&input, &AdmitsEverything, &mut SequentialAllocator::new());
        assert!(
            registered.is_ok(),
            "{clause}: `mandate-federation` refuses nothing here on its own; the refusal \
             the registry publishes as decided on the real path is the port \
             implementation's answer, and a second implementation of the same port \
             registers the client"
        );
    }
}

// ==================================================================================
// The document, read as the specification it claims to be
// ==================================================================================

fn workspace() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the workspace root")
}

fn registry() -> serde_json::Value {
    let path = workspace().join("contracts/obligations/federation.json");
    let text = fs::read_to_string(&path).expect("contracts/obligations/federation.json");
    serde_json::from_str(&text).expect("a registry document")
}

fn register_client_clauses(document: &serde_json::Value) -> Vec<serde_json::Value> {
    document["commands"]
        .as_array()
        .expect("commands")
        .iter()
        .find(|command| command["command"] == "mandate.federation.RegisterOAuthClient")
        .expect("mandate.federation.RegisterOAuthClient is in this document")["clauses"]
        .as_array()
        .expect("clauses")
        .clone()
}

/// `contracts/obligations/README.md`: a clause whose deciding code is a stand-in for the
/// deciding code itself is a `double` row, is counted in `double_only` and never in
/// `real_covered`, and still carries `blocked_on`.
///
/// The deciding code for all three of these is an implementation of
/// `mandate_federation::register_client::ClientRegistrationAdmission` — settled by
/// [`the_three_register_o_auth_client_refusals_are_the_ports_answer_and_not_this_crates`]
/// above — and the only implementation in the workspace is
/// `mandate_federation::register_client::ConfiguredAdmission`, which
/// `crates/mandate-conformance/src/external.rs:248` names as this port's standing double
/// beside `GraphDouble` and `PolicyDouble`.
#[test]
fn a_clause_a_standing_double_decides_is_not_published_on_the_real_path() {
    let document = registry();
    let clauses = register_client_clauses(&document);

    let published: Vec<(String, Vec<String>)> = clauses
        .iter()
        .map(|clause| {
            (
                clause["clause"].as_str().unwrap_or_default().to_owned(),
                clause["tests"]
                    .as_array()
                    .map(|rows| {
                        rows.iter()
                            .filter(|row| row["kind"] == "denial")
                            .map(|row| row["path"].as_str().unwrap_or_default().to_owned())
                            .collect()
                    })
                    .unwrap_or_default(),
            )
        })
        .collect();

    assert_eq!(
        published
            .iter()
            .map(|(clause, _)| clause.as_str())
            .collect::<Vec<_>>(),
        PORT_DECIDED.to_vec(),
        "the three clauses this case is about",
    );

    for (clause, paths) in &published {
        assert!(
            !paths.iter().any(|path| path == "real"),
            "{clause}: published on the real path, and nothing in `mandate-federation` \
             decides it — the refusal is `ClientRegistrationAdmission`'s answer, and the \
             only implementation of that port is `ConfiguredAdmission`, which \
             `register_client.rs:181` calls \"a fixture, never a shipped implementation\" \
             and `crates/mandate-conformance/src/external.rs:248` registers as this \
             port's standing double. `contracts/obligations/README.md` puts such a clause \
             in `double_only` with a `blocked_on` naming the story that owns the port's \
             real implementation; published `real` it is counted in \
             `contracts/conformance/obligations-report.json:5` `real_covered`, which is \
             the column this registry exists to make fall"
        );
    }
}

/// The report the misclassification writes: three clauses of `mandate-federation` sit in
/// `real_covered` that belong in `double_only`.
///
/// Stated as its own case because the report is its own committed artefact and is what a
/// reader of the wave's numbers sees; `cargo xtask obligations-registry` byte-compares it
/// and agrees with it, because it recomputes it from the same `path` strings.
#[test]
fn the_report_does_not_count_a_double_backed_clause_in_real_covered() {
    let path = workspace().join("contracts/conformance/obligations-report.json");
    let text = fs::read_to_string(&path).expect("contracts/conformance/obligations-report.json");
    let report: serde_json::Value = serde_json::from_str(&text).expect("a report");
    let federation = &report["crates"]["mandate-federation"];

    assert_eq!(
        federation["clauses"], 41,
        "the clause count is not in question"
    );
    assert_eq!(
        (
            federation["real_covered"].as_u64(),
            federation["double_only"].as_u64(),
            federation["deferred"].as_u64(),
        ),
        (Some(30), Some(3), Some(8)),
        "the three `mandate.federation.RegisterOAuthClient` clauses are decided by this \
         crate's standing double for `ClientRegistrationAdmission` and belong in \
         `double_only`; published `real_covered` they make the crate's row, and the \
         `totals` row with it, report three real-path decisions that no code of \
         `mandate-federation` makes"
    );
}

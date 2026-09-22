//! Adversary pass 1 over the `host-spelling-folded` unit of `story:host-spelling-folded`
//! (commit `d6b1876`).
//!
//! Nothing here changes an implementation file. No key is generated and no case reaches
//! the network: every case calls [`UreqJwks::admits`], which decides a destination without
//! contacting it.
//!
//! # What these cases drive
//!
//! The unit says it "folds the host once and hands that one name to both halves of the
//! SSRF containment", and ships
//! `a_trailing_dot_does_not_change_what_the_jwks_destination_guard_answers`
//! (`tests/verifier_real.rs:2305`) as a property rather than an enumeration: *"A trailing
//! dot is the absolute form of the same host, so the destination guard answers the same
//! with one and without it"*, *"A host added below is covered by it without any
//! enumeration being edited."*
//!
//! `admits` (`src/verifier_real.rs:323`) compares the destination host in **three**
//! places, not two:
//!
//! | # | site | folded? |
//! |---|---|---|
//! | 1 | `(&target.host, target.port) == (&source.host, source.port)` (`:337`) | **no** |
//! | 2 | `literal_address(host)` / `loopback(host)` (`:338`, `:341-342`) | yes |
//! | 3 | `listed(entry, &target)` (`:343`) | no, deliberately (`src/verifier_real.rs:501-504`) |
//!
//! Site 3 is the boundary the unit states and pins. Site 1 is neither stated nor pinned,
//! and it is the one the shipped property test cannot reach: its loop fixes the issuer at
//! a third host (`https://idp.example`) and passes **both** spellings in `allowed_hosts`,
//! so every host it iterates leaves through site 2 and site 3 and none of them through
//! site 1.
//!
//! The two cases below ask the unit's own property at site 1, under the two
//! configurations the shipped source actually uses: the empty host list that
//! `JwksSource::jwks` passes (`src/verifier_real.rs:400`, and
//! `docs/public/federated-login.md:135` — "With no entry, the issuer's own origin is
//! admitted and nothing else"), and the plaintext loopback issuer that
//! `docs/public/federated-login.md:177` says is the only road this repository has ever
//! driven.

use mandate_federation::verifier_real::UreqJwks;
use mandate_types::Issuer;

/// The unit's own property, asked of the issuer's own host under the default host list.
///
/// `JwksSource::jwks` calls `key_set(issuer, &[])` (`src/verifier_real.rs:400`), so the
/// empty list is not a corner of the configuration space — it is the configuration a
/// connection with no `jwks_hosts` member runs under, which is every connection in this
/// repository's fixtures and the one `docs/public/federated-login.md:135` documents.
///
/// `https://idp.example/jwks` is the issuer's own origin and is admitted. Its absolute
/// spelling `https://idp.example./jwks` is the same origin and is refused, because the
/// equality at `src/verifier_real.rs:337` compares the unfolded `target.host` against the
/// unfolded `source.host` and then falls through to a branch an empty list cannot satisfy.
/// One host, two answers.
#[test]
fn a_host_and_its_absolute_spelling_get_one_answer_under_the_default_host_list() {
    let issuer = Issuer::new("https://idp.example");
    let no_hosts_listed: [String; 0] = [];

    let relative = UreqJwks::admits(&issuer, "https://idp.example/jwks", &no_hosts_listed);
    let absolute = UreqJwks::admits(&issuer, "https://idp.example./jwks", &no_hosts_listed);

    assert_eq!(
        relative, absolute,
        "idp.example and idp.example. are one host and the guard gave them two answers: \
         relative={relative}, absolute={absolute}"
    );
}

/// The same property, asked of the plaintext loopback issuer that is the only road driven.
///
/// `docs/public/federated-login.md:177` — "the end-to-end cases run on loopback `http`,
/// which `UreqJwks::admits` permits for loopback hosts only" — and
/// `services/control-plane/tests/end_to_end.rs` binds exactly such an issuer. The unit's
/// own shipped case asserts that a plaintext loopback issuer reads its own key set, for
/// six spellings, each time spelling the issuer and the `jwks_uri` the *same* way
/// (`tests/verifier_real.rs:2343-2359`).
///
/// A discovery document does not have to spell its host the way the deployment spelled the
/// issuer, and it is the discovery document — not the deployment — that writes `jwks_uri`.
/// Spell the issuer `http://localhost` and the `jwks_uri` `http://localhost./jwks` and the
/// same interface, under the same scheme, is refused: the equality at
/// `src/verifier_real.rs:337` is false, and the branch below it requires `https`.
///
/// `allowed_hosts` cannot rescue it — the branch below site 1 begins
/// `target.scheme == "https"` — so both spellings are listed here to show the refusal is
/// site 1's and not the host list's.
#[test]
fn a_host_and_its_absolute_spelling_get_one_answer_for_a_plaintext_loopback_issuer() {
    let issuer = Issuer::new("http://localhost");
    let both = ["localhost".to_owned(), "localhost.".to_owned()];

    let relative = UreqJwks::admits(&issuer, "http://localhost/jwks", &both);
    let absolute = UreqJwks::admits(&issuer, "http://localhost./jwks", &both);

    assert_eq!(
        relative, absolute,
        "localhost and localhost. are one interface and the guard gave them two answers: \
         relative={relative}, absolute={absolute}"
    );
}

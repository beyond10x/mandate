//! The in-process ESS conformance target over the real Mandate handlers.
//!
//! `story:conformance-target` fills this crate: [`MandateTarget`] becomes the
//! `ess_conformance::ConformanceTarget` a suite is executed against, reporting what the real
//! handlers observed — emitted events serialized through the crates' own types, resulting
//! state, denials carrying the declared reason — and never a manufactured expectation. Today
//! the type is a placeholder with no methods, and `mandate-conform` refuses.
//!
//! # What this crate is for before that
//!
//! The conformance harness reaches ESS 0.26.0 over a git dependency, and a dependency that is
//! declared but never named in source is a dependency nobody has shown to resolve, build and
//! link. The test below names one public item from each of the three ESS crates this crate
//! depends on, so `cargo test -p mandate-conformance` is what says the pin in
//! `[workspace.dependencies]` is real. Without it the first evidence that the tag resolves
//! would arrive in the middle of the story that needs it.

/// The Mandate implementation, as an ESS conformance suite sees it.
///
/// `story:conformance-target` gives this the per-scenario `Live` fold, the armed external
/// outcome and the injection log, and implements `ess_conformance::ConformanceTarget` for it.
/// It carries no state yet: a target that answered a scenario from anything but the real
/// handlers would report a manufactured expectation, which is the one failure the suite cannot
/// detect from its own output.
pub struct MandateTarget;

#[cfg(test)]
mod tests {
    /// The three ESS crates resolve, compile and link at the pinned tag.
    ///
    /// One public item each, chosen to execute rather than merely typecheck: a `const` slice
    /// read at runtime proves the rlib is linked, and `AdmittedSuite::from_json` proves
    /// `ess-conformance`'s own dependency closure — `ess-compiler`, `ess-gen`, `serde_yaml`,
    /// `sha2` — built too. An empty document is not a suite, so admission must refuse it;
    /// accepting one would mean the admission this crate will rely on checks nothing.
    #[test]
    fn ess_crates_link_at_the_pinned_tag() {
        assert!(
            !ess_primitives::error::ValidationCode::ALL.is_empty(),
            "ess-primitives declares no validation codes"
        );
        assert!(
            ess_domain::types::Primitive::ALL.contains(&ess_domain::types::Primitive::String),
            "ess-domain declares no string primitive"
        );
        let refused = ess_conformance::AdmittedSuite::from_json("");
        assert!(
            refused.is_err(),
            "ess-conformance admitted an empty document as a suite"
        );
    }
}

//! Adversary: `StreamVersion::advance` is the unchecked sibling of `Generation::advance`.
//!
//! `Generation::advance` (`crates/mandate-identity/src/generation.rs:52-58`) tests
//! `is_at_maximum` before it adds, which is what makes "never wraps, never reuses" true of
//! a generation. `StreamVersion::advance` (`src/port.rs:44-46`) is `Self(self.0 + 1)`
//! with no such test, on a public type with a public `new(u64)`. At `u64::MAX` it panics
//! under the workspace's overflow checks and wraps to `StreamVersion::INITIAL` without
//! them — and `INITIAL` is the expected version the compare-and-set at `src/port.rs:227`
//! accepts for an untouched stream.
//!
//! Reaching it through the fold needs 2^64 recorded events, so this is a property of the
//! type rather than a state anybody arrives at; the case is filed as such.

use std::hint::black_box;

use mandate_identity::StreamVersion;

#[test]
fn advancing_the_maximum_stream_version_does_not_wrap_to_the_initial_one() {
    let maximum = black_box(StreamVersion::new(u64::MAX));

    let next = maximum.advance();

    assert!(
        next > maximum,
        "a stream version that advances to {} from {} is no longer a compare-and-set key",
        next.get(),
        maximum.get()
    );
}

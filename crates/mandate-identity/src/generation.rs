//! The exact security generation: non-negative, monotonic, never wrapping.
//!
//! The contract declares `generation` as an ESS `Integer` on the three epoch entities,
//! constrained `generation >= 0` (`systems/mandate/domains/identity.yaml`). ESS 0.25.0
//! has no unsigned primitive, so `Integer` is the recorded stand-in for the addendum's
//! `u64`: signed 64-bit, held non-negative by this type rather than by convention.
//! Widening when ESS gains an unsigned primitive is a compatible change.

use core::fmt;

/// The generation of one epoch dimension.
///
/// Construction refuses a negative value and advancing refuses the maximum, so no value
/// of this type is outside the declared constraint and no advance ever wraps or reuses a
/// generation.
///
/// ```
/// use mandate_identity::Generation;
///
/// let generation = Generation::new(41).unwrap();
/// assert_eq!(generation.advance().unwrap().get(), 42);
/// assert!(Generation::new(-1).is_none());
/// assert!(Generation::MAX.advance().is_none());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Generation(i64);

impl Generation {
    /// The generation of a dimension no increment has been recorded for.
    pub const ZERO: Self = Self(0);

    /// The largest generation the declared `Integer` can hold.
    ///
    /// At this value [`Generation::advance`] refuses; the contract's answer is an
    /// out-of-band reset, not a wrap (`docs/architecture/command-obligations.md`).
    pub const MAX: Self = Self(i64::MAX);

    /// The generation for a declared value, or `None` when it is negative.
    #[must_use]
    pub const fn new(value: i64) -> Option<Self> {
        if value < 0 { None } else { Some(Self(value)) }
    }

    /// The declared `Integer` value.
    #[must_use]
    pub const fn get(self) -> i64 {
        self.0
    }

    /// The next generation, or `None` at [`Generation::MAX`].
    #[must_use]
    pub const fn advance(self) -> Option<Self> {
        if self.is_at_maximum() {
            None
        } else {
            Some(Self(self.0 + 1))
        }
    }

    /// Whether this generation can no longer advance.
    #[must_use]
    pub const fn is_at_maximum(self) -> bool {
        self.0 == i64::MAX
    }
}

impl Default for Generation {
    fn default() -> Self {
        Self::ZERO
    }
}

impl fmt::Display for Generation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, formatter)
    }
}

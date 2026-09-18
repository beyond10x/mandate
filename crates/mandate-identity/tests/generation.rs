//! `epoch-overflow` (`tests/security/cases.json`): the generation itself never wraps and
//! never reuses a value, and it can never hold a negative one.

use mandate_identity::Generation;

#[test]
fn epoch_overflow_the_maximum_generation_does_not_advance() {
    assert!(Generation::MAX.advance().is_none());
    assert!(Generation::MAX.is_at_maximum());
}

#[test]
fn epoch_overflow_the_maximum_is_the_declared_integer_maximum() {
    assert_eq!(Generation::MAX.get(), i64::MAX);
    assert_eq!(Generation::new(i64::MAX), Some(Generation::MAX));
}

#[test]
fn epoch_overflow_the_generation_one_below_the_maximum_advances_to_the_maximum_and_stops() {
    let penultimate = Generation::new(i64::MAX - 1).expect("non-negative");
    let last = penultimate.advance().expect("one advance remains");

    assert_eq!(last, Generation::MAX);
    assert!(last.advance().is_none());
}

#[test]
fn a_negative_generation_is_not_constructible() {
    assert!(Generation::new(-1).is_none());
    assert!(Generation::new(i64::MIN).is_none());
    assert_eq!(Generation::new(0), Some(Generation::ZERO));
}

#[test]
fn a_generation_advances_by_exactly_one_and_stays_ordered() {
    let generation = Generation::new(41).expect("non-negative");
    let advanced = generation.advance().expect("below the maximum");

    assert_eq!(advanced.get(), 42);
    assert!(generation < advanced);
    assert_eq!(Generation::ZERO.get(), 0);
    assert!(!generation.is_at_maximum());
}

#[test]
fn the_unincremented_generation_is_zero() {
    assert_eq!(Generation::default(), Generation::ZERO);
    assert_eq!(Generation::ZERO.to_string(), "0");
}

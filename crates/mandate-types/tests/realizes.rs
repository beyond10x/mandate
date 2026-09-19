//! `mandate_types::realizes!` — the realization registry, invoked the way a crate invokes it.
//!
//! An integration test is a separate crate, so this exercises the macro across a crate
//! boundary, which is the only way it is ever used: `mandate-types` itself realizes nothing,
//! and the crates that do — federation, identity, authz — reach it through `#[macro_export]`.

mandate_types::realizes! {
    "mandate.core.PrincipalId" => mandate_types::PrincipalId,
    "mandate.core.CorrelationId" => mandate_types::CorrelationId,
}

/// The registry pairs every ESS element with the written path of its symbol, in order.
#[test]
fn the_registry_names_each_element_and_its_symbol() {
    assert_eq!(
        ESS_REALIZATIONS,
        [
            ("mandate.core.PrincipalId", "mandate_types::PrincipalId"),
            ("mandate.core.CorrelationId", "mandate_types::CorrelationId"),
        ]
    );
}

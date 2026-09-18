//! Deny precedence and role expansion: the single home of both.
//!
//! `docs/architecture/combined.md:53` states the rule in four words — "Denies override
//! grants" — and the same paragraph states the other half: "an empty source list grants
//! none". `story:check-api` consumes this module rather than restating either.

use mandate_policy::port::{ChallengeRequirement, PolicyEffect};
use mandate_policy::precedence::{
    Combined, Component, Expansion, RoleCatalog, combine, expand, strictest,
};
use mandate_types::{Action, DenialReason, OrganizationId, Uuid};

fn uuid(byte: u8) -> Uuid {
    Uuid::from_bytes([byte; 16])
}

fn organization() -> OrganizationId {
    OrganizationId::new(uuid(1))
}

/// A catalog told which actions a role name carries. The contract declares no role
/// catalog, so the catalog is a port and this crate invents no role names.
struct Catalog(Vec<(OrganizationId, String, Vec<Action>)>);

impl RoleCatalog for Catalog {
    fn actions(&self, organization: &OrganizationId, role: &str) -> Option<Vec<Action>> {
        self.0
            .iter()
            .find(|(held, name, _)| held == organization && name == role)
            .map(|(_, _, actions)| actions.clone())
    }
}

fn catalog() -> Catalog {
    Catalog(vec![(
        organization(),
        "editor".to_owned(),
        vec![Action::new("read"), Action::new("write")],
    )])
}

#[test]
fn a_deny_overrides_a_grant() {
    let combined = combine(&[
        Component::Allowed,
        Component::Denied(DenialReason::Denied),
        Component::Allowed,
    ]);

    assert_eq!(combined, Combined::Denied(DenialReason::Denied));
    assert!(!combined.allowed());
    assert_eq!(combined.denial_reason(), Some(DenialReason::Denied));
}

#[test]
fn deny_precedence_does_not_depend_on_the_order_the_components_arrive_in() {
    let allowed = Component::Allowed;
    let approval = Component::ApprovalRequired;
    let denied = Component::Denied(DenialReason::TenantMismatch);

    let orders = [
        [allowed, approval, denied],
        [allowed, denied, approval],
        [approval, allowed, denied],
        [approval, denied, allowed],
        [denied, allowed, approval],
        [denied, approval, allowed],
    ];

    for order in orders {
        assert_eq!(
            combine(&order),
            Combined::Denied(DenialReason::TenantMismatch)
        );
    }
}

#[test]
fn combining_is_associative() {
    let left = [Component::Allowed, Component::ApprovalRequired];
    let right = [Component::Denied(DenialReason::Unavailable)];

    let all_at_once = combine(&[
        Component::Allowed,
        Component::ApprovalRequired,
        Component::Denied(DenialReason::Unavailable),
    ]);
    let in_two_steps = combine(&[combine(&left).component(), combine(&right).component()]);

    assert_eq!(all_at_once, in_two_steps);
}

#[test]
fn an_approval_requirement_overrides_an_allow_but_not_a_deny() {
    assert_eq!(
        combine(&[Component::Allowed, Component::ApprovalRequired]),
        Combined::ApprovalRequired
    );
    assert_eq!(
        combine(&[
            Component::ApprovalRequired,
            Component::Denied(DenialReason::ApprovalRequired)
        ]),
        Combined::Denied(DenialReason::ApprovalRequired)
    );
}

#[test]
fn an_empty_set_of_components_grants_none() {
    let nothing = combine(&[]);

    assert!(!nothing.allowed());
    assert_eq!(nothing.denial_reason(), Some(DenialReason::Denied));
}

/// Nothing at all is the identity of combination: a group that contributed no component
/// changes no result it is later combined into. Without this, `combine` is not the
/// associative operation its own doc claims, because an empty group injects a denial.
#[test]
fn nothing_is_the_identity_of_combination() {
    let alphabet = [
        Component::Nothing,
        Component::Allowed,
        Component::ApprovalRequired,
        Component::Denied(DenialReason::TenantMismatch),
    ];

    for component in alphabet {
        assert_eq!(
            combine(&[Component::Nothing, component]),
            combine(&[component]),
            "an empty group changed the result it was combined into"
        );
        assert_eq!(
            combine(&[component, Component::Nothing]),
            combine(&[component])
        );
    }

    assert_eq!(combine(&[]).component(), Component::Nothing);
    assert_eq!(combine(&[Component::Nothing]), combine(&[]));
}

/// The property the module doc states, checked over the whole domain rather than one
/// example: for every sequence of up to three components drawn from the alphabet, and
/// every way of splitting it into two groups — including a split that leaves one group
/// empty — combining the groups agrees with combining all of them at once.
#[test]
fn combining_in_any_grouping_agrees_with_combining_all_at_once() {
    let alphabet = [
        Component::Nothing,
        Component::Allowed,
        Component::ApprovalRequired,
        Component::Denied(DenialReason::Denied),
        Component::Denied(DenialReason::TenantMismatch),
    ];

    let mut sequences: Vec<Vec<Component>> = vec![Vec::new()];
    for _ in 0..3 {
        let mut longer = Vec::new();
        for sequence in &sequences {
            for component in alphabet {
                let mut next = sequence.clone();
                next.push(component);
                longer.push(next);
            }
        }
        sequences.extend(longer);
    }

    let mut checked = 0_usize;
    for sequence in &sequences {
        let all_at_once = combine(sequence);
        for split in 0..=sequence.len() {
            let (left, right) = sequence.split_at(split);
            let in_two_steps = combine(&[combine(left).component(), combine(right).component()]);

            assert_eq!(
                in_two_steps, all_at_once,
                "grouping changed the result: {left:?} | {right:?}"
            );
            checked += 1;
        }
    }

    assert!(
        checked > 500,
        "the property was checked over {checked} groupings"
    );
}

/// Commutativity over every ordered pair and triple of the alphabet, not one example.
#[test]
fn combining_is_commutative_over_every_pair_and_triple() {
    let alphabet = [
        Component::Nothing,
        Component::Allowed,
        Component::ApprovalRequired,
        Component::Denied(DenialReason::Denied),
        Component::Denied(DenialReason::Unavailable),
    ];

    for a in alphabet {
        for b in alphabet {
            assert_eq!(combine(&[a, b]), combine(&[b, a]));
            for c in alphabet {
                let reference = combine(&[a, b, c]);
                for order in [
                    [a, b, c],
                    [a, c, b],
                    [b, a, c],
                    [b, c, a],
                    [c, a, b],
                    [c, b, a],
                ] {
                    assert_eq!(combine(&order), reference);
                }
            }
        }
    }
}

/// A role name that differs from its trim is a name the catalog does not hold, so it
/// expands to nothing and contributes a refusal. Same class as the relation name
/// `mandate-graph` refuses at admission: a padded name reads identically in a log.
#[test]
fn a_role_name_that_differs_from_its_trim_is_unknown() {
    for padded in [" editor", "editor ", " editor "] {
        let expansion = expand(&catalog(), &organization(), padded, &Action::new("read"));

        assert_eq!(expansion, Expansion::UnknownRole);
        assert_eq!(
            expansion.component(),
            Component::Denied(DenialReason::Denied)
        );
    }
}

#[test]
fn every_component_allowed_is_allowed() {
    let combined = combine(&[Component::Allowed, Component::Allowed]);

    assert_eq!(combined, Combined::Allowed);
    assert!(combined.allowed());
    assert_eq!(combined.denial_reason(), None);
}

#[test]
fn the_reported_reason_follows_the_contract_s_declaration_order() {
    for (position, earlier) in DenialReason::VARIANTS.iter().enumerate() {
        for later in &DenialReason::VARIANTS[position..] {
            assert_eq!(
                combine(&[Component::Denied(*earlier), Component::Denied(*later)]),
                Combined::Denied(*earlier)
            );
            assert_eq!(
                combine(&[Component::Denied(*later), Component::Denied(*earlier)]),
                Combined::Denied(*earlier)
            );
        }
    }
}

#[test]
fn a_policy_effect_maps_onto_the_component_it_contributes() {
    assert_eq!(
        Component::of_effect(PolicyEffect::Allow),
        Component::Allowed
    );
    assert_eq!(
        Component::of_effect(PolicyEffect::Deny),
        Component::Denied(DenialReason::Denied)
    );
    assert_eq!(
        Component::of_effect(PolicyEffect::ApprovalRequired),
        Component::ApprovalRequired
    );
}

#[test]
fn a_role_that_covers_the_action_contributes_an_allow() {
    let expansion = expand(&catalog(), &organization(), "editor", &Action::new("write"));

    assert_eq!(expansion, Expansion::Covers);
    assert_eq!(expansion.component(), Component::Allowed);
}

#[test]
fn a_role_that_does_not_cover_the_action_contributes_a_denial() {
    let expansion = expand(
        &catalog(),
        &organization(),
        "editor",
        &Action::new("delete"),
    );

    assert_eq!(expansion, Expansion::DoesNotCover);
    assert_eq!(
        expansion.component(),
        Component::Denied(DenialReason::Denied)
    );
}

#[test]
fn a_role_the_catalog_does_not_know_fails_closed() {
    let unknown = expand(&catalog(), &organization(), "owner", &Action::new("read"));
    let other_tenant = expand(
        &catalog(),
        &OrganizationId::new(uuid(9)),
        "editor",
        &Action::new("read"),
    );

    assert_eq!(unknown, Expansion::UnknownRole);
    assert_eq!(other_tenant, Expansion::UnknownRole);
    assert_eq!(unknown.component(), Component::Denied(DenialReason::Denied));
}

#[test]
fn an_unknown_role_never_turns_a_deny_into_an_allow() {
    let expansion = expand(&catalog(), &organization(), "owner", &Action::new("read"));

    assert_eq!(
        combine(&[Component::Allowed, expansion.component()]),
        Combined::Denied(DenialReason::Denied)
    );
}

fn combined_index(combined: Combined) -> usize {
    match combined {
        Combined::Nothing => 0,
        Combined::Allowed => 1,
        Combined::ApprovalRequired => 2,
        Combined::Denied(_) => 3,
    }
}

fn requirement_index(requirement: ChallengeRequirement) -> usize {
    match requirement {
        ChallengeRequirement::Approval => 0,
        ChallengeRequirement::Reauthentication => 1,
    }
}

/// Every result a caller can hold says something: it is an allow, or it names the reason it
/// is not. `ApprovalRequired` said neither, which is a state with no report in it — and
/// `DenialReason::ApprovalRequired` is one of the four mappings this story owes
/// `story:check-api`, so the home of precedence is where it is produced.
///
/// The exhaustive match above is what makes this a check rather than a list: a new
/// `Combined` variant does not compile until it is accounted for here.
#[test]
fn every_combination_names_what_the_caller_is_told() {
    let every = [
        Combined::Nothing,
        Combined::Allowed,
        Combined::ApprovalRequired,
        Combined::Denied(DenialReason::TenantMismatch),
    ];

    for (position, combined) in every.iter().enumerate() {
        assert_eq!(combined_index(*combined), position);
        assert!(
            combined.allowed() || combined.denial_reason().is_some(),
            "{combined:?} tells the caller nothing"
        );
    }

    assert_eq!(
        combine(&[Component::ApprovalRequired]).denial_reason(),
        Some(DenialReason::ApprovalRequired)
    );
    assert_eq!(Combined::Allowed.denial_reason(), None);
    assert_eq!(
        Combined::Nothing.denial_reason(),
        Some(DenialReason::Denied)
    );
}

/// The two readings of `Nothing`, side by side: a source with zero applicable rules denies
/// when it is the decision, and contributes nothing when it is composed with others. Both
/// are true at once, and which one applies is decided by which accessor the consumer
/// reaches for, not by anything about the value.
#[test]
fn nothing_denies_when_decided_and_contributes_nothing_when_composed() {
    let found_nothing = combine(&[]);

    // Read as the decision.
    assert!(!found_nothing.allowed());
    assert_eq!(found_nothing.denial_reason(), Some(DenialReason::Denied));

    // Read as one source among several.
    assert_eq!(
        combine(&[found_nothing.component(), Component::Allowed]),
        Combined::Allowed
    );

    // A real refusal reads the same way when decided and the opposite way when composed,
    // which is exactly the distinction a consumer has to know it is making.
    let refused = combine(&[Component::Denied(DenialReason::Denied)]);
    assert_eq!(refused.allowed(), found_nothing.allowed());
    assert_eq!(refused.denial_reason(), found_nothing.denial_reason());
    assert_eq!(
        combine(&[refused.component(), Component::Allowed]),
        Combined::Denied(DenialReason::Denied)
    );
}

/// Which party has to clear a challenge is decided here, by a total order over the
/// requirement, and never by the order rules were recorded in. The requirement a caller
/// cannot clear alone outranks the one it can.
#[test]
fn the_strictest_challenge_requirement_is_the_one_the_caller_cannot_clear_alone() {
    let every = [
        ChallengeRequirement::Approval,
        ChallengeRequirement::Reauthentication,
    ];

    for (position, requirement) in every.iter().enumerate() {
        assert_eq!(requirement_index(*requirement), position);
    }

    assert_eq!(strictest(&[]), None);
    for requirement in every {
        assert_eq!(strictest(&[requirement]), Some(requirement));
    }
    assert_eq!(
        strictest(&[
            ChallengeRequirement::Reauthentication,
            ChallengeRequirement::Approval
        ]),
        Some(ChallengeRequirement::Approval)
    );
    assert_eq!(
        strictest(&[
            ChallengeRequirement::Approval,
            ChallengeRequirement::Reauthentication
        ]),
        Some(ChallengeRequirement::Approval),
        "the order they arrive in decides nothing"
    );
}

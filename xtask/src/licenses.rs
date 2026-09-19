//! Every crate in the resolved graph carries a license `deny.toml` allows.
//!
//! `cargo deny check licenses` is the license gate and it does not see the whole lock. A crate
//! reachable only through a dev-dependency is written to `Cargo.lock` and is absent from
//! cargo-deny's graph, with or without `[graph] exclude-dev = false` (cargo-deny 0.20.2,
//! measured): `subtle 2.6.1`, BSD-3-Clause, admitted as a dev-dependency of `mandate-token`,
//! reached the lock behind a green `licenses ok`. Twelve crates of this workspace's resolved
//! graph are invisible to that gate today. A refused license shipping behind a green line is
//! the one thing a license gate exists to make impossible, so this step reads the set
//! cargo-deny cannot: `cargo metadata --locked`'s own resolve, which carries the dev edges.
//!
//! The allowlist is read out of `deny.toml` rather than restated here. A second hand-maintained
//! copy of the allowed licenses would drift from the first, and the drift would be silent —
//! which is the same defect in a new place.
//!
//! # What an expression means
//!
//! An SPDX expression is satisfied when any one of its `OR` alternatives is, and an alternative
//! is satisfied only when *every* one of its `AND` terms is allowed. `A/B` is the deprecated
//! spelling of `A OR B` and is still carried by crates in this lock. A crate that declares no
//! license at all is refused rather than skipped: unstated is not permitted, and a reader that
//! skipped it would report a count that silently excluded the one crate nobody could vouch for.
use serde_json::Value;
use std::collections::BTreeSet;
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
/// The licenses `deny.toml` allows, read from its own `[licenses] allow` line.
///
/// # Errors
///
/// Returns an error when the policy declares no allowlist or declares an empty one. An empty
/// allowlist would refuse every crate rather than admit every crate, but a *missing* one read
/// as empty-and-permissive is how this step would come to pass by reading nothing.
pub fn allowed(policy: &str) -> Result<BTreeSet<String>> {
    let line = policy
        .lines()
        .find(|line| line.trim_start().starts_with("allow = ["))
        .ok_or("deny.toml declares no license allowlist")?;
    let names: BTreeSet<String> = line
        .split('"')
        .skip(1)
        .step_by(2)
        .filter(|name| !name.trim().is_empty())
        .map(str::to_owned)
        .collect();
    if names.is_empty() {
        return Err("deny.toml declares an empty license allowlist".into());
    }
    Ok(names)
}
/// Whether `expression` is satisfied by `allowed`.
fn satisfied(expression: &str, allowed: &BTreeSet<String>) -> bool {
    expression
        .replace('/', " OR ")
        .replace(['(', ')'], " ")
        .split(" OR ")
        .any(|alternative| {
            let terms: Vec<&str> = alternative
                .split(" AND ")
                .map(str::trim)
                .filter(|term| !term.is_empty())
                .collect();
            !terms.is_empty() && terms.iter().all(|term| allowed.contains(*term))
        })
}
/// Read every crate of `metadata`'s resolved graph, and answer with how many were read.
///
/// The count is returned rather than printed so a caller can state it and a case can assert
/// it: a fold that silently read nothing is indistinguishable from a clean one by its verdict
/// alone, which is the failure mode this whole step is about.
///
/// # Errors
///
/// Returns an error naming the first crate whose license the allowlist does not satisfy, and
/// the license it declared, so the refusal is actionable without a second run.
pub fn audit(metadata: &Value, allowed: &BTreeSet<String>) -> Result<usize> {
    let resolved: BTreeSet<&str> = metadata["resolve"]["nodes"]
        .as_array()
        .ok_or("cargo metadata declares no resolved graph")?
        .iter()
        .filter_map(|node| node["id"].as_str())
        .collect();
    let mut counted = 0_usize;
    for package in metadata["packages"]
        .as_array()
        .ok_or("cargo metadata declares no packages")?
    {
        let id = package["id"].as_str().ok_or("package without an id")?;
        if !resolved.contains(id) {
            continue;
        }
        counted += 1;
        let name = package["name"].as_str().ok_or("package without a name")?;
        let Some(expression) = package["license"].as_str() else {
            return Err(format!("license not declared: {name}").into());
        };
        if !satisfied(expression, allowed) {
            return Err(format!("license not allowed: {name} is {expression}").into());
        }
    }
    Ok(counted)
}

---
format: aep.planning-md/1
id: review-result:wave-d-coverage-map-adversary-1
kind: review-result
status: active
title: Adversary pass — coverage map
relations:
- reviews: story:coverage-map
revision: 1
---
```
unit: story:coverage-map — impl/coverage-map on fe03999
verdict: NEEDS-CHANGE (2 blockers, 3 warnings, 1 note)
cases: 170 → 176 executed, 6 red when written
origin: introduced 6 / pre-existing 0
```

```findings
- file: contracts/coverage.json
  category: contract-drift
  severity: blocker
  verdict: CONFIRMED
  origin: introduced
  message: 'six elements are implemented by mandate-types in the manifest while the crate that owns their domain registers them in ESS_UNREALIZED, and mandate.identity.RefreshCredential is declared with no implementation in the row above its .State being implemented'
- file: contracts/coverage.json
  category: contract-drift
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: 'mandate-graph ESS_UNREALIZED says mandate.graph.Resource.State is realized by mandate_model::graph::ResourceState and the manifest says mandate_contract::entities::MandateGraphResourceState, which is two realizers for one element against ruling 3'
- file: contracts/coverage.json
  line: 37
  category: acceptance
  severity: blocker
  verdict: CONFIRMED
  origin: introduced
  message: 'mandate.core.CredentialDescriptor and mandate.core.CredentialProfile are deferred on decision-blocker:identity-uniqueness while mandate_types::inventory::ACCEPTED names mandate-token as the crate that declares them and mandate-token round-trips both against the generated shapes'
- file: xtask/src/coverage.rs
  line: 105
  category: mutant
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: 'Compiled::crates is documented as every workspace package and is every package cargo emitted a message for, so an implemented entry may name serde_json::Value as its symbol and the step accepts it'
- file: xtask/src/coverage.rs
  line: 418
  category: mutant
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: 'the tests column is checked for existence only and no per-crate case reads it, so any test id in the workspace satisfies any element'
- file: xtask/src/coverage.rs
  line: 176
  category: boundary
  severity: note
  verdict: INFEASIBLE
  origin: introduced
  message: 'libtest --list prints an ignored case exactly as a running one so the proven-test set admits cases cargo test never runs, but the workspace holds no #[ignore] today and the state was built by the case'
```

Held under attack: element-set equality both ways, duplicates, one-entry-per-line, story and blocker existence and openness, multi-blocker stories, the declared-on-blocked rule in both directions, the `OnceLock` cache under two roots, receipt byte-stability and digest movement, `ACCOUNTING_CRATES` in both directions, the 292 count in all eight per-crate cases, the 68/23 split.

Coordinator measurement: all 23 derived `.State` entries name a `mandate_contract::entities::*State` symbol and are `implemented` by `mandate-types`; 13 of them belong to records that are not `implemented`.

Rulings (correction round 1): a generated contract symbol is never an implementation — no `impl` may be rooted in `mandate_contract` or in any non-workspace package (closes F4 too). A `.State` element follows its record: `implemented` only when the realizing crate registers its own state enum (`mandate_model::graph::ResourceState` and the tenancy enums in `mandate-model`; F2 closes by registration); otherwise it carries the record's status, story and blocker, and an implemented record whose crate has no state enum leaves its `.State` `declared` on that crate's alignment story. Every per-crate manifest case additionally asserts nothing the crate lists in `ESS_UNREALIZED` is `implemented` anywhere (F1's check). F3: `mandate-token` gains a `realizes!` registry and the manifest case in its `contract_agreement.rs` and joins `ACCOUNTING_CRATES` (scope extended); the step asserts every crate holding a `tests/contract_agreement.rs` is an accounting crate or is named with a reason. F5: every `implemented` entry names at least one test whose package equals the entry's `crate`. F6: `--list --ignored` subtracted from the proven set.

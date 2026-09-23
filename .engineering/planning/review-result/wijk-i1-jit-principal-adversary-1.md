---
format: aep.planning-md/1
id: review-result:wijk-i1-jit-principal-adversary-1
kind: review-result
status: active
title: Adversary pass 1 on I1 (jit-principal-record)
relations:
- reviews: story:jit-principal-record
revision: 1
---
unit: story:jit-principal-record, commit 1b7fb72 (base 86a32ae) plus one untracked adversary test file in the working tree
verdict: red
cases: executed 152→153, red 1
origin: introduced 1, pre-existing 1, undecided 0
wrote-outside-worktree: 2 paths (listed in part 6)
needs-coordinator: no

**1. `git --no-pager diff --stat`**
The output is empty. My only change is one new, untracked test file: `?? services/control-plane/tests/adversary_jit_principal_1.rs`. I changed no implementation file and ran no git or `aep` write.

**2. The case I added**
`services/control-plane/tests/adversary_jit_principal_1.rs`, one test: `a_provisioning_the_identity_fold_refuses_leaves_no_federation_link`. It is **red now**.

- **What it asserts:** the header of `provisioned` says a `false` answer means "a login that still has no linked principal". So when the identity fold refuses the provisioning, the federation fold should hold no link.
- **How it builds the refusal:** it builds two identical deployments (same secrets and clock). The first login on the first one shows which principal id gets minted. On the second one, it pre-records a creation for that id through `record_identity`, then logs in. Login is refused, as expected.
- **Red output**, from running this case alone before the suite:
```
test a_provisioning_the_identity_fold_refuses_leaves_no_federation_link ... FAILED
panicked at services/control-plane/tests/adversary_jit_principal_1.rs:146:5:
a login refused because the identity fold would not record its principal left 1 federation link(s) behind; `provisioned` wrote the federation fold before the identity fold decided
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

**3. The suite, run after the case existed**
`cargo test -p mandate-control-plane --locked --no-fail-fast` exited with status 101. Only my binary is red: `adversary_jit_principal_1.rs: test result: FAILED. 0 passed; 1 failed`. Every other binary is ok. Totals: 152 passed, 1 failed. `cargo clippy -p mandate-control-plane --all-targets --locked -- -D warnings` ends with `Finished`, and `cargo fmt --check` reports nothing.

**4. Findings (covering 1b7fb72)**

| # | file:line | verdict | origin | what was measured | what reaches it |
|---|---|---|---|---|---|
| 1 | `services/control-plane/src/adapters.rs:2460` | INFEASIBLE | introduced | `self.federation.apply(..) && self.identity.try_record(..)` writes the link first. When the identity fold then refuses, the login is refused but the link stays, and the next login authenticates through it. This contradicts the header of `provisioned`. | **Nothing found** in production. The identity fold refuses a well-formed event only for a principal id it has already created. Production mints ids from `SystemSecrets` (a CSPRNG), and `record_identity` has no production caller. The other route, a year above 9999 in `linked_at`, needs the clock to pass year 9999. I built this state; it is not observed. Suggested fix (not applied): decide both folds before writing either. |
| 2 | `services/control-plane/src/adapters.rs:2236` | INFEASIBLE | pre-existing | `record_federation` of an `ExternalPrincipalProvisioned` event folds only into the federation model. The new module header says `authenticate` folds this event into both. A replay through `record_federation` would rebuild the links but not the principal records. | **Nothing found.** At `main.rs:305/323` it is only fed seeded Created/Linked events. The event-log replay that main.rs expects (ruling D4) has not landed. Judgement only; no case written. |

**5. What I attacked and could not break**
- Acceptance: the implementor's case asserts `IdentityRead::principal` for the minted id directly.
- Serde round-trip: `FederationEvent` is untagged, and the generated struct (`deny_unknown_fields`, `display_name: String`) matches its fields one for one.
- Validation parity: subject trim, kind and link-method are checked the same way in the federation fold and in `principal_of`.
- Mutants: dropping the `&& try_record` clause, or making `identity_event_of` return `None`, both turn the implementor's case red.
- Boundaries: `mandate-contract` was already on the `mandate-control-plane` allowlist.

**6. Paths written outside the worktree**
- `~/.cache/claude-tmp/wijk/i1/scratch/adv1-suite.log`
- `~/.cache/claude-tmp/wijk/i1/scratch/adv1-suite-nff.log`

**7. Findings block**
```findings
- file: services/control-plane/src/adapters.rs
  line: 2460
  category: concurrency
  severity: warning
  verdict: INFEASIBLE
  origin: introduced
  message: 'provisioned writes the federation link before the identity fold decides, so an identity refusal (constructed only: duplicate principal id) returns false yet leaves a link the next login authenticates through'
- file: services/control-plane/src/adapters.rs
  line: 2236
  category: judgement
  severity: note
  verdict: INFEASIBLE
  origin: pre-existing
  message: record_federation folds an ExternalPrincipalProvisioned event into the federation model only, so a future log replay through it would rebuild links without their principal records
```

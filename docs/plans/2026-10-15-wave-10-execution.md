# Wave 10 (spec conformance audit): proposal and execution

Opened 2026-10-15 on `integration/wave-20261015-002`, cut from `main` at `04e1465` (0.9.0), with
the tooling wave (`integration/wave-20261015-001`, ESS 0.60.0 and AEP 0.73.0) merged in. Approved
by the operator before it was proposed. Umbrella: `story:spec-conformance-audit`
(`epic:foundations`); the audit's 89 gaps (G-01 to G-89) each have one owning story.

## Already on the branch

- `story:spec-conformance-audit` and its 26 child stories (22 story-class gaps, 4 grouped
  small-gap stories), filed as drafts.
- `story:audit-docs-truth`: `README.md` and the public documents state what 0.9.0 ships.

## Units

| Unit | Story | Gaps |
|---|---|---|
| U1 | `story:audit-manifest-owners` | manifest statuses, owners and reasons |
| U2 | `story:audit-small-code-fixes` | small code fixes, specified first where a scenario or outcome changes |
| U3 | `story:audit-comments-and-store` | comments and ownership rows; the store edits are the coordinator's, through `aep` |

Width: three units, every small-gap story the audit filed; the 22 story-class stories stay drafts
for later waves. The units share `contracts/coverage.json` and owner comments in a few crates, so
each runs in its own tree and the coordinator merges them one at a time.

## Spec first

Each unit changes `systems/mandate` first where a scenario, an outcome or a comment there changes,
validates with `ess specify validate --strict-requires --path systems/mandate` under ESS 0.60.0,
regenerates through `cargo xtask generate`, then changes the code.

## Results

| Unit | Commit | Merge | Outcome |
|---|---|---|---|
| U3 | `1a6c789` | `afa15fd` | comments, ownership rows and scenario summaries cite symbols, not line numbers |
| U1 | `8be6cc7` | `cc5f70b` | every deferred clause, injection row and blocked scenario names a live story; `xtask/tests/open_work_owners.rs` refuses a finished or absent owner |
| U2 | `bad7d9d` | `9f5a8b7` | a foreign record is answered like an unknown one; workload refusals say denied or wrong state; `WorkloadIdentity` is realized |

U2 needed three changes beyond its gap list, each a consequence of a fix: the conformance target
reads OAuth clients and sessions from the scenario's own records (an empty client reader had made
every authorization-code issuance refuse, so one PKCE scenario failed and two passed by
coincidence), the armed-fault handlers check the real readers first, and a new authored scenario
`epoch-increment-commit-fails` replaces the fault anchor the containment fix removed.

The merge of U2 keeps U1's deferral of the graph and policy commands to
`story:graph-policy-adapter`, so those carry no registry rows; the still-implemented ones take
U2's test ids.

Measured on the merged head `9f5a8b7`:

- `ess specify validate --strict-requires`: valid, 14 files, 22 scenarios.
- `cargo xtask conform`: 186 scenarios (185 before), 56 passed, 66 failed, 64 unsupported, every
  outcome matching `contracts/expected-outcomes.json` (48 passed before).
- `cargo xtask coverage`: 297 contract elements, 227 implemented, 15 declared, 55 deferred
  (225/17/55 before).
- `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --check`: clean.

The 22 story-class audit stories stay drafts for later waves.

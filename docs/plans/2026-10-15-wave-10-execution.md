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

Filled at the close of the wave.

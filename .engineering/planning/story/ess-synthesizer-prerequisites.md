---
format: aep.planning-md/1
id: story:ess-synthesizer-prerequisites
kind: story
status: draft
title: Scenarios blocked on the synthesizer arranging no prerequisite (ESS-side fix, Mandate-side attribution)
relations:
- decomposes: epic:foundations
- informed_by: initiative:drift-enforcement
- serves: vision:mandate
scope:
- confidence: inferred
  path: .github/workflows/ci.yml
- confidence: inferred
  path: AGENTS.md
- confidence: inferred
  path: Cargo.lock
- confidence: inferred
  path: Cargo.toml
- confidence: inferred
  path: README.md
- confidence: inferred
  path: contracts/conformance/injections.json
- confidence: cited
  path: contracts/expected-outcomes.json
- confidence: inferred
  path: generated/conformance/suite.json
revision: 4
---
## Why

The synthesizer arranges no prerequisite for an accepted outcome: `CreateTeam` runs on a fold holding no `Organization`, `RegisterFederationConnection` with a rule resolving to a foreign organization, `RegisterSigningKey` with `algorithm: "algorithm"` and `not_before == expires_at`. Sixteen tenancy scenarios and others fail for that one cause (`review-result:wave-d-conform-gate-adversary-1` F7). The fix is in ESS (the synthesizer consulting `creates:` chains and entity invariants — rows on `initiative:drift-enforcement`); this story is the Mandate-side home the conformance ledger attributes those scenarios to until the ESS release lands and Mandate repins.

## Outcome

After the repin, the scenarios attributed here pass or move to the story owning the remaining gap; this story closes with none attributed.

## Acceptance

`cargo xtask conform` reports no scenario `blocked_on` this story.

## Scope

Derived 2026-09-23 by `aep-drive:story-scoper` at `92fc026`. Every line is **cited** or **inferred**.

- **Files:** `contracts/expected-outcomes.json` (58 rows `blocked_on` this story) — cited
- **Also likely:** `Cargo.toml:24-26`, `Cargo.lock`, `generated/conformance/suite.json`, `contracts/conformance/injections.json`, the ESS pin lines in `.github/workflows/ci.yml`, `AGENTS.md`, `README.md` — inferred
- **Confidence:** medium
- **Not closable in this tree:** ESS `8fc460abd` (0.27.0+) likely covers the CreateTeam-without-Organization case; no released ESS fix was found for the entity-invariant cases or the foreign-organization federation rule

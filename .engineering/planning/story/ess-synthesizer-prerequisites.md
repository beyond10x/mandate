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
revision: 1
---
## Why

The synthesizer arranges no prerequisite for an accepted outcome: `CreateTeam` runs on a fold holding no `Organization`, `RegisterFederationConnection` with a rule resolving to a foreign organization, `RegisterSigningKey` with `algorithm: "algorithm"` and `not_before == expires_at`. Sixteen tenancy scenarios and others fail for that one cause (`review-result:wave-d-conform-gate-adversary-1` F7). The fix is in ESS (the synthesizer consulting `creates:` chains and entity invariants — rows on `initiative:drift-enforcement`); this story is the Mandate-side home the conformance ledger attributes those scenarios to until the ESS release lands and Mandate repins.

## Outcome

After the repin, the scenarios attributed here pass or move to the story owning the remaining gap; this story closes with none attributed.

## Acceptance

`cargo xtask conform` reports no scenario `blocked_on` this story.

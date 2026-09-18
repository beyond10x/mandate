---
format: aep.planning-md/1
id: initiative:next-ten-waves
kind: initiative
status: draft
title: Prepare the next ten Mandate waves
relations:
- serves: vision:mandate
- derived_from: specification:combined
revision: 3
---
# Prepare Mandate's next ten waves

## Acceptance

Given the current Mandate backlog and unresolved ESS semantics, when the next-step proposal is inspected, then it contains ten dependency-ordered multi-story waves with cited or inferred typed scopes, observable exits, unfiltered AEP scheduling output and explicit readiness/approval limits.

## Plan and boundaries

The complete proposal is `docs/plans/2026-09-18-next-ten-waves.md`. All selected stories serve vision:mandate and retain their existing epic ownership. This planning mandate does not approve their implementation or clear blockers. Waves 2–10 must be replanned against the post-wave store. Six new draft stories fill source-backed gaps; existing stories retain their statuses.

Sources: `docs/requirements.md`, `docs/architecture/combined.md`, `docs/architecture/unmapped.md`, the story bodies and ESS `systems/mandate/ess-inputs.yaml`. No new domain nouns or semantics are introduced. The linked page retains exact command evidence and exclusions.

## Selected stories

- Wave 1: `story:canonical-types`, `story:runtime-decision-dossier`.
- Wave 2: `story:domain-runtime`, `story:federation-linking`, `story:graph-policy`.
- Wave 3: `story:session-epochs`, `story:tenancy-topology`.
- Wave 4: `story:check-api`, `story:directory-provenance`, `story:pkce-sessions`.
- Wave 5: `story:agent-authority-kernel`, `story:audit-client`.
- Wave 6: `story:audit-worker-delivery`, `story:credential-profiles`.
- Wave 7: `story:constrained-exchange`, `story:recovery-runbooks`.
- Wave 8: `story:agent-security`, `story:protocol-adapters`.
- Wave 9: `story:audit-recovery-conformance`, `story:oauth-integration`.
- Wave 10: `story:product-cli`, `story:runtime-service-qualification`.

## Review disposition

Eight immutable critic verdicts are review-result:ten-waves-{acceptance,design,scope,parallel}-r{1,2}. Six findings were corrected and have review_outcome=fixed records. Round-two design, scope and parallel-safety approved; the acceptance critic requested explicit PKCE candidate/refusal inputs, corrected after that final round without claiming a third review. No runtime readiness or execution approval follows from the panel.

Validation and exact AEP output: docs/plans/2026-09-18-next-ten-waves-validation.md. The source tree remains planning-only; existing story statuses and open decision statuses are preserved.

## Operator delivery refinement

On 2026-09-18 the operator requested story/feature integration into integration/wave-xxxx, then a PR when a coherent batch has accumulated, then a tag after merge and release checks. AGENTS.md and docs/adr/0008-integration-batches.md now override the generic automatic merge-to-main wave boundary. task:integration-batch-workflow records this authorized workflow refinement after the two planning critic rounds; no third panel or implementation approval is claimed.

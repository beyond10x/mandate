---
format: aep.planning-md/3
id: story:spec-conformance-audit
kind: story
status: draft
title: Every gap of the 0.9.0 spec-conformance audit has an owner
relations:
- decomposes: epic:foundations
- serves: vision:mandate
revision: 1
---
# Every gap of the 0.9.0 spec-conformance audit has an owner

## Acceptance

Given the audit of `main` at 0.9.0 (89 gaps, G-01 to G-89: 66 small and 23 story-class), when the planning store is read, then each gap is owned by exactly one story (the 23 story-class gaps by the 22 stories from `introspection-descriptor` to `audit-credential-references`, the 66 small gaps by `audit-docs-truth`, `audit-manifest-owners`, `audit-small-code-fixes` and `audit-comments-and-store`), `audit-docs-truth` is implemented in this wave, `README.md:7` states what `CHANGELOG.md` records for 0.9.0, and `aep plan artifact validate` passes.

## Scope

- `.engineering/planning/story/` (the 26 child stories, through `aep`)
- `README.md`, `CHANGELOG.md` (verified, changed by `audit-docs-truth`)

## Source

Audit G-01 to G-89 (stories S-01 to S-22 and the Small fixes).

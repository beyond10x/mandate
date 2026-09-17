---
format: aep.planning-md/1
id: decision-blocker:epoch-atomicity
kind: decision-blocker
status: open
title: UNMAPPED-ATOMICITY
relations:
- blocks: story:session-epochs
- blocks: story:directory-provenance
- blocks: story:oauth-integration
revision: 1
---
Cross-record invalidation, code redemption, mapping contribution reconciliation and audit persistence need transactional behavior not captured by current single-entity transitions. Specify atomic storage boundaries and race tests before runtime acceptance.

Source: `docs/architecture/unmapped.md`. Clear only with reviewed concrete semantics and evidence.
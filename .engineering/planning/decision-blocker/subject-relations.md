---
format: aep.planning-md/1
id: decision-blocker:subject-relations
kind: decision-blocker
status: open
title: UNMAPPED-SUBJECT-RELATIONS
relations:
- blocks: story:graph-policy-adapter
revision: 1
---
AuthoritySubject is an exact tagged principal/team union. The chosen branch references one Principal or Team membership without owning it. ESS 0.25 cannot carry a relation through a union branch. Settle conditional foreign-key and tenant-membership enforcement before graph runtime admission; schemas must continue to reject zero or multiple subjects.

Source: `docs/architecture/unmapped.md`, `docs/architecture/ownership.md` and the preserved technical reviews. Clear only with concrete reviewed semantics and verification evidence.

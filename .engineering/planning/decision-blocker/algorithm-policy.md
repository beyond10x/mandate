---
format: aep.planning-md/1
id: decision-blocker:algorithm-policy
kind: decision-blocker
status: open
title: UNMAPPED-ALGORITHM-POLICY
relations:
- blocks: story:credential-profiles
- blocks: story:federation-linking
revision: 1
---
SigningAlgorithm is a nominal name. Select and review a verifier-side algorithm/key allowlist; reject unconfigured names and untrusted token-header selection. The supplied sources do not settle the initial concrete set. No algorithm or numeric security behavior is invented to make this foundation compile.

Source: `docs/architecture/unmapped.md`, `docs/architecture/ownership.md` and the preserved technical reviews. Clear only with concrete reviewed semantics and verification evidence.

---
format: aep.planning-md/1
id: decision-blocker:algorithm-policy
kind: decision-blocker
status: open
title: UNMAPPED-ALGORITHM-POLICY
relations:
- blocks: story:credential-profiles
- blocks: story:federation-linking
- blocks: story:signing-and-verification
revision: 2
---
SigningAlgorithm is a nominal name. Select and review a verifier-side algorithm/key allowlist; reject unconfigured names and untrusted token-header selection. The supplied sources do not settle the initial concrete set. No algorithm or numeric security behavior is invented to make this foundation compile.

Source: `docs/architecture/unmapped.md`, `docs/architecture/ownership.md` and the preserved technical reviews. Clear only with concrete reviewed semantics and verification evidence.

## Operator decision on the allowlist, 2026-09-18

Approving authority: the operator, in the interactive session of 2026-09-18. Admitted verifier-side algorithms: RS256 and ES256. Refused at startup: a name outside the list, an empty list, an algorithm selected from a token header, and `none`. Recorded as `approval` evidence against this blocker; not a clearance. The clearance evidence remains the runtime cases at `docs/architecture/runtime-decisions.md:276-278`, produced by `story:signing-and-verification` (verifier side) and `story:credential-profiles` (issuance side). The list is carried here, in `story:signing-and-verification`, and in the deployment configuration validated at startup. `docs/architecture/runtime-decisions.md` (check SC4) and `docs/architecture/federated-login.md` (check FL3) must keep naming no algorithm.

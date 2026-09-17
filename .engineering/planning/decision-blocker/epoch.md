---
format: aep.planning-md/1
id: decision-blocker:epoch
kind: decision-blocker
status: open
title: UNMAPPED-EPOCH
relations:
- blocks: story:session-epochs
revision: 2
---
PrincipalSecurityEpoch, OrganizationSecurityEpoch and FederationSecurityEpoch now declare independent ownership; SecurityEpochSnapshot declares scoped immutable ownership and session/credential references. Their numeric values remain absent: ESS 0.25 has no exact unsigned u64 generation with monotonic increment, overflow denial and atomic comparison semantics. EpochSnapshotRef is a handle, never a generation. ESS also cannot carry a relation through an entity identity. Exclude these incomplete epoch records from canonical realization; clear only with reviewed concrete types, owner linkage, comparison/increment semantics and isolation/race evidence. Do not invent lifecycle self-loops or approximate values.

Source: docs/architecture/unmapped.md#unmapped-epoch; response to C3/C11 in docs/technical-review-disposition.md.

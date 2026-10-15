---
format: aep.planning-md/3
id: story:workload-binding-uniqueness
kind: story
status: draft
title: Workload binding uniqueness is declared
relations:
- decomposes: epic:agents-workloads
- serves: vision:mandate
revision: 1
---
# Workload binding uniqueness is declared

## Acceptance

Given `workload.yaml` declaring either a uniqueness rule on (trust domain, external subject) or a denial clause for an ambiguous binding, when `AuthenticateWorkload` resolves a proof that matches two recorded workload identities, then it refuses with that declared clause, the `WorkloadAmbiguous` test in `crates/mandate-authz/tests/` is bound to it in `contracts/obligations/authz.json`, and its ESS scenario passes.

## Scope

- `systems/mandate/domains/workload.yaml`
- `crates/mandate-authz/src/workload.rs`, `crates/mandate-model/src/workload.rs`
- `contracts/obligations/authz.json`

## Source

Audit G-45 (story S-21).

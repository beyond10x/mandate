---
format: aep.planning-md/1
id: feature-design:federated-login
kind: feature-design
status: draft
title: 'Federated login: customer IdP session to Mandate session and credential'
relations:
- designs: epic:authentication
- informed_by: story:federation-linking
- informed_by: story:domain-runtime
revision: 1
---
# Federated login — design record

Owns two documents and the decisions they carry: `docs/architecture/federated-login.md` (the internal design: the contract-declared flow as two mermaid diagrams, the nine-step resolution order, the refusal table, the JIT gap and its closure, the nine operator decisions of 2026-09-18, the type-count constraint that makes the JIT switch a `Boolean`, and what current repository policy leaves unbuildable) and `docs/customer/federated-login-approval.md` (the customer-facing variant, outside the public allowlist, with an approval block).

## What it designs

The requirement at `docs/requirements.md:153`: a customer's user with an existing IdP session enters Mandate-protected flows without a separate password or account. The flow is already declared in `systems/mandate/domains/federation.yaml:144-248` and `credential.yaml:183-215`; the design adds no command except the JIT command `story:domain-runtime` carries, and records that `AuthenticateFederation` alone supports only the provisioned mode.

## Decisions recorded, none a clearance

`lifecycle`, `worker-orchestration`, `identity-uniqueness`, `algorithm-policy`, `epoch`, `epoch-atomicity`, `guards`, `jit-provisioning` — each as `approval` evidence on its blocker, each blocker still `open` because its clearance evidence is runtime cases that do not exist. The standing constraint that every persistence is event-sourced through `eventlog` is `docs/adr/0009-event-sourced-persistence.md` and one line in `AGENTS.md`.

## Stories it informs

The ten on the path — `domain-runtime`, `federation-linking`, `session-epochs`, `pkce-sessions`, `credential-profiles`, `tenancy-topology`, `check-api`, `graph-policy`, `protocol-adapters`, `oauth-integration` — each rewritten on 2026-09-18 to carry one acceptance statement, a unit table with one source file and one test file per agent and no file in two rows, `scope` at file granularity, the case ids from `tests/security/cases.json`, the decisions that apply, the dependency ceiling, exclusions, and a package-scoped gate. Each story's `## Scope` was returned by `aep-drive:story-scoper` and written by the coordinator.

## Not decided here

The signing-algorithm list (`runtime-decisions.md:256`); the graph and policy engines (`decision-blocker:backend`); the dependency decision that admits a signature verifier to `mandate-federation`; the replacement of the `serve` refusal at `xtask/src/main.rs:259-273`.

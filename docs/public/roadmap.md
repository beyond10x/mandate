# Roadmap

Mandate starts from reviewable contracts and then implements the security behavior they require. The roadmap orders dependencies rather than promising release dates.

| Stage | Outcome and exit condition | Where it stands |
|---|---|---|
| Foundations | Combined architecture and threat model, buildable Rust scaffold, validated ESS contracts, structural acceptance corpus, and reviewed planning records. | Done |
| Parallel core tracks | Authentication delivers federation, S256 PKCE, sessions, and epoch checks. Core authorization delivers tenancy, relationships, policy evaluation, checks, audit, and a client. Each track must satisfy its own required contracts. | Authentication: the federated-login road runs end to end against the shipped binary. Core authorization: tenancy, relationships and checks are implemented over ports; audit is not — it waits on a denial-routing decision. |
| STS and credentials | Both cores support registered audiences, signed and reference issuance, verifier-only persistence, introspection, revocation, and constrained exchange. Authority-bearing exchange depends on both cores. | Audience registration, both credential families, introspection and revocation are implemented as a library and composed into the control plane. Constrained exchange is not started. |
| Enterprise directory | SCIM, explicit group-to-team mappings, SAML, and provisioning/deprovisioning preserve membership provenance and tenant isolation. | Not started. |
| Services, workloads, and agents | Workload trust, ceilings, delegation, execution identity, approvals, and sender constraints satisfy containment and narrowing requirements. | Not started. |
| Hardening | Security resets, emergency federation shutdown, key-rotation drills, revocation/load testing, and audit export have operational evidence. | Not started. |
| Scale and interoperability | Batch/list APIs, consistency, indexing, AuthZEN, multi-region planning, and SDKs have explicit compatibility and performance criteria. | Not started. |
| Advanced delegation — deferred | Chains, task/transaction credentials, simulation, and access review require separate design and acceptance. | Deferred by decision. |

## What runs today

`mandate-control-plane serve` takes `--listen`, `--issuer` and four repeatable document flags —
`--connection`, `--key`, `--client`, `--resource-server` — and serves six routes:
`/v1/federation/login`, `/oauth/authorize`, `/oauth/token`, `/oauth/introspect`, `/oauth/jwks` and
`/.well-known/oauth-authorization-server`. A login through a configured identity provider opens a
session, an authorization request yields a code, the token endpoint issues a credential, and
introspection answers for it. A first-time user is provisioned just in time where the connection
admits it, and a revoked link is not provisioned around.

Every document a flag reads is admitted through the command that owns it, so a configuration the
domain would refuse is refused before the socket is bound rather than after a login it would silently
break.

## What is not true yet

This is a development milestone, not a deployable service. The
[use-case registry](https://github.com/beyond10x/mandate/blob/main/contracts/use-cases/federated-login.json)
records each gap with what it costs; in short:

- **No TLS in the process.** The listener speaks plain HTTP. Behind an ingress that terminates TLS
  the external leg is encrypted and the hop from the ingress to the process is not; without one,
  every proof, session identifier, authorization code and credential crosses the network in the clear.
- **No persistence.** A restart loses every session, every unredeemed authorization code, every
  credential and every link a first login provisioned. The deployment is configured per process and
  remembers nothing across one.
- **No self-service registration.** `RegisterFederationConnection` is served by no route: an identity
  provider is a file a Mandate operator writes, not an API a customer's administrator calls.
- **No denial is audited.** A refusal leaves no durable record an incident responder can read.
- **No commercial identity provider has been driven.** Every claim about the road is a claim about an
  issuer this repository stands up and signs with itself.

## How progress is evidenced

Every number below is read from a command rather than written from memory, and each is stated **as of `0.5.1`** so that a later reading which disagrees is a drift somebody can see rather than a claim that quietly went stale.

| measured at `0.5.1` | |
|---|---|
| Tests | `task check` — 274 suites, 2,016 tests, 0 failed |
| Mutation | 11 named mutants, each killed by the test that names it |
| Contract coverage | 292 declared elements — 201 implemented, 29 declared, 62 deferred |
| Conformance corpus | 166 synthesized scenarios — 44 passed, 59 failed, 0 error, 63 unsupported |
| Denial obligations | 191 external denial clauses — 85 decided on the real path, 21 reached only by a test double, 85 deferred |

Those numbers are published rather than summarised because the failing and deferred halves are the
honest part: every non-passing scenario and every unbound clause names the live story or open
decision that owns it, and a check refuses the record if that owner has been closed. The counts come
from `cargo xtask coverage`, `cargo xtask conform` and `cargo xtask obligations-registry`.

The [planning store](https://github.com/beyond10x/mandate/tree/main/.engineering/planning),
[review provenance](https://github.com/beyond10x/mandate/blob/main/docs/review-provenance.md), and
[execution handoff](https://github.com/beyond10x/mandate/blob/main/docs/handoff.md) retain measurable
acceptance, dependencies, review findings, and outstanding blockers.

## What decides the next milestone

Two open decisions hold more of the remaining work than any amount of implementation does, and both
are recorded with their bounded alternatives in the
[runtime decision dossier](https://github.com/beyond10x/mandate/blob/main/docs/architecture/runtime-decisions.md)
and the [unmapped register](https://github.com/beyond10x/mandate/blob/main/docs/architecture/unmapped.md):

- **Guards and denial audit** — where the trusted context adapter validates, and how a denial is
  recorded durably when the domain transaction is refused. 35 denial clauses wait on it, as do the
  product routes and the audit client.
- **Persistence runtime** — the organization event-log kit's surface is asynchronous and this
  workspace admits no async runtime, so the event-sourced persistence this project decided on is
  implemented by nothing and every fold is in memory.

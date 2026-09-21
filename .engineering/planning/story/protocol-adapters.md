---
format: aep.planning-md/1
id: story:protocol-adapters
kind: story
status: draft
title: Implement product routes and OAuth adapters
relations:
- decomposes: epic:sts-credentials
- serves: vision:mandate
- depends_on: story:canonical-types
- depends_on: story:federation-linking
- depends_on: story:check-api
- depends_on: story:constrained-exchange
- depends_on: story:directory-provenance
- informed_by: initiative:next-ten-waves
- depends_on: story:audit-worker-delivery
- depends_on: story:credential-profiles
- depends_on: story:login-adapters
scope:
- confidence: cited
  path: crates/mandate-proto/src/lib.rs
- confidence: inferred
  path: crates/mandate-server/src/denial.rs
- confidence: inferred
  path: crates/mandate-server/src/ingress.rs
- confidence: cited
  path: crates/mandate-server/src/lib.rs
- confidence: inferred
  path: crates/mandate-server/tests/denial.rs
- confidence: inferred
  path: crates/mandate-server/tests/ingress.rs
revision: 12
---
# Implement product routes and OAuth adapters

## Acceptance

Given a caller supplies spoofed authority selectors, when a product adapter decodes the request, then only credential-validated context reaches the corresponding application command.

## Required observations

Resolve UNMAPPED-GUARDS before exposing routes; trusted adapter constructs context and ignores/rejects spoofed authority selectors. Registration, linking, mapping, OAuth form encoding/errors, token exchange, introspection, revocation comply with their protocols as library-level encode/decode under test. credential-containment passes. Moved to `story:product-listener`: the listener, the served metadata document, JWKS key material.

## Deliverable this wave, and the follow-on

"A product adapter decodes the request" is satisfied by the adapter library's decode function under test: the `context` unit takes a request value, strips every caller-supplied selector, and yields a `VerifiedContext` only from credential evidence — case `credential-containment`. A listener is transport, not an adapter; nothing in the acceptance names one. On that evidence, with the `obligations` registry equal to the OpenAPI `operationId`s and the `routes` disjointness proof passing, the story moves to `implemented`. The listener, the served RFC 8414 document and JWKS key material are `story:product-listener`'s, which `depends_on` this story and carries the `serve`-assertion replacement under `task:runtime-wave-integration`.

## Product surface versus generated surface

The generated surface is exactly 34 routes, all `POST /<domain>/commands/<Command>`, one-to-one with `command-obligations.md:7-40` (35 after `story:domain-runtime`). `docs/public/contracts.md:29`: generated command routes do not implement product routes. So `unmapped.md:19` means: **no path of the form `/<domain>/commands/<Command>` may appear in the route table.** The product surface is `combined.md:61`'s list; the concrete paths at `original-design.md:1855-1862` and `:1784-1796` say "Endpoint layout can differ", and the `routes` unit's choice is unreviewed until the critic panel or the operator reads it.

## The adapter contract is code first, document second

`runtime-decisions.md:118` demands a written adapter contract for every command. `story:gate-reads-document-deliverables` records that the gate opens nothing under `docs/architecture/`, so the normative artefact is `crates/mandate-server/src/obligations.rs`, a typed registry whose test asserts the entry set equals the `operationId`s read as text from `generated/openapi/*.yaml`. `docs/architecture/adapter-contract.md` is derived from it and is what the blocker's clearance reads.

## Units

Superseded at the wave D opening (2026-09-19): units `context`, `obligations`, `routes`, `metadata` and `oauth` and their files are `story:login-adapters`' (as its `decode`, `obligations`, `routes`, `metadata`, `oauth`), and that story closes on them. What stays here: `denial` and `ingress` (behind `decision-blocker:audit-routing` and outside `mandate-server`'s ceiling until `AuditRecord` is reachable), the exchange, SCIM, revocation and other product rows of the route table, the `credential-containment` case over product routes that carry a `context`, and the three draft `depends_on` edges. This story closes on that residue, not on the road units.

## Case ids

`credential-containment`. The negative case per deny clause (`runtime-decisions.md:119`) is a Rust test per registry entry; the corpus stays `contract-scenario` and is coordinator-owned.

## Decisions that apply

`decision-blocker:guards` — the denial path shape; the blocker clears when the registry, the negative cases, the selector-stripping case, the `TokenExchangeDenied` audit case and the route-disjointness proof exist (`runtime-decisions.md:117-123`). `docs/adr/0009-event-sourced-persistence.md`.

## Dependency ceiling

`mandate-server`: `mandate-types`, `mandate-proto`. `mandate-proto`: `mandate-model`, `mandate-token`, `mandate-types`, `serde`, `serde_json`. Nothing else, dev-dependencies included. No YAML crate. A unit may not edit `Cargo.toml`, `Cargo.lock`, `dependency-boundaries.json` or `xtask/`.

## Exclusions

Any listener, socket, `serve`, async (`story:product-listener`). `services/*`, `bins/mandate`. `generated/**`. `tests/security/cases.json`. `docs/architecture/runtime-decisions.md`. The wave-1 `crates/mandate-proto` suites — unchanged. `#[ignore]`.

## Gate per unit

`cargo fmt -p mandate-server -p mandate-proto -- --check`; `cargo clippy -p mandate-server -p mandate-proto --all-targets --locked -- -D warnings`; `cargo test -p mandate-server -p mandate-proto --locked`, counts reported.

## Scope

- `crates/mandate-server/src/lib.rs` — cited; 4-line scaffold; coordinator. `crates/mandate-proto/src/lib.rs` — cited; `:209-223`; coordinator; one line.
- `crates/mandate-server/src/context.rs`, `obligations.rs`, `denial.rs`, `ingress.rs`, `routes.rs`, `metadata.rs`; `tests/conformance.rs`, `context.rs`, `obligations.rs`, `denial.rs`, `ingress.rs`, `routes.rs`, `metadata.rs` — inferred; do not exist.
- `crates/mandate-proto/src/oauth.rs`, `crates/mandate-proto/tests/oauth.rs` — inferred; do not exist.
- `docs/architecture/adapter-contract.md` — inferred; derived from the registry.
- Would collide with: any unit touching either crate root; `story:product-listener`, `depends_on` this story.

## Validation and contract

`task check` and the runtime tests named above. `tests/security/cases.json` is a contract corpus, not runtime evidence. ESS: `systems/mandate/ess-inputs.yaml`. Source: `docs/requirements.md` and combined architecture.

## Integration obligations

The trusted worker RecordAuditEvent ingress is part of this adapter delivery: authenticate the emitter independently of optional event subject/tenant, preserve unknown tenant on invalid-proof denials, and reject forged emitter or client-supplied tenant authority. Expose the completed worker append port through the actual adapter so audit-recovery-conformance can exercise it. Source: docs/architecture/audit-routing.md:3 and systems/mandate/domains/audit.yaml:113.

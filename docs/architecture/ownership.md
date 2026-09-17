# Contract, library and deployment ownership

`combined.md` is the normative combined design. This map connects all twelve ESS domains to the original fourteen libraries and four deployment boundaries. Library ownership does not add a deployment.

| ESS domain | Rust ownership | Deployment responsibility |
|---|---|---|
| `mandate.core` | `mandate-types`: identifiers, enums and shared value/wire records | All four deployments compile the vocabulary. Control plane is its ESS documentation publisher, not a remote runtime dependency. |
| `mandate.identity` | `mandate-model`: records; `mandate-identity`: identity/session behavior | Control plane; STS consumes validated session/epoch information. |
| `mandate.tenancy` | `mandate-model`: organization/team records; `mandate-authz`: isolation evaluation | Control-plane administration and authorization evaluation. |
| `mandate.directory` | `mandate-model`: directory/contribution records; `mandate-provisioning`: mapping/provisioning behavior | Control plane owns state and commands; worker orchestration invokes those ports. |
| `mandate.graph` | `mandate-model`: resource/relation/grant records; `mandate-graph`: graph ports | Authorization; concrete storage remains an adapter. |
| `mandate.policy` | `mandate-model`: versioned policies/models; `mandate-policy`: policy ports | Authorization; backend choice remains UNMAPPED-BACKEND. |
| `mandate.authorization` | `mandate-authz`: combined decision evaluation | Authorization service; PEPs enforce decisions. |
| `mandate.federation` | `mandate-model`: connection/link/client records; `mandate-federation`: trust and public-client integration | Control plane authenticates and invokes STS code issuance. |
| `mandate.credential` | `mandate-model`: registry/credential/code records; `mandate-token`: credential formats and token primitives | STS alone issues, resolves, exchanges and revokes credentials, stores code verifiers, and consumes codes. |
| `mandate.delegation` | `mandate-model`: delegation/ceiling/execution/approval records; `mandate-authz`: intersections | Control plane administers; authorization evaluates; STS bounds exchange. |
| `mandate.workload` | `mandate-model`: workload records; `mandate-identity`/`mandate-federation`: trust verification | Control plane establishes trust; STS exchanges validated proofs. |
| `mandate.audit` | `mandate-audit`: audit values/writer/export ports; shared fields in `mandate-types` | Worker owns `RecordAuditEvent`; producers supply redacted records through durable transport. |

Four further libraries provide cross-domain interfaces: `mandate-proto` owns wire contracts on shared types; `mandate-client` owns the Rust client; `mandate-server` owns shared transport/authentication adapters; `mandate-testkit` owns fixtures and future conformance/security support. The server adapter does not acquire PDP or token-issuance authority.

`dependency-boundaries.json` enforces crate direction. Canonical-type realization includes this file in scope so required serialization dependencies can be reviewed with their consuming crates. Later work must declare changes to this shared policy before parallel scheduling.

## Code redemption transaction

The control-plane `AuthorizePublicClient` adapter validates session, client, exact redirect, S256 policy, state/applicable nonce, target and requested authority. It invokes STS `IssueAuthorizationCode`; the code record binds narrowed scope and registered target, and stores only a non-reversible verifier.

STS resolves the proof to `code_id` internally and verifies it against that record. `RedeemAuthorizationCode` consumes the STS-owned code and creates the bounded credential and durable audit outbox in one transaction. `code_id` is an internal identifier, not a public OAuth parameter or source of authority. A failed/replayed transaction must not issue a credential. No separate control-plane consumption operation remains.

Synchronous adapter calls and storage transactions remain required under UNMAPPED-ATOMICITY/GUARDS. An asynchronous event binding would not establish one-use redemption, so none is invented.

## Worker boundary

The worker's declared ingress is the trusted audit append port. Job scheduling, cleanup, audit export scheduling, retries and delivery guarantees remain UNMAPPED-ORCHESTRATION. `SyncJob` and directory mutation commands remain control-plane-owned; invoking them from a worker does not transfer state ownership. No lifecycle or queue protocol is inferred from the word “worker.”

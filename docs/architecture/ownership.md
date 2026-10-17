# Contract, library and deployment ownership

`combined.md` is the normative combined design. This map connects all twelve ESS domains to the original fourteen libraries and four deployment boundaries. Library ownership does not add a deployment.

| ESS domain | Rust ownership | Deployment responsibility |
|---|---|---|
| `mandate.core` | `mandate-types`: identifiers, enums and shared value/wire records | All four deployments compile the vocabulary. Control plane is its ESS documentation publisher, not a remote runtime dependency. |
| `mandate.identity` | `mandate-identity`: the principal, session, epoch-snapshot and generation records, their fold and identity/session behavior; `mandate-model` holds no identity record | Control plane; STS consumes validated session/epoch information. |
| `mandate.tenancy` | `mandate-model`: organization/team records; `mandate-authz`: isolation evaluation | Control-plane administration and authorization evaluation. |
| `mandate.directory` | `mandate-model`: directory/contribution records; `mandate-provisioning`: mapping/provisioning behavior | Control plane owns state and commands; worker orchestration invokes those ports. `dependency-boundaries.json` admits `mandate-provisioning` to no service, the control plane included, so no running component links the directory behavior; the story that serves directory commands declares that boundary change in its scope. |
| `mandate.graph` | `mandate-model`: the `Resource` projection; `mandate-graph`: relation/grant projections of its own fold, graph ports | Authorization; concrete storage remains an adapter. |
| `mandate.policy` | `mandate-policy`: policy/model projections of its own fold, policy ports | Authorization; backend choice remains UNMAPPED-BACKEND. |
| `mandate.authorization` | `mandate-authz`: combined decision evaluation | Authorization service; PEPs enforce decisions. |
| `mandate.federation` | `mandate-federation`: connection/link/client projections of its own fold, trust and public-client integration | Control plane authenticates and invokes STS code issuance. |
| `mandate.credential` | `mandate-token`: resource-server/credential/signing-key projections, credential formats and token primitives; STS: the authorization-code projection | STS alone issues, resolves, exchanges and revokes credentials, stores code verifiers, and consumes codes. |
| `mandate.delegation` | `mandate-authz`: delegation/ceiling/execution/approval projections of its own fold, intersections | Control plane administers; authorization evaluates; STS bounds exchange. |
| `mandate.workload` | `mandate-model`: workload records and the revocation decision; `mandate-authz`: `AuthenticateWorkload` and its trust-domain verification port (`TrustDomainVerifier`) | Control plane establishes trust; STS exchanges validated proofs. |
| `mandate.audit` | `mandate-audit`: audit values/writer/export ports; shared fields in `mandate-types` | Worker owns `RecordAuditEvent`; producers supply redacted records through durable transport. |

Four further libraries provide cross-domain interfaces: `mandate-proto` owns wire contracts on shared types; `mandate-client` owns the Rust client; `mandate-server` owns shared transport/authentication adapters; `mandate-testkit` owns fixtures and future conformance/security support. The server adapter does not acquire PDP or token-issuance authority.

For the first served vertical (wave D, 2026-09-19) the `mandate-control-plane` binary composes the control plane and the STS in one process: it depends on both libraries and holds the port adapters that let each read the other's records. The authority rows above do not move — the STS handlers still decide issuance, redemption and introspection, the control plane's still decide authentication and authorization — and splitting the process later changes wiring, not authority.

## Running composition

`systems/mandate/components.yaml` declares four deployment boundaries. The process that runs today is one of them hosting two others; the remaining binaries are scaffolds.

| Declared component | What runs today |
|---|---|
| `mandate-control-plane` | `services/control-plane`, the one serving binary. It serves federated login, `AuthorizeClient`, the token endpoint (code redemption and token exchange), introspection, the authorization-server metadata and the key set, and hosts the STS library in-process through the adapters in `services/control-plane/src/adapters.rs`. |
| `mandate-sts` | No process of its own: `services/sts/src/main.rs` is a scaffold that parses no command. Its handlers run inside `mandate-control-plane`. |
| `mandate-authorization` | No process of its own: `services/authorization/src/main.rs` is a scaffold. A deployment configured to do so asks `mandate.authorization.Check` in-process, before a handler is dispatched, through `mandate_control_plane::authority::DecisionPoint`. |
| `mandate-worker` | No process: `services/worker/src/main.rs` is a scaffold, and no audit append runs. |

`bins/mandate` is no component: it runs local, secret-free computations and links no workspace crate. `cargo xtask` checks crate edges against `dependency-boundaries.json`, not against this table.

`dependency-boundaries.json` enforces crate direction. Canonical-type realization includes this file in scope so required serialization dependencies can be reviewed with their consuming crates. Later work must declare changes to this shared policy before parallel scheduling.

## Code redemption transaction

The control-plane `AuthorizeClient` adapter validates session, client, exact redirect, S256 policy, state/applicable nonce, target and requested authority. It invokes STS `IssueAuthorizationCode`; the code record binds narrowed scope and registered target, and stores only a non-reversible verifier.

STS resolves the proof to `code_id` internally and verifies it against that record. `RedeemAuthorizationCode` consumes the STS-owned code and creates the bounded credential and durable audit outbox in one transaction. `code_id` is an internal identifier, not a public OAuth parameter or source of authority. A failed/replayed transaction must not issue a credential. No separate control-plane consumption operation remains.

Synchronous adapter calls and storage transactions remain required under UNMAPPED-ATOMICITY/GUARDS. An asynchronous event binding would not establish one-use redemption, so none is invented.

## Worker boundary

The worker's declared ingress is the trusted audit append port. Job scheduling, cleanup, audit export scheduling, retries and delivery guarantees remain UNMAPPED-ORCHESTRATION. `SyncJob` and directory mutation commands remain control-plane-owned; invoking them from a worker does not transfer state ownership. No lifecycle or queue protocol is inferred from the word “worker.”

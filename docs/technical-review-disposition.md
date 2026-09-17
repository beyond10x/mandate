# Technical review disposition

This records changes after the two additional technical reviews, `contracts-review-1` and `design-review-1`. Their immutable `needs-revision` verdicts and originally recorded escalation evidence remain unchanged. These are implementation responses, not new independent approvals. The four original planning critics completed their two rounds separately; no third planning panel was run.

Finding numbers follow each review's prose order. Contract sources are under `systems/mandate/domains`; the [combined architecture](architecture/combined.md) is normative. Required unsupported semantics are tracked in [UNMAPPED blockers](architecture/unmapped.md), not represented as working runtime behavior.

| Contract finding | Response and remaining limit |
|---|---|
| C1 team relation subject | `core.AuthoritySubject` tags a principal or team; graph relations and writes use it. Conditional foreign keys remain UNMAPPED-SUBJECT-RELATIONS. |
| C2 grant target exclusivity | Grant requires the same tagged union; a missing, double or unknown branch fails its schema. |
| C3 epoch ownership | Separate principal, organization and federation records plus scoped immutable snapshot references. Numeric fields and owner-identity relations remain UNMAPPED-EPOCH and excluded from canonical realization. |
| C4 platform/tenant ceilings | Ceiling has its own ID, required agent and optional organization; absent organization means platform. Applicable records intersect; composite uniqueness remains an explicit storage obligation. |
| C5 decision versions | Decision carries optional policy and model versions alongside graph revision. Producer must include applicable versions. |
| C6 unknown denied identity | AuditRecord subject and organization are optional; emitter authentication is separate. |
| C7 audit producer | Worker accepts RecordAuditEvent and publishes AuditEventRecorded. Durable routing remains UNMAPPED-AUDIT-ROUTING. |
| C8 audit categories and metadata | Shared AuditRecord carries correlation and exchange metadata. All 18 addendum categories have an explicit [routing map](architecture/audit-routing.md); remaining producer/vocabulary gaps stay blocked. The review's stated count of 20 differs from the supplied addendum. |
| C9 exchange source ambiguity | Registered ResourceServer IDs replace audience strings, with typed many references and same-verified-tenant validation. |
| C10 external identity uniqueness | Issuer derives from the validated immutable connection; duplicate supplied/stored issuer removed. Composite uniqueness remains UNMAPPED-UNIQUENESS. |
| C11 epoch mutation | IncrementSecurityEpoch identifies exactly one target and explicitly declares the numeric mutation gap. No invented transition or approximate number type. |
| C12 enabled state duplication | ResourceServer and FederationConnection use lifecycle state only. |
| C13 allowed denial | Separate DenialReason excludes Allowed in every domain error. |
| C14 delegation creation | Input includes not_before and execution_binding; server fixes transitive=false and the entity declares the invariant. Semantic enforcement remains runtime work. |
| C15 command guards | Each command has specific denial obligations; all 47 corpus cases reference existing commands, checked by xtask against ESS compilation. Guards remain external predicates. |
| C16 nominal names | SigningAlgorithm, AuditAction and AuditOutcome are named types. Actual algorithm and vocabulary allowlists remain blocked rather than invented. |

| Design finding | Response and remaining limit |
|---|---|
| D1 code transaction split | STS owns AuthorizationCode issuance, storage, consumption and credential issuance. Redeem selects the internal code resolved from proof; product adapters cannot trust a caller-selected ID. Atomic code/credential/outbox commit remains UNMAPPED-ATOMICITY. |
| D2 worker scope | Worker has the audit append port. Directory state and mutation ports remain on the control plane; worker scheduling/cleanup/retry behavior is explicitly blocked. |
| D3 library ownership | [Ownership map](architecture/ownership.md) maps all 12 domains to 14 libraries and four deployment boundaries. |
| D4 shared vocabulary | Core's control-plane assignment is publication ownership. All deployments compile the shared libraries without a remote core dependency. |
| D5 duplicate design | AEP architecture record references the normative combined document instead of copying it. |
| D6 requirement ownership | Original sections 19, 30, 33, 34, 35, 36 and 52 map to their actual cross-cutting domains and source files. |
| D7 serialization dependency scope | Canonical story and handoff include dependency-boundaries.json, Cargo.toml and Cargo.lock; dependency policy changes require review. |

See [verification](verification.md) for observed checks. Schema rejection checks establish data shape only. They cannot prove cryptographic validation, atomicity, tenancy, redaction, lifecycle execution or authority narrowing. These remain required roadmap work, with blockers where the contract cannot yet state their full semantics.

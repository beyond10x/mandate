# Threat model

Assets: principal and organization identity; authority graph; federation trust; bearer/refresh secrets; signing keys; directory mapping provenance; approvals; durable audit. Adversaries include external attackers, malicious tenant administrators/IdPs, compromised workloads and agents, prompt injection, stolen credentials and stale replicas. Trust boundaries are external IdP → federation; trusted session broker → STS; workload → application agent; PEP → PDP; services → graph/store; security events → audit/export.

| Threat | Required mitigation and negative evidence |
|---|---|
| Cross-tenant confused deputy / parent tampering | Verified context and parent ownership; zero/ambiguous tenant and cross-org registration deny |
| Email or issuer account collision | Exact organization/issuer/subject key and audited explicit linking; equal email never merges |
| Directory privilege injection | Directory state grants nothing; explicit mapping and source contributions; overlaps/manual survive removal |
| Bearer theft / persistence disclosure | Short TTL, verifier-only persistence, redaction, audience binding, sender constraints for high-risk profiles |
| Agent or service confused deputy | Independently validate actor; preserve actor; intersect authority and expiry; autonomous ceilings apply |
| Prompt injection / approval laundering | Model text is untrusted; each tool call checks; approval-required remains denied |
| Token exchange laundering | Registered enabled target and permitted source; no tenant/space/audience/scope widening or transitive chain |
| Stale permission or credential | Graph consistency plus online revocation; current epochs for refresh/exchange/high risk; offline bounds explicit |
| OAuth code interception / reuse | S256, exact redirect, state/nonce and atomic consumption; wrong/missing/plain/replayed code deny |
| Malicious issuer / JWKS confusion | Pinned configured trust and algorithm policy; no remote key URL from unverified token; bounded key cache |
| Required service failure | Fail closed for PDP, STS, credential resolution and unresolved topology |
| Audit tampering or leakage | Durable correlated evidence, access controls, retention/tamper review, no tokens/prompts/secrets |
| Workload identity collapse | Runtime trust domain, application principal and execution stay separate |
| Federation compromise / security reset | Atomic disabling and generation bump, emergency drills, no unrelated-tenant invalidation |

`tests/security/cases.json` contains concrete setup/action/expected observations and future owner stories. `cargo xtask corpus` checks traceability and case structure; it does not run authentication, cryptography or a PDP. Runtime conformance, property tests, fuzzing, integration/race/load tests and adversarial review must be added by their owner stories before production. See original §33 and §52 for the retained testing and release checklist.

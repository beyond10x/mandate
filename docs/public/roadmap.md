# Roadmap

Mandate starts from reviewable contracts and then implements the security behavior they require. The roadmap orders dependencies rather than promising release dates.

| Stage | Outcome and exit condition |
|---|---|
| Foundations — current milestone | Combined architecture and threat model, buildable Rust scaffold, validated ESS contracts, structural acceptance corpus, and reviewed planning records. |
| Parallel core tracks | Authentication delivers federation, S256 PKCE, sessions, and epoch checks. Core authorization delivers tenancy, relationships, policy evaluation, checks, audit, and a client. Each track must satisfy its own required contracts. |
| STS and credentials | Both cores support registered audiences, signed and reference issuance, verifier-only persistence, introspection, revocation, and constrained exchange. Authority-bearing exchange depends on both cores. |
| Enterprise directory | SCIM, explicit group-to-team mappings, SAML, and provisioning/deprovisioning preserve membership provenance and tenant isolation. |
| Services, workloads, and agents | Workload trust, ceilings, delegation, execution identity, approvals, and sender constraints satisfy containment and narrowing requirements. |
| Hardening | Security resets, emergency federation shutdown, key-rotation drills, revocation/load testing, and audit export have operational evidence. |
| Scale and interoperability | Batch/list APIs, consistency, indexing, AuthZEN, multi-region planning, and SDKs have explicit compatibility and performance criteria. |
| Advanced delegation — deferred | Chains, task/transaction credentials, simulation, and access review require separate design and acceptance. |

## Next implementation

The first proposed implementation story realizes canonical Rust types from the accepted ESS contracts. A Wave proposal and a separate Drive task identify prerequisites and verification. A Drive launch still requires a reviewed task and explicitly supplied spending limits.

Authentication and core authorization then proceed as parallel tracks. Addendum requirements such as verified tenancy, audience registration, verifier-only storage, and security epochs are required work in their owning tracks; they are not optional later hardening.

## How progress is evidenced

The foundation corpus includes 47 structural scenarios covering isolation, mapping provenance, explicit linking, revocation, PKCE failures and code reuse, exchange escalation, subject/actor preservation, credential containment, and audit redaction. These validate contract coverage today. Future runtime tests must demonstrate the actual behavior.

The [planning store](https://github.com/beyond10x/mandate/tree/main/.engineering/planning), [review provenance](https://github.com/beyond10x/mandate/blob/main/docs/review-provenance.md), and [execution handoff](https://github.com/beyond10x/mandate/blob/main/docs/handoff.md) retain measurable acceptance, dependencies, review findings, and outstanding blockers.

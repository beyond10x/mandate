# Mandate

Identity and authority for people, services, and agents.

Mandate is a standalone foundation for applications that need to know who is acting, which organization they belong to, and precisely what they may do. Its design brings authentication, tenant isolation, relationship-based authorization, and constrained credential exchange into one explicit model.

**Current release: 0.9.0, a development release.** `mandate-control-plane serve` runs federated login — a direct IdP-proof login and an OIDC relying-party code flow — S256 PKCE authorization codes, reference-credential issuance, RFC 7662 introspection and subject-only RFC 8693 token exchange, over nine routes and from in-memory state seeded per process. Authorization checks, agent delegation, approval consumption and workload authentication are implemented as libraries; relationship and policy reads still run against in-memory doubles. Nothing persists across a restart, the listener speaks plain HTTP, denials are not audited, and directory sync, SAML, actor or delegation exchange and a token revocation endpoint are not implemented. The [changelog](CHANGELOG.md) records what each release shipped.

## Explore the design

- [Architecture](docs/public/architecture.md): one identity and authority model across four planned service boundaries.
- [Contract reference](docs/public/contracts.md): browse entities, commands, relationships, events, and lifecycle transitions.
- [Roadmap](docs/public/roadmap.md): parallel authentication and authorization tracks, followed by credentials, enterprise integration, and agents.
- [Build and review](docs/public/development.md): validate the foundations and find the source specifications.

## The questions Mandate makes explicit

Who is the subject, and who is acting for them? Which tenant has verified the identity? What authority was granted, what constraints narrow it, and when does it stop being valid? Those questions stay connected through authentication, authorization, and credential exchange.

Directory groups contribute to authorization only through explicit mappings. Email equality never merges identities. Agents operate under capability ceilings and delegations, and what they may do is the intersection of every input. A decision requiring approval stays denied until a recorded, matching approval is consumed. Credential exchange keeps the subject and never widens authority or expiry; an exchange naming an actor or a delegation is refused until constrained exchange is built.

These are required behaviors in the contracts and acceptance scenarios. The [roadmap](docs/public/roadmap.md) measures how much of them the code enforces today; directory mappings are specified and not yet implemented.

## Start with the source

Use Rust 1.98.1, ESS 0.60.0, AEP 0.73.0, Task, and cargo-deny:

```bash
task check
```

The gate checks formatting, lints, the workspace and its tests, dependencies, licenses and crate boundaries, ESS contracts, deterministic generated artifacts, the coverage and denial-obligation registries, an executed conformance run, named mutants, and planning records. It spawns `mandate-control-plane` on loopback; it exercises no deployment and no external identity provider.

Licensed under Apache-2.0. Packages carry the workspace version, 0.9.0, and are not published to crates.io. Releases are source releases; nothing is deployed.

<!-- b10x-docs:start -->
## Documentation

[Mandate documentation](https://beyond10x.github.io/docs/mandate/) · [Start](https://beyond10x.github.io/) · [Ecosystem](https://beyond10x.github.io/ecosystem/) · [Impact](https://beyond10x.github.io/changes/) · [Releases](https://beyond10x.github.io/releases/)
<!-- b10x-docs:end -->

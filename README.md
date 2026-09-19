# Mandate

Identity and authority for people, services, and agents.

Mandate is a standalone foundation for applications that need to know who is acting, which organization they belong to, and precisely what they may do. Its design brings authentication, tenant isolation, relationship-based authorization, and constrained credential exchange into one explicit model.

**Current milestone: foundations.** The Rust workspace builds, the ESS contracts validate, and the implementation roadmap has been reviewed. Services and the CLI expose help/version only. Authentication, authorization enforcement, and credential issuance are not implemented yet.

## Explore the design

- [Architecture](docs/public/architecture.md): one identity and authority model across four planned service boundaries.
- [Contract reference](docs/public/contracts.md): browse entities, commands, relationships, events, and lifecycle transitions.
- [Roadmap](docs/public/roadmap.md): parallel authentication and authorization tracks, followed by credentials, enterprise integration, and agents.
- [Build and review](docs/public/development.md): validate the foundations and find the source specifications.

## The questions Mandate makes explicit

Who is the subject, and who is acting for them? Which tenant has verified the identity? What authority was granted, what constraints narrow it, and when does it stop being valid? Those questions stay connected through authentication, authorization, and credential exchange.

Directory groups contribute to authorization only through explicit mappings. Email equality never merges identities. Agents operate under ceilings, and a decision requiring approval remains denied. Credential exchange preserves subject and actor while narrowing authority and expiry.

These are required behaviors in the contracts and acceptance scenarios. Runtime implementation is the next phase.

## Start with the source

Use Rust 1.98.1, ESS 0.26.0, AEP 0.55.0, Task, and cargo-deny:

```bash
task check
```

The gate checks the Rust scaffold, dependencies, ESS contracts, deterministic generated artifacts, planning records, and structural acceptance scenarios. It does not test a running authorization service.

Licensed under Apache-2.0. Packages are version 0.1.0 and are not published to crates.io. This milestone contains no service release or deployment.

<!-- b10x-docs:start -->
## Documentation

[Mandate documentation](https://beyond10x.github.io/docs/mandate/) · [Start](https://beyond10x.github.io/) · [Ecosystem](https://beyond10x.github.io/ecosystem/) · [Impact](https://beyond10x.github.io/changes/) · [Releases](https://beyond10x.github.io/releases/)
<!-- b10x-docs:end -->

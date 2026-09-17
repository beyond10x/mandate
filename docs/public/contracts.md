# Contract reference

[Open the interactive contract viewer](https://beyond10x.github.io/components/mandate/document/). Search for a named type, entity, command, or event; follow relationships; inspect lifecycle diagrams; and share a link to a specific declaration.

The viewer reads ESS's `ess-docs/1` projection. Its source and contract digests are visible on every page, with a downloadable projection. These describe the declared model. They do not establish implementation or runtime enforcement.

## Read the generated reference

The same specification generates a complete Markdown reference:

- [System and deployment overview](../../generated/docs/index.md)
- [Core identifiers](../../generated/docs/domains/mandate-core.md)
- [Identity and sessions](../../generated/docs/domains/mandate-identity.md)
- [Organizations and teams](../../generated/docs/domains/mandate-tenancy.md)
- [Directory mapping](../../generated/docs/domains/mandate-directory.md)
- [External identity and federation](../../generated/docs/domains/mandate-federation.md)
- [Credentials, registered audiences, and exchange](../../generated/docs/domains/mandate-credential.md)
- [Relationships and grants](../../generated/docs/domains/mandate-graph.md)
- [Policies](../../generated/docs/domains/mandate-policy.md)
- [Authorization decisions](../../generated/docs/domains/mandate-authorization.md)
- [Delegation, execution, and approval](../../generated/docs/domains/mandate-delegation.md)
- [Workload identity](../../generated/docs/domains/mandate-workload.md)
- [Audit](../../generated/docs/domains/mandate-audit.md)

## Semantic API projections

ESS generates command-oriented OpenAPI references for the [control plane](https://beyond10x.github.io/api/mandate/control-plane/), [authorization service](https://beyond10x.github.io/api/mandate/authorization/), [STS](https://beyond10x.github.io/api/mandate/sts/), and [worker](https://beyond10x.github.io/api/mandate/worker/).

Generated command routes are contract projections. They do not implement product routes, OAuth token exchange, authorization-code/PKCE, introspection, SCIM, or federation protocols. Those adapters are required implementation work. S256 is the initial PKCE policy; device authorization remains deferred.

## Unsettled semantics remain visible

Numeric epoch semantics, atomic membership contribution updates, lifecycle algorithms, and denial-audit behavior have explicit `UNMAPPED` entries and linked blockers. The [unmapped register](https://github.com/beyond10x/mandate/blob/main/docs/architecture/unmapped.md) records the decisions and verification still required. A generated schema is not a substitute for those decisions.

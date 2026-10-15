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

Generated command routes are contract projections and are never served as product endpoints. The product routes are implemented separately, in `mandate-server` and `mandate-proto`, and the control plane serves nine of them today: `/v1/federation/login`, `/v1/federation/authorize`, `/v1/federation/callback`, `/v1/federation/handoff`, `/oauth/authorize`, `/oauth/token`, `/oauth/introspect`, `/oauth/jwks` and `/.well-known/oauth-authorization-server`. Authorization-code redemption with S256 PKCE, subject-only RFC 8693 token exchange, introspection, the OIDC relying-party flow and the metadata and JWKS documents are implemented; actor and delegation exchange, a token revocation endpoint, SCIM, SAML and the administration routes a customer's administrator would call are not. Device authorization remains deferred.

## Unsettled semantics remain visible

Numeric epoch semantics, atomic membership contribution updates, lifecycle algorithms, and denial-audit behavior have explicit `UNMAPPED` entries and linked blockers. The [unmapped register](https://github.com/beyond10x/mandate/blob/main/docs/architecture/unmapped.md) records the decisions and verification still required. A generated schema is not a substitute for those decisions.

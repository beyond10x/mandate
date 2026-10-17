---
format: aep.planning-md/3
id: decision-blocker:oidc-design-forks
kind: decision-blocker
status: cleared
title: OpenID Provider design forks F1-F9 that change the contract
relations:
- blocks: story:oidc-static-client-registry
- blocks: story:oidc-discovery-and-code-flow
- blocks: story:oidc-signed-tokens-and-key-rotation
- blocks: story:oidc-refresh-and-logout
- blocks: story:oidc-durable-state
- decides: epic:openid-provider
revision: 2
transitions:
- {from: "open", to: "cleared", at: "2026-10-15T13:30:26Z", actor: "human:timo", revision: 2}
---
# OpenID Provider design forks that change the contract

**Decision question.** Before the spec-first wave of `epic:openid-provider` can model anything, nine
forks of the design in `docs/adr/0012-openid-provider.md` must be settled, because each changes
`systems/mandate` or the runtime every parity story builds on: the subject identifier (F1), how
client secrets are held (F2), PKCE for confidential clients (F3), the browser session (F4), consent
(F5), refresh rotation and reuse (F6), the logout surface (F7), the signing algorithm (F8) and the
durable-state runtime (F9). Their options and costs are in `docs/adr/0012-openid-provider-forks.md`.

**Bounded alternatives.** The lettered options of F1–F9 in the forks document.

**Proposed owner.** The `mandate.federation` and `mandate.credential` contract owners; the contract
change itself belongs to the spec-first wave of the epic.

**Affected stories.** `story:oidc-static-client-registry`, `story:oidc-discovery-and-code-flow`,
`story:oidc-signed-tokens-and-key-rotation`, `story:oidc-refresh-and-logout`,
`story:oidc-durable-state`.

## Decided 2026-10-15 — every fork on its recommended option

- F1 B+A: a Dex-compatible `sub` for a connection that replaces a Dex connector; a Mandate principal
  id everywhere else.
- F2 A: the configuration names a secret file; only a keyed verifier is stored; two active
  verifiers per client, for rotation.
- F3 B: PKCE is a per-client setting, required by default, off only for a client whose measured
  gateway sends none.
- F4 B: a minimal host-only session cookie bound to the `Session` record.
- F5 A: no consent screen for static first-party clients.
- F6 B: refresh rotation with a 2 s grace that mints at most one sibling; a reuse after the grace
  revokes the family.
- F7 A: RP-initiated `end_session` first; `/oauth/revoke` later.
- F8 C: RS256 by default, ES256 per client.
- F9 A: tokio + hyper, the organization `eventlog` kit on SQLite on a volume, one replica.

The decision is recorded in ADR 0012, section "Design forks decided". F10–F22 are decided inside the
story that meets them, on the forks document's recommendation.

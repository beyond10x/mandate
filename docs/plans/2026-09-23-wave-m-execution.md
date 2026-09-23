# Wave M — execution

Opened 2026-09-23 on `integration/wave-20260923-003`, cut from `main` at `d55a951` (`v0.5.1`).
Coordinator: an interactive session running `aep-drive:wave` 0.9.3, approved by the operator's plan.
At most three concurrent agents; the standing cadence in `AGENTS.md` applies at close.

Purpose: an external OIDC IdP whose token endpoint accepts only `client_secret_basic`, whose `sub`
is pairwise and whose tenant claim is URL-named can sign a browser in, and the resulting session can
be exchanged for a credential a downstream platform validates by introspection.

## Units

| unit | story | branch | managed id | scratch |
|---|---|---|---|---|
| M1 | `story:relying-party-code-flow` | `impl/relying-party-code-flow` | `mandate-wm-rp-flow` | `~/.cache/claude-tmp/wm/m1/` |
| M2 | `story:federated-token-exchange` | `impl/federated-token-exchange` | `mandate-wm-exchange` | `~/.cache/claude-tmp/wm/m2/` |
| M3 | `story:federation-fixtures-rs256` | `impl/federation-fixtures-rs256` | `mandate-wm-fixtures` | `~/.cache/claude-tmp/wm/m3/` |

Each tree builds into its own `target/`.

**Shared files, split by symbol.** M1 and M2 both write `crates/mandate-server/src/routes.rs`,
`decode.rs` and `services/control-plane/src/serve.rs`. M1 owns the two new federation routes, their
decoders and serve arms. M2 owns the `/oauth/token` grant dispatch, the exchange decoder and the
metadata change. `git merge-tree --write-tree` is run on the two branches before the second merges.
M1's token-endpoint port lives in a new file, `crates/mandate-federation/src/idp_token.rs`, so M1 and
M3 do not share `verifier_real.rs`.

**Coordinator decisions.**
- The exchange is subject-only. Its denials use the existing in-memory audit path; durable delivery
  stays with `decision-blocker:audit-routing`.
- The IdP client secret is read from a file named by `--client-secret-file` and never appears in
  argv, a log or a domain record.

## Commits this wave authorises

One commit per unit plus each adversary pass's test file; the merges into the integration branch;
the coordinator's opening, alignment and closing store commits; then the standing cadence — PR, bot
merge, Gates baseline advance, release, branch and tree cleanup.

## Pre-flight

| check | reading |
|---|---|
| primary checkout | `main` at `d55a951`, clean but for untracked `.agents/` |
| free disk | 16G, `/` at 99%; the largest consumers are other sessions' (`ess` trees 36G, `ess` target 23G), not touched |
| floor | builds stop below 10G free |

## Stage log


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

- Opening commit `871c11b0`: fmt 0, documents 0, validate valid; 0 banned-term hits in the staged diff. Three unit trees at `871c11b0`; three `aep-drive:implementor` dispatches. Free disk 14G.
- HTTP 429 stopped all three implementors (M1 and M2 clean at `871c11b0`; M3 with one untracked test file). Operator rotated; all three resumed in their own context on the same model. Free disk 13G.
- M2 blocked: the Acceptance named the session's connection as the exchange source, but `allowed_exchange_sources` is a `ResourceServerId` list (`credential.yaml:22-23`). Coordinator decision: option A, standard RFC 8693 — the subject token is an access credential for a source resource server the target admits (`docs/architecture/combined.md:53`). Story Acceptance amended in the store; M2 resumed.
- M3 green: federation 348→353, red 3; a non-string tenant claim is refused as `TenantClaimNotText(ClaimType)`. Committed `18efbc51` (0 banned-term hits). Adversary pass 1 dispatched.
- M3 adversary 1: red, 2 findings (introduced: the type refusal in step 3 pre-empts the fallback and empty-subject refusals), recorded `review-result:wm-m3-fixtures-adversary-1`; cases `4b1cda4`. Decision: the refusal moves into `resolve_tenant`, answering only where base answered `TenantZero`; M3's assignment gains `authenticate.rs` (M1 does not edit it).
- M3 correction 1 green (federation 357; both pass-1 cases green). It edited `verifier.rs` and `lib.rs` (a defaulted trait method; M1 owns other hunks in `lib.rs`) — accepted, merge-tree dry run before M1 merges. The control-plane `RecordingVerifier` forwarding patch is held for an integration alignment commit. Committed `c90e990`, outcomes `fixed` ×2. Adversary pass 2 dispatched.
- M1 green with its `mandate-server` test patch applied (federation 348→357, control-plane 170→176, server 104; conform, boundaries, obligations-registry 0). Scope correction: the redirect URI and secret reference live in the `--connection` document (as `algorithm` and `jwks_hosts` do), not the contract; the secret comes from `--client-secret-file NAME=PATH`. Committed `70906bc`. Adversary pass 1 dispatched. `lib.rs` and `mandate-server/tests` may overlap M2 and M3 — dry run before merges.
- M3 adversary 2: red, 1 note (a rule with no value logs a type refusal), recorded `review-result:wm-m3-fixtures-adversary-2`. Coordinator made the correction (report the type only when the rule names a value); federation 360 passed, clippy and fmt 0; outcome `fixed`. M3 ready to merge after M1 and M2.
- M1 adversary 1: red, 10 findings (9 introduced: header injection through a discovered endpoint — blocker; missing RFC 9207 `iss`; IdP error leaves state usable; pending-store flood; login CSRF; session proof to a top-level navigation; single-threaded stall; a doc length; key hosts reused for the secret; 1 pre-existing: direct login skips nonce), recorded `review-result:wm-m1-rp-flow-adversary-1`; cases `260395a`. Decisions: F1–F6, F8–F10 fixed in M1 (F6 adds a `return_uri` + single-use handoff code and `POST /v1/federation/handoff`); F7 filed as `story:listener-outbound-stall` (outcome `no-op`). Back to the same implementor.
- M2 green: sts 225→241, server 104→111, control-plane 170→176, token 122, proto 53, conformance 41; conform, obligations-registry, boundaries 0. It edited `mandate-token` (the two exchange events and three denial reasons), `mandate-proto` (their error codes) and re-anchored the `lifecycle-transition-wrong` mutant — accepted, no other unit touches them. Doc patch to `adapter-contract.md` applied. Committed `5d5c40a`. Dry runs: M1×M2 clean, M2×integration clean. Adversary pass 1 dispatched. Not realized in conformance: `ExchangeCredential` stays unsupported in `mandate-conformance` (hand-kept list).
- HTTP 429 (weekly limit) stopped M1's correction mid-edit (`adapters.rs` and `tests/idp_token.rs` modified) and M2's adversary pass 1 (tree clean). Operator fixed the limit; both resumed in their own context on the same model.
- M2 adversary 1: red, 4 findings (introduced: the wire ignores `CLAUSE_CODES`; an unbounded record of refused exchanges; actor and audience-by-name refusals stop in the decoder, unrecorded; target by UUID only), recorded `review-result:wm-m2-exchange-adversary-1`; cases `91206c2`. Decisions: all four fixed in M2 (the table drives the wire; cap with oldest evicted; actor reaches the handler; audience name resolved within the subject's organization). Back to the same implementor.
- M1 correction 1 green with its second `mandate-server` test patch applied (federation 359, control-plane 188, server 104; boundaries, conform, obligations-registry 0). Pass 1's cases now pass vacuously (no 200 session body after the handoff; no cookie) — pass 2 briefed to observe the real outcome. Committed `c387293`; outcomes `fixed` ×9. Dry runs M1×integration and M1×M2 clean. Adversary pass 2 dispatched.
- M2 correction 1 green (sts 251, control-plane 181, server 111, token 122, proto 53; conform, obligations-registry, boundaries 0), uncommitted. Its open item: through the single table, a bad subject token answered 401 `invalid_client`. Coordinator decision: a dedicated subject-token clause mapped to 400 `invalid_grant`; three adversary assertions re-pinned (wrong-now). Sent back before pass 2 so pass 2 attacks the final shape.
- M1 adversary 2: red, 5 findings (introduced: the binding cookie cleared by any callback; flood eviction; the seed admits unusable `return_uri` queries; a string-prefix loopback rule; a handoff redeemed by the bare code reopens login CSRF), recorded `review-result:wm-m1-rp-flow-adversary-2`; cases `e285587`. Decisions: A, C, D, E fixed in M1's final correction (per-sign-in cookie cleared only on its own callback; the seed runs the callback's check; parsed loopback host; handoff bound to an app-supplied `app_state`); B filed as `story:authorize-flood-eviction`, its case re-pinned. Coordinator verifies.
- M2 correction 2 green (sts 251, control-plane 182, server 111, token 122, proto 53; conform, obligations-registry, boundaries 0): `SubjectTokenInvalid` → 400 `invalid_grant`; three adversary assertions re-pinned, coordinator checked the hunks (clause swapped, one stricter assertion added). Committed `736556e`; pass-1 outcomes `fixed` ×4. Adversary pass 2 dispatched.
- M2 adversary 2: red, 7 findings (F1 stale — the unit tree carries the story as of `871c11b0`, before the Acceptance amendment; F2 `invalid_scope` for a target refusal; F3 a UUID-spelled audience; F4 nil target id; F5 RFC 8707 `resource` URI refused in the decoder; F6 one shared ring; F7 an uninformative operator log), recorded `review-result:wm-m2-exchange-adversary-2`; cases `78e27a0`. Decisions: F1's case re-pinned (wrong-now); F2 adds `invalid_target`; F3–F7 fixed. Final correction; coordinator verifies.
- M1 final correction: one adversary pair was mutually unsatisfiable (:949 wanted a `?state=` return_uri to work, :1031 wanted it refused). Coordinator ruling: decision C stands, :949 re-pinned to a benign query (`?tab=home`). Accepted deviation: one cookie name holding up to four bindings (a per-sign-in name broke the adversary harness; two tabs complete). control-plane 196, server 104, federation 359; clippy 0 after a forced recheck. Committed `df30509`; outcomes A, C, D, E `fixed`, B `no-op` (filed). **M1 merged.**

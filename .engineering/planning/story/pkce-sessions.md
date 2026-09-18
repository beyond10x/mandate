---
format: aep.planning-md/1
id: story:pkce-sessions
kind: story
status: draft
title: Implement public-client authentication and sessions
relations:
- decomposes: epic:authentication
- serves: vision:mandate
- depends_on: story:federation-linking
- depends_on: story:session-epochs
- informed_by: initiative:next-ten-waves
scope:
- confidence: cited
  path: bins/mandate
- confidence: cited
  path: crates/mandate-identity
revision: 6
---
# Implement public-client authentication and sessions

## Acceptance

Given a registered public client and an unconsumed, unexpired S256-bound code record, when the matching verifier and exact registered redirect are validated under the bound client and authenticated session, then the core returns a non-consuming validation candidate.

## Required observations

Implement non-consuming validation behind typed ports: S256, exact registered redirect, expiry, state/nonce, client binding, active organization and authenticated session state. Cases cover missing, wrong and plain verifiers, expired or already-consumed records, redirect/client mismatch and secret-free CLI primitives. Validation neither consumes a code nor creates a credential or committed redemption result. Two concurrent valid callers may both obtain validation candidates; neither has authority to redeem. story:oauth-integration owns revalidation inside the STS transaction, atomic one-use consumption, credential creation and durable outbox commit, including the one-winner concurrency assertion. No identity-owned code store or separate consume-then-issue transaction is authorized.

## Scope

- `crates/mandate-identity` — cited planned scope; canonical directory granularity.
- `bins/mandate` — cited planned scope; canonical directory granularity.

## Validation and contract

`task check` and the runtime tests named above. `tests/security/cases.json` is a contract corpus, not runtime evidence. ESS: `systems/mandate/ess-inputs.yaml`. Source: `docs/requirements.md` and combined architecture.

## Ten-wave refinement

The first review identified that returning a consumed redemption result would split the STS transaction. This story is now explicitly non-consuming. STS owns code storage; story:oauth-integration performs the complete consume/issue/outbox transaction under decision-blocker:epoch-atomicity. The former direct atomicity blocker added during preparation is removed from this validation-only story; its existing session-epoch prerequisite remains unchanged. Source: docs/architecture/ownership.md:28 and docs/architecture/unmapped.md:25.

## Validation outcomes and final review correction

| Input | Required result |
|---|---|
| Matching S256 verifier, exact registered redirect and bound client, unexpired/unconsumed record, valid bound session/state/nonce | Validation candidate; no code consumption, credential issuance or committed redemption |
| Missing or wrong verifier; plain method | Refusal; no candidate |
| Expired or already consumed record | Refusal; no candidate |
| Client/redirect mismatch or invalid bound session/state/nonce | Refusal; no candidate |
| Two concurrent callers each meeting every positive condition | Each may validate; only the later atomic STS transaction decides the redemption winner |

This explicit matrix answers review-result:ten-waves-acceptance-r2 after the second and final critic round. The coordinator checked it against the existing Required observations and the STS transaction boundary; the wording correction has not received a third independent review. No runtime evidence is claimed.

---
format: aep.planning-md/1
id: review-result:wave3-pkce-sessions-adversary-2
kind: review-result
status: active
title: Adversary pass 2 — story:pkce-sessions
tags:
- model-deviation-opus
relations:
- reviews: story:pkce-sessions
revision: 1
---
```
unit: story:pkce-sessions after correction round 1 — working tree at <worktree>, branch impl/pkce-sessions, uncommitted over base 0d1947d
verdict: CONFIRMED
cases: executed 134→156, red 2
origin: introduced 7 / pre-existing 0 / undecided 0
wrote-outside-worktree: 10 paths under <scratch>/adv2-MWgi6r/ and <scratch>/pass2-scratch.txt
needs-coordinator: none
```

Adversary files this pass: `crates/mandate-federation/tests/adversary_pkce_2.rs` (13 cases, 1 red), `bins/mandate/tests/adversary_cli_2.rs` (9 cases, 1 red). Pass-1 files verified against the pre-edit copy: exactly the two fixture changes, no assertion moved; 12/12 and 6/6 green. Mutant probe on a scratch copy: reverting `challenge_is_well_formed` to length-and-alphabet leaves every implementor-owned test green; only adversary cases catch it.

## Findings

```yaml
findings:
  - id: G1
    severity: medium
    verdict: CONFIRMED
    origin: introduced
    location: "crates/mandate-federation/src/authorize.rs:235"
    message: "validate_authorization_code now requires impl OAuthClientStore + TargetRegistry and the crate's own Projection fold implements only the first, so the sole read model that can reach the command is the test double, unlike the authenticate_federation precedent the change cites where the fold satisfies the whole bound."
  - id: G2
    severity: medium
    verdict: CONFIRMED
    origin: introduced
    location: "bins/mandate/src/main.rs:56"
    message: "Running the binary with a verifier but without its one subcommand makes clap print the complete verifier verbatim on standard error, which is the exact channel the correction's own comment says must never carry credential material."
  - id: G3
    severity: low
    verdict: CONFIRMED
    origin: introduced
    location: "crates/mandate-federation/src/authorize.rs:64"
    message: "TargetRegistry returns Option<OrganizationId> and so cannot distinguish a target that is not registered from a registry that could not answer, a distinction the same correction round added DenialReason::Unavailable for on the request clock."
  - id: G4
    severity: low
    verdict: CONFIRMED
    origin: introduced
    location: "crates/mandate-federation/src/pkce.rs:74"
    message: "Reverting the challenge guard to a length and alphabet check on a scratch copy leaves every implementor-owned test green and is caught only by adversary-owned cases, so the corrected guard has no case of its own in the suite."
  - id: G5
    severity: low
    verdict: CONFIRMED
    origin: introduced
    location: "crates/mandate-federation/src/pkce.rs:45"
    message: "CHALLENGE_LENGTH is still exported but is now referenced by nothing, and a consumer validating a challenge by that constant would apply exactly the length-only check the correction established is insufficient."
  - id: G6
    severity: low
    verdict: CONFIRMED
    origin: introduced
    location: "crates/mandate-federation/src/authorize.rs:382"
    message: "The state and nonce bindings are compared with short-circuiting equality while the public S256 challenge is compared in constant time, inverting the crate's own stated standard on which of the three values is the secret."
  - id: G7
    severity: low
    verdict: CONFIRMED
    origin: introduced
    location: "crates/mandate-federation/src/publicclient.rs:146"
    message: "RecordedClients admits one ResourceServerId registered to two organizations and answers whichever was recorded first, so a fixture with a duplicate registration gets a silent pass from write order alone."
```

## Attacked and could not break

`decode_base64url`/`challenge_is_well_formed`: exactly the 16 of 64 final characters are admitted; ten externally computed S256 challenges pass; every malformed shape refused. `StandInDigest`: deterministic, distinct outputs, the declared form; its 32 bytes are a function of a 64-bit FNV-1a state (63 bits of entropy) — recorded, not a defect of a stand-in. `TargetRegistry` in the command: registered/unregistered/foreign all decided; refusal ordering stable. Nonce: an empty recorded nonce matches nothing. The undated reader: `Unavailable`. The CLI stdin path: line endings, EOF, blank, non-UTF-8, positional-wins, exit codes, help text carrying no verifier-shaped token. Could not establish: whether `TenantMismatch` is rendered to a public client by any adapter (a cross-tenant existence oracle if `target` is wired straight from the caller).

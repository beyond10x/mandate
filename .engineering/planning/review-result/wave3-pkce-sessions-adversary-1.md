---
format: aep.planning-md/1
id: review-result:wave3-pkce-sessions-adversary-1
kind: review-result
status: active
title: Adversary pass 1 — story:pkce-sessions
tags:
- model-deviation-opus
relations:
- reviews: story:pkce-sessions
revision: 1
---
```
unit: story:pkce-sessions (units A–D) — working tree at <worktree>, branch impl/pkce-sessions, uncommitted over base 0d1947d
verdict: CONFIRMED (blocker)
cases: executed 109→127, red 7
origin: introduced 11 / pre-existing 0 / undecided 0
wrote-outside-worktree: 10 paths under <scratch>/adv-z1iXsh/ and <scratch>/last-scratch.txt
needs-coordinator: whether F3 is fixed in code (a resource-server port this story excluded) or by correcting the story's "ESS command realized" claim
```

## Diff under attack

```
 bins/mandate/src/main.rs                        |  55 ++-
 bins/mandate/tests/cli.rs                       |  88 ++++
 crates/mandate-federation/src/authorize.rs      | 473 ++++++++++++++++++
 crates/mandate-federation/src/lib.rs            |  50 ++
 crates/mandate-federation/src/pkce.rs           | 194 ++++++++
 crates/mandate-federation/src/publicclient.rs   | 139 ++++++
 crates/mandate-federation/tests/authorize.rs    | 625 ++++++++++++++++++++++++
 crates/mandate-federation/tests/pkce.rs         | 178 +++++++
 crates/mandate-federation/tests/publicclient.rs | 182 +++++++
 9 files changed, 1981 insertions(+), 3 deletions(-)
```

Adversary files: `crates/mandate-federation/tests/adversary_pkce.rs` (12 cases, 4 red), `bins/mandate/tests/adversary_cli.rs` (6 cases, 3 red). Suites after: federation 115 executed, `adversary_pkce` 8 passed 4 failed, every other lane green; bin 12 executed, `adversary_cli` 3 passed 3 failed, `cli` 6 passed.

## Findings

```yaml
findings:
  - id: F1
    severity: medium
    verdict: CONFIRMED
    origin: introduced
    location: "crates/mandate-federation/src/pkce.rs:172"
    message: "StandInDigest is the crate's only PkceDigest implementation and answers 43-character values that are the base64url encoding of no 32-byte digest, so it is not BASE64URL-ENCODE(SHA256(..)) as the trait it implements requires, and every positive case in the unit's suite records one as the code record's challenge."
  - id: F2
    severity: medium
    verdict: CONFIRMED
    origin: introduced
    location: "crates/mandate-federation/src/pkce.rs:65"
    message: "challenge_is_well_formed is documented as deciding a 32-byte digest in unpadded base64url but admits three of every four 43-character base64url strings, which are the encoding of no value at all and therefore the S256 challenge of no verifier."
  - id: F3
    severity: high
    verdict: NEEDS-CHANGE
    origin: introduced
    location: "crates/mandate-federation/src/authorize.rs:188"
    message: "validate_authorization_code never reads code.target and copies it into the issuance input unexamined, so the declared denial condition 'target is unregistered/outside tenant' (federation.yaml:299-300) is undecided while the story's 'ESS command realized' section claims this unit realizes it."
  - id: F4
    severity: medium
    verdict: CONFIRMED
    origin: introduced
    location: "bins/mandate/src/main.rs:29"
    message: "A code verifier beginning with '-' is in RFC 7636 section 4.1's unreserved set and in the base64url alphabet the same section recommends generating from, and clap rejects it as an unexpected argument, so roughly one correctly generated verifier in sixty-four cannot be passed to the subcommand at all."
  - id: F5
    severity: medium
    verdict: CONFIRMED
    origin: introduced
    location: "bins/mandate/src/main.rs:29"
    message: "The subcommand prints a challenge for any string including the empty one, 42 and 129 characters, an interior space and non-ASCII, all of which the same change's verifier_is_well_formed refuses, so the CLI hands an operator a challenge the core it serves will never admit."
  - id: F6
    severity: medium
    verdict: CONFIRMED
    origin: introduced
    location: "bins/mandate/src/main.rs:29"
    message: "The verifier can only be supplied as a command-line argument, which places credential material in /proc/<pid>/cmdline and in every interactive shell's history, undoing the coordinator decision that the verifier is credential material and is never printed."
  - id: F7
    severity: low
    verdict: CONFIRMED
    origin: introduced
    location: "crates/mandate-federation/src/pkce.rs:170"
    message: "StandInDigest is pub in a shipped module with no cfg(test) and no doc(hidden) and is selectable by any dependent crate, and unlike the crate's other pub doubles it stands in for a cryptographic primitive rather than for a store."
  - id: F8
    severity: low
    verdict: CONFIRMED
    origin: introduced
    location: "crates/mandate-federation/src/authorize.rs:323"
    message: "federation.yaml:281-282 declares nonce as a required String and the file uses Optional nowhere, while nonce_matches admits a request that recorded no nonce at all; no caller can reach the state, so this is a document-versus-code disagreement rather than a hole."
  - id: F9
    severity: low
    verdict: CONFIRMED
    origin: introduced
    location: "crates/mandate-federation/src/authorize.rs:348"
    message: "An unparsable request instant denies InvalidCredential/CodeExpired, blaming the code for a reader that has no clock, where mandate-identity distinguishes the two and returns Unavailable; it fails closed, and the unit's 12-spelling pin varies expires_at only so this path has no case."
  - id: F10
    severity: low
    verdict: CONFIRMED
    origin: introduced
    location: "crates/mandate-federation/src/authorize.rs:158"
    message: "ValidationCandidate's documentation claims every declared condition held while possession of the code itself is never proven and no presented client_id exists to compare against code.client_id, both of which RedeemAuthorizationCode's denial names."
  - id: F11
    severity: low
    verdict: INFEASIBLE
    origin: introduced
    location: "crates/mandate-federation/src/publicclient.rs:40"
    message: "The OAuthClientStore implementation over Projection can only ever answer None because no declared event creates an OAuthClient, so unit B's real read model is unreachable until story:declared-writers lands and cannot be fixed in this story."
```

## Attacked and could not break

Redirect exactness (14 normalizations refused); verifier length boundaries 43/128; verifier alphabet; `plain` smuggled through S256 (refused `VerifierMismatch`); the RFC 7636 appendix B pair through the library predicate (admitted); the binary against an independent SHA-256 + base64url (six vectors, byte-identical); non-consuming and concurrent validation (equal candidates, records unchanged, `Consumed` refuses; the candidate carries `code_id`); the federation `instant::parse` copy (fail closed, no panic path); `equal_in_constant_time` (branch-free over equal lengths); the two `instant` modules are byte-identical copies. Could not establish: whether `Denied::clause` is ever rendered to a caller; whether any deployment would select `StandInDigest`.

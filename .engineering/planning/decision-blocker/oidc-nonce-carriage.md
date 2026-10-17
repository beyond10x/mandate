---
format: aep.planning-md/3
id: decision-blocker:oidc-nonce-carriage
kind: decision-blocker
status: cleared
title: OIDC-NONCE — where the authorization request's nonce lives between authorize and redemption
relations:
- blocks: story:oidc-signed-tokens-and-key-rotation
revision: 3
transitions:
- {from: "open", to: "cleared", at: "2026-10-17T19:33:57Z", actor: "human:timo", revision: 3}
---
# OIDC-NONCE — where the authorization request's nonce lives between authorize and redemption

## What is undecided

`mandate.credential.RedeemAuthorizationCode` (`systems/mandate/domains/credential.yaml:305`) signs an
identity token whose nonce is "the authorization request's", and says no claim value, the nonce
included, enters `IdentityTokenIssued` (fork F13). Nothing in the specification carries the nonce
from `AuthorizeClient` (`federation.yaml:382`) to redemption: neither `IssueAuthorizationCode` nor the
`AuthorizationCode` record nor `AuthorizationCodeIssued` has a nonce field. The same gap holds for
the granted identity scopes (whether `openid` was granted) and, on the session binding
(`services/sts/src/binding.rs:80`), for `auth_time` and the connection and upstream subject that the
Dex-compatible subject (fork F1) needs.

## Options

- **A. Record the nonce on the code** (record and `AuthorizationCodeIssued`), with the identity
  scopes. A code survives a restart, as the durable single replica (fork F9) intends; this is how
  Dex keeps it. Cost: a client-chosen value enters the append-only log (not a credential and not
  personal data; it is already in the browser's URL and in the issued token); redaction per ADR 0009
  if ever needed.
- **B. Hold the nonce in memory beside the code, for the code's lifetime (300 s)**, as the pending
  sign-in already is (`PendingLogin`). The log stays free of client values. Cost: codes outstanding at
  a restart are refused at redemption and the app restarts the login; a second, non-event-sourced
  store for in-flight state.

Both carry the identity scopes on the code record, and `auth_time`, connection and upstream subject
on the session binding, as specification fields.

## Recommendation

A: the code's other properties are already in the log, the nonce is not secret, and B makes a
restart visible to every signed-in app.

## What it blocks

The identity token at redemption (story:oidc-signed-tokens-and-key-rotation) and with it the
epic's acceptance.

## Decided

2026-10-17, by the coordinator: **B**. The nonce is held in memory beside the authorization code for
the code's 300 s life, as `PendingLogin` holds the sign-in; the append-only log stays free of
client values. A code outstanding at a restart is refused at redemption and the app restarts the
login. B can be undone (moving to A later only adds a field to the code record and event); A
cannot (client values stay in the append-only log). The identity scopes go on the code record, and
`auth_time`, the connection and the upstream subject on the session binding, as specification fields.

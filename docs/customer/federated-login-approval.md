# Signing in to Mandate with your existing accounts

For your approval. Text mirror of the PDF produced by `build.sh`; the PDF is the version to share.

## What your users experience

A user signs in to your platform the way they do today. When they reach a Mandate-protected service they are already signed in. There is no second password and no separate account to create. The first time a given user arrives, Mandate creates their account automatically from the proof your identity provider issued; every later visit finds it. Nobody — not you, not us — does anything per user.

## How the sign-in works

1. The user signs in to your platform. Your identity provider issues a signed proof of who they are.
2. The user's browser presents that proof to Mandate. Mandate checks — in this order — that the proof came from the identity provider you registered, that its signature is valid, that it was issued to the registered client, that the one-time values match the request, and that it names your organization through the claim you told us to trust. If any check fails, or the proof could belong to more than one organization, the sign-in is refused. Mandate never guesses.
3. If this is the user's first visit and you have chosen automatic account creation, Mandate creates the account and the link to your identity provider's subject identifier. Otherwise it finds the existing link.
4. Mandate establishes a session.
5. Your application asks Mandate for a token on the user's behalf, using the standard authorization-code flow with PKCE. Mandate issues a short-lived token scoped to exactly one audience — the service it is meant for — and to no more authority than the user holds.
6. Your application calls the Mandate-protected service with that token.
7. The service checks the token with Mandate before acting on it. A revoked or expired token is refused at that check.

## The token your application receives

| | |
|---|---|
| Who it is for | One audience: the specific Mandate-protected service. A token for one service is refused by every other. |
| What it carries | The user, your organization, the audience, the narrowed scope, and an expiry. It never carries your identity provider's token or anything from it. |
| How long it lives | Minutes, not days. Your application refreshes through the session rather than holding long-lived credentials. |
| How a service trusts it | By checking with Mandate, or by verifying Mandate's signature against Mandate's published keys. Services never talk to your identity provider. |

## Setting it up

| # | Step | Who |
|---|---|---|
| 1 | Register Mandate as a client in your identity provider and note the client identifier it assigns. | You |
| 2 | Send us the items in the table below. | You |
| 3 | We register a federation connection bound to your organization, with the claim that identifies your tenant and the signing algorithms your provider uses. | We |
| 4 | We register your applications' exact redirect addresses. | We |
| 5 | You confirm automatic account creation on first sign-in, or tell us you will provision users ahead of time. | You |
| 6 | We open a test environment against your identity provider; a user of yours signs in end to end. | Both |
| 7 | Go-live. Everything after this is per-organization configuration, never per-user work. | Both |

### What we need from you

| Item | Why |
|---|---|
| The issuer URL of your identity provider | It is the trust anchor; Mandate accepts proofs from nowhere else. |
| The client identifier assigned to Mandate | So a proof issued to another application is refused. |
| The address where your provider publishes its signing keys | So signatures are verified against your current keys; rotating keys on your side needs nothing from us. |
| The exact claim that identifies your organization, and its value | This is the only thing that places a user in your organization. |
| The signing algorithms your provider uses | Mandate accepts a fixed, configured list and refuses everything else. |
| The redirect addresses of the applications that will sign in | Only exact registered addresses are accepted. |
| Your choice on automatic account creation | Recommended; the alternative is provisioning users ahead of time. |

## Taking access away

| Situation | Trigger | Effect |
|---|---|---|
| A user leaves your organization | You disable them in your identity provider. | Their next Mandate session refresh is refused. Tell us, and we end their sessions at once. |
| One session looks compromised | You or we end that session. | Every token issued from it is refused on its next check. |
| One token is exposed | We revoke that token. | The next check by any service reports it inactive. |
| You need a security reset for one user | We advance that user's security generation. | All of their sessions and tokens become stale immediately. |
| You need to cut the whole connection | We disable the connection. | Every session that came through it is invalidated; nothing new is accepted. |

Two things hold in every row. Revocation is fail-closed: a token or session that has been revoked is refused on its next check, and no cached earlier answer overrides that. And nothing is deleted: the fact that a session existed and was ended is retained; where a record must be removed for privacy, it is redacted in place and the redaction itself is recorded.

## What we will not do

- We do not create or store passwords for your users.
- We do not merge two accounts because they share an email address. Email is displayed and used for invitations; it never establishes identity.
- We do not pass your identity provider's token on to any service. Services receive a Mandate-issued token scoped to what they need, and nothing of yours.
- We do not derive your organization from an email domain, a hostname, or anything a user typed.
- We do not delete sign-in history or account records.

## Where this stands

The behaviour above is specified and reviewed. The components that implement it are being built in stages. The first stage delivers the sign-in path and token issuance with an internal verification step; signature verification against your provider's published keys goes live once the supporting library is admitted. We will tell you when the test environment in step 6 is ready for your identity provider.

## Approval

| | |
|---|---|
| Approved by | |
| Organization | |
| Date | |
| Automatic account creation on first sign-in | yes / no |

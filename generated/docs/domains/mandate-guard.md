<!--
generated from mandate v1
model digest 751472a620cc3a7650f9a2496c9e81022fbef0887158483d3bbd761f09e76837
contract digest slice-sha256/2:275b42d00514b7ac1e039b1b2e538b0f298918ced54aa6bad4b3559acc98c4e5
do not edit: regenerate with `ess generate`
-->

# guard

`mandate.guard` is one of mandate's bounded contexts. [Back to the index](../index.md).

## Types

### `AllowRule`

`mandate.guard.AllowRule` is a record of two fields:

- `emails` — `List<mandate.guard.EmailAddress>`
- `domains` — `List<mandate.guard.EmailDomain>`

### `EmailAddress`

`mandate.guard.EmailAddress` wraps `String` and is not interchangeable with one: the whole value of naming it separately is the crossings the model then refuses.

### `EmailDomain`

`mandate.guard.EmailDomain` wraps `String` and is not interchangeable with one: the whole value of naming it separately is the crossings the model then refuses.

### `GroupName`

`mandate.guard.GroupName` wraps `String` and is not interchangeable with one: the whole value of naming it separately is the crossings the model then refuses.

### `GuardLimits`

`mandate.guard.GuardLimits` is a record of three fields:

- `per_minute` — `Integer`
- `burst` — `Integer`
- `queue` — `Integer`

### `GuardPolicy`

`mandate.guard.GuardPolicy` is a record of five fields:

- `issuer` — `mandate.core.Issuer`
- `audiences` — `List<mandate.core.Audience>`
- `allow` — `mandate.guard.AllowRule`
- `limits` — `mandate.guard.GuardLimits`
- `clock_skew` — `Duration`

### `RefusalReason`

`mandate.guard.RefusalReason` is one of `Malformed`, `InvalidSignature`, `UnknownKey`, `IssuerMismatch`, `AudienceMismatch`, `Expired`, `NotYetValid`, `IdentityNotAllowed`, `OverLimit` and `QueueFull`.

One of the types above is reached by nothing else in this system: `mandate.guard.GroupName`. No entity, view, command, event, error or crossing names it, so it is either vocabulary something outside this specification uses or a leftover — and only a person can tell which.

## Commands

### `AdmitRequest`

`mandate.guard.AdmitRequest`.

It takes:

- `policy` — `mandate.guard.GuardPolicy`
- `token` — `mandate.core.CredentialProof`

It has 11 outcomes.

**`accepted`** — The token is a compact JWS signed by a key in the issuer's JWK Set, its iss is the policy's issuer, its aud names one of the policy's audiences, the clock is within its nbf and exp widened by the policy's clock skew, the identity passes the allow rule, and its bucket and the waiting queue have room. The verified identity is returned for the service; nothing is created or moved, and the event folds into no record. The default branch, taken when no other outcome's condition matched. No entity in this specification changes. It emits `mandate.guard.RequestAdmitted`. A test reaches it by constructing an input that satisfies no other outcome's condition.

**`malformed`** — Decided outside the input: The token is not a compact JWS, its header names no key or an algorithm the guard does not admit, or its claims lack iss, sub, aud or exp.. No predicate over the input reaches this branch, and saying `when: false` instead would have claimed it is unreachable, which is a different and false statement. No entity in this specification changes. It reports `mandate.guard.Refused`, carrying `reason`. It emits nothing. A test reaches it by injecting the declared fault, because no input can.

**`invalid-signature`** — Decided outside the input: The signature does not verify under the key its kid names.. No predicate over the input reaches this branch, and saying `when: false` instead would have claimed it is unreachable, which is a different and false statement. No entity in this specification changes. It reports `mandate.guard.Refused`, carrying `reason`. It emits nothing. A test reaches it by injecting the declared fault, because no input can.

**`unknown-key`** — Decided outside the input: The kid is absent from the issuer's JWK Set as the guard last fetched it. A held set is refetched once it reaches its maximum age (15 minutes unless configured), so a key the issuer withdrew stops verifying within that age; an unknown kid refetches it sooner, at most once per bounded refresh interval.. No predicate over the input reaches this branch, and saying `when: false` instead would have claimed it is unreachable, which is a different and false statement. No entity in this specification changes. It reports `mandate.guard.Refused`, carrying `reason`. It emits nothing. A test reaches it by injecting the declared fault, because no input can.

**`issuer-mismatch`** — Decided outside the input: The token's iss is not the policy's issuer.. No predicate over the input reaches this branch, and saying `when: false` instead would have claimed it is unreachable, which is a different and false statement. No entity in this specification changes. It reports `mandate.guard.Refused`, carrying `reason`. It emits nothing. A test reaches it by injecting the declared fault, because no input can.

**`audience-mismatch`** — Decided outside the input: No aud of the token is one of the policy's audiences.. No predicate over the input reaches this branch, and saying `when: false` instead would have claimed it is unreachable, which is a different and false statement. No entity in this specification changes. It reports `mandate.guard.Refused`, carrying `reason`. It emits nothing. A test reaches it by injecting the declared fault, because no input can.

**`expired`** — Decided outside the input: The clock is past exp by more than the policy's clock skew.. No predicate over the input reaches this branch, and saying `when: false` instead would have claimed it is unreachable, which is a different and false statement. No entity in this specification changes. It reports `mandate.guard.Refused`, carrying `reason`. It emits nothing. A test reaches it by injecting the declared fault, because no input can.

**`not-yet-valid`** — Decided outside the input: The clock is before nbf by more than the policy's clock skew.. No predicate over the input reaches this branch, and saying `when: false` instead would have claimed it is unreachable, which is a different and false statement. No entity in this specification changes. It reports `mandate.guard.Refused`, carrying `reason`. It emits nothing. A test reaches it by injecting the declared fault, because no input can.

**`identity-not-allowed`** — Decided outside the input: The rule is not empty, and the token carries no email, an email the issuer has not verified, or one neither listed in allow.emails nor in a domain listed in allow.domains.. No predicate over the input reaches this branch, and saying `when: false` instead would have claimed it is unreachable, which is a different and false statement. No entity in this specification changes. It reports `mandate.guard.Refused`, carrying `reason`. It emits nothing. A test reaches it by injecting the declared fault, because no input can.

**`over-limit`** — Decided outside the input: The identity's bucket, refilled at limits.per_minute and holding at most limits.burst, is empty; other identities are admitted on their own buckets.. No predicate over the input reaches this branch, and saying `when: false` instead would have claimed it is unreachable, which is a different and false statement. No entity in this specification changes. It reports `mandate.guard.Refused`, carrying `reason`. It emits nothing. A test reaches it by injecting the declared fault, because no input can.

**`queue-full`** — Decided outside the input: limits.queue requests are already waiting; the request is refused at once, never buffered.. No predicate over the input reaches this branch, and saying `when: false` instead would have claimed it is unreachable, which is a different and false statement. No entity in this specification changes. It reports `mandate.guard.Refused`, carrying `reason`. It emits nothing. A test reaches it by injecting the declared fault, because no input can.

## Events

### `RequestAdmitted`

`mandate.guard.RequestAdmitted`.

It carries:

- `issuer` — `mandate.core.Issuer`
- `subject` — `mandate.core.ExternalSubject`
- `audience` — `mandate.core.Audience`
- `admitted_at` — `Timestamp`

Emitted by `mandate.guard.AdmitRequest` on its `accepted` outcome.

Nothing in this system reacts to it.

## Errors

### `Refused`

Fail closed; the request does not reach the service and nothing is recorded. The reason names the clause that refused it, the same in the library and the sidecar.

It carries:

- `reason` — `mandate.guard.RefusalReason`

Reported by `mandate.guard.AdmitRequest` on its `malformed`, `invalid-signature`, `unknown-key`, `issuer-mismatch`, `audience-mismatch`, `expired`, `not-yet-valid`, `identity-not-allowed`, `over-limit` and `queue-full` outcomes.


---

Generated from mandate v1 · model digest `751472a620cc3a7650f9a2496c9e81022fbef0887158483d3bbd761f09e76837` · contract digest `slice-sha256/2:275b42d00514b7ac1e039b1b2e538b0f298918ced54aa6bad4b3559acc98c4e5`. Do not edit this file; change the specification and regenerate it with `ess generate`.

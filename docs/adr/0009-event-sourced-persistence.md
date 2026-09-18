# Event-sourced persistence through the organization event log

Status: accepted by the operator on 2026-09-18.

## Decision

Every durable state in this repository is implemented with the organization's `eventlog` kit. A command produces domain events; the events are the record; every read is a fold over them — from a snapshot, from the log, or from both. State tables are projections: derived, droppable, rebuildable, never authoritative. Data is never thrown away.

The kit is consumed as a library, never run as a service. It is pinned by its bare-version Git tag; the first pin is `0.2.1`. It is repinned to the next release when that release lands; the work in flight there is recorded under `### Fixed` with no API removal, so a repin is expected to be a version bump. The kit's SQLite backend is `:memory:`-capable, which is why a property proved in a test is proved for the deployment.

## What follows for decisions already taken

`decision-blocker:lifecycle` resolves to immutable-with-status because the log admits nothing else: a lifecycle change is a new event, and the projection's status column is derived from it. Retention and privacy obligations are met by the kit's erasure and redaction, which rewrite the projection and record the fact of the rewrite, rather than by deletion. A record that must disappear for privacy is redacted in place; the audit that it existed and was redacted is itself retained.

`decision-blocker:identity-uniqueness` places its unique index on the projection, not on the log. The log is append-only and has no unique key beyond the stream coordinate; the composite external key `(organization, connection.issuer, external subject)` is enforced where the fold materializes it, and the conflict-detection path that returns the declared denial reads that projection inside the same transaction.

`decision-blocker:epoch-atomicity` is satisfied by the kit's own transaction. Its aggregate append is a compare-and-set on the expected stream version; required projections and the audit outbox commit or roll back with the group. No second mechanism is introduced.

`decision-blocker:guards` writes a denial to the audit stream, a separate stream from the refused domain aggregate, so the denial is durable though the domain append was refused.

`decision-blocker:worker-orchestration` takes a queue in the same store, polled by the worker, behind a trait so the transport can change. The kit's tenant-scoped idempotency identity on append groups is what makes a redelivered job safe to apply.

## Consequences for the workspace

Adding the kit is a coordinator change under `task:runtime-wave-integration`: the workspace `Cargo.toml` gains the git-pinned dependency; `dependency-boundaries.json` admits it to each consuming crate's array, since the checker applies a crate's own array in full and falls back to `external` only for packages it does not list; `deny.toml` admits the git source. The package and library counts the gate asserts are unaffected, because the kit is external. None of this is wired until the first crate consumes it; a workspace dependency no member references does not enter the lockfile and proves nothing.

Every stream coordinate in the kit carries an explicit tenant, and projection callbacks are confined to the current transaction's tenant. The owning host derives that tenant from current authority before calling the store. This is the same isolation root the domain declares: every tenant-owned record resolves to exactly one organization. The kit does not authenticate a caller or grant domain access; that remains this repository's.

## Not decided here

Which backend each deployment runs — SQLite, PostgreSQL or the JSONL file provider — is a deployment decision, recorded when a deployment exists. The graph and policy backend under `decision-blocker:backend` is constrained by this record (its state is a projection too) but not selected by it. The concrete retention floor for audit records under `decision-blocker:lifecycle` is still owed.

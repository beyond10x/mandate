---
format: aep.planning-md/1
id: decision-blocker:async-runtime
kind: decision-blocker
status: open
title: UNMAPPED-RUNTIME — no async runtime is admitted, and the event log's surface is async
relations:
- blocks: story:domain-folds-over-the-kit
revision: 1
---
# UNMAPPED-RUNTIME — no async runtime is admitted, and the event log's surface is async

## What is undecided

`eventlog-core`'s `EventStore` is an async trait (`crates/eventlog-core/src/lib.rs:59` at tag
`0.3.0`: *"The store surface is async, but a native `async fn` in the trait would cost `dyn
EventStore`"*), and every `eventlog-sqlite` entry point is `pub async fn`, including
`SqliteEventStore::in_memory` (`crates/eventlog-sqlite/src/lib.rs:118`). This repository admits no
async runtime: `tokio` appears in neither the workspace `Cargo.toml` nor `dependency-boundaries.json`.

So `docs/adr/0009-event-sourced-persistence.md`, accepted by the operator on 2026-09-18, cannot be
carried out by any crate, and has not been: no `.rs` file in this repository references the kit. The
three mentions that exist are comments saying it is the next milestone
(`services/control-plane/src/adapters.rs:2113`, `services/sts/src/store.rs:43,500`).

This was measured once already and deferred. `docs/plans/2026-09-18-wave-3-execution.md:13` records it
as stop condition **S1**: *"`tokio` admitted nowhere though every `eventlog-sqlite` call needs a
runtime"*, listed with S3 as *"coordinator admissions before the next dispatch"*. Four waves have run
since. `task:runtime-wave-integration:37` still lists the kit as pending wiring *"when the first crate
consumes it"*, and no crate does.

## What it blocks

Every fold in the repository is hand-written and synchronous, and the substitutes were admitted
one wave at a time, each with a reason of its own. `docs/plans/2026-09-19-wave-c-execution.md:24`,
verbatim: *"`eventlog-core` is not admitted (the in-memory fake is a test double with the kit's shape,
ADR 0009: no second mechanism)."* The ADR's own argument for the kit's in-memory backend —
*"which is why a property proved in a test is proved for the deployment"* — is what those doubles do
not deliver.

`services/worker` and `crates/mandate-provisioning` name the kit in their manifests and use it
nowhere; they carry it as an unused dependency.

## What a decision looks like

The options are not symmetric and the operator decides between them:

1. **Admit an async runtime** to the crates that own durable state, with an admitted ceiling — the
   kit's own providers run their blocking work through `run_blocking`
   (`eventlog-sqlite/src/lib.rs:132`), so what is admitted is a runtime, not an async rewrite of the
   domain. This is the option ADR 0009 assumed.
2. **Ask the kit for a blocking facade**, which is a change in another repository and a contract of
   its own.
3. **Record that the domain stays synchronous and the ADR is narrowed** to the deployment boundary,
   which is a reversal of an accepted decision and should be written as one rather than arrived at by
   four more waves of doubles.

Until one of those is recorded, a story that proposes to persist anything is proposing a second
mechanism.

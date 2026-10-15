# Wave 9 (tooling): proposal and execution

Opened 2026-10-15 on `integration/wave-20261015-001`, cut from `main` at `04e1465` (0.9.0).
Approved by the operator before it was proposed. Story: `story:tooling-repin-0-73-0-60`
(`epic:foundations`).

Purpose: the store, the specification and the gate run on the tools installed for this
repository: AEP 0.73.0 and ESS 0.60.0, with Rust as `rust-toolchain.toml` says (1.98.1).

Width: one unit. Every change lands on the same pins, the same generated tree and the same gate
(`Cargo.toml`, `Cargo.lock`, `generated/`, `xtask/src/main.rs`); split units would all touch them.

## Spec first

- `aep plan store migrate git --dry-run` under AEP 0.73.0: "`.engineering/project.yaml` already
  selects `aep.project/5` and no transition repeats the one before it; nothing to migrate or
  repair, and nothing was written". No `--verify` run follows: there is nothing to verify.
  `aep plan artifact validate` prints `valid`.
- `systems/mandate/ess-inputs.yaml` moves to `format: ess-inputs/2` and declares
  `requires: ess 0.60.0` (`ess generate` under 0.60.0 refuses `requires` in `ess-inputs/1`:
  "`requires` needs format ess-inputs/2"). `ess specify validate
  --strict-requires --path systems/mandate` under 0.60.0: valid, the same two `ESS-ENTITY-019`
  warnings as under 0.59.0 (`mandate.audit.AuditEvent` `source_credential_id`,
  `issued_credential_id`). The gate's validation (`xtask/src/main.rs`, `contracts`) now passes
  `--strict-requires`.

## Pins

- `Cargo.toml`: `ess-conformance`, `ess-primitives`, `ess-domain` at 0.60.0. The lock gains
  `ess-yaml` and `serde_norway`; `serde_yaml` and `unsafe-libyaml` leave it, so the scoped
  advisory ignore in `deny.toml` goes.
- `xtask/src/main.rs`: `ess 0.60.0`, `aep 0.73.0`; `xtask/src/conform.rs` and
  `xtask/src/emit.rs` name 0.60.0.
- `.github/workflows/ci.yml` installs `ess:0.60.0 aep:0.73.0`.
- `README.md`, `AGENTS.md`, `docs/public/development.md` name Rust 1.98.1, ESS 0.60.0, AEP 0.73.0.

## Results

- Regeneration under ESS 0.60.0: `cargo xtask adopt` then `cargo xtask generate`; "ESS projections
  match deterministically". `generated/` changes in 5 files, 7 lines: the `ess 0.59.0` header of the
  four emitted `mandate-contract` sources and the coverage receipt's `ess_version`, `source_digest`
  and `contract_crate_digest`. The compiled IR is byte-identical (`ir/system.json` sha256
  `570126bd…` in both headers).
- `cargo xtask conform` under 0.60.0: 185 scenarios, 48 passed, 73 failed, 0 error, 64
  unsupported, 0 skipped: the same counts as under 0.59.0. Peak `target/` 1001M.

## Hardening

Run: technique 7, the compatibility diff. Planted first: `mandate.audit.AuditEvent.subject` made
required in a scratch copy; `ess verify diff --from <main> --to <planted> --fail-on
breaking-or-unknown` exits 4 naming `entity/mandate.audit.AuditEvent/field-type-changed/subject`.
Then the real change, `main` (0.59.0 inputs) to this wave's inputs: exit 0, "no semantic change:
these two revisions mean the same system".

Not run, with the reason: the design review (8), guard analysis (6), random sequences (2),
determinism (4), metamorphic relations (5) and caller replay (3). This wave changes no declaration
and the IR is byte-identical, so each would measure the same system as under 0.59.0; the spec
conformance audit that follows this wave is the design review of the specification against code and
documents. The mutation audit (1) stays the gate's `xtask mutants` step, run by CI's full gate.

```findings
[]
```

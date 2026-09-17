# Build and review the foundations

Mandate is a Rust 2024 workspace with 14 library crates, four service packages, a CLI, and a Rust `xtask`. All packages are version 0.1.0 with `publish = false`; the lockfile is committed.

## Validate locally

Install Rust 1.98.1, ESS 0.25.0, AEP 0.55.0, Task, and cargo-deny, then run from the repository root:

```bash
task check
```

This checks formatting, clippy, workspace compilation and tests, dependency policy and crate boundaries, ESS validation, deterministic regeneration, structural acceptance scenarios, AEP validation, and help/version smoke checks. It does not start services or exercise runtime authorization.

## Regenerate the references

```bash
cargo xtask generate
```

ESS owns all generated output. Each generator receives `generated/` as its root and writes its own `schema/`, `openapi/`, `docs/`, or `docs-ir/` directory. The interactive viewer consumes `generated/docs-ir/document.json`; Markdown and semantic OpenAPI come from the same accepted contracts. Never edit a generated projection by hand.

## Find the source

- [ESS input manifest and system](https://github.com/beyond10x/mandate/tree/main/systems/mandate)
- [Original design snapshot](https://github.com/beyond10x/mandate/blob/main/docs/sources/original-design.md)
- [Architecture addendum snapshot](https://github.com/beyond10x/mandate/blob/main/docs/sources/architecture-addendum.md)
- [Combined architecture](https://github.com/beyond10x/mandate/blob/main/docs/architecture/combined.md)
- [Threat model](https://github.com/beyond10x/mandate/blob/main/docs/threat-model/README.md)
- [Requirements and roadmap mapping](https://github.com/beyond10x/mandate/blob/main/docs/requirements.md)

The authorization service package is `mandate-authorization` and its binary is `mandate-authz`; the `mandate-authz` library remains a separate package. All binaries currently expose help/version only.

Mandate remains standalone. This milestone does not deploy services or migrate Identity.

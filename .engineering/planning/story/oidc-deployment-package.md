---
format: aep.planning-md/3
id: story:oidc-deployment-package
kind: story
status: active
title: Mandate ships as a container image and a Helm chart with health and readiness
relations:
- decomposes: epic:openid-provider
- serves: vision:mandate
revision: 3
transitions:
- {from: "draft", to: "proposed", at: "2026-10-16T21:58:37Z", actor: "human:timo", revision: 2, decided_on: {"asserted":{"review_outcome":1}}}
- {from: "proposed", to: "active", at: "2026-10-16T21:58:37Z", actor: "human:timo", revision: 3, decided_on: {"asserted":{"review_outcome":1}}}
---
# Mandate ships as a container image and a Helm chart with health and readiness

Parity story 7, first half (packaging). The durable-state half is `story:oidc-durable-state`; the
two are split because this half depends on nothing and the other on the persistence runtime.

## Why

**Exists:** the `mandate-control-plane serve` binary with clap flags and exit statuses 1/2
(`services/control-plane/src/main.rs:79-185`); `deploy/helm/README.md`, `deploy/docker/README.md`
and `examples/oidc-federation/README.md` say "Reserved for the reviewed roadmap" — no Dockerfile,
no chart; no health or readiness route (`crates/mandate-server/src/routes.rs:120-166`); configuration
is files and `NAME=PATH` secret references, which map one-to-one onto ConfigMap and Secret mounts.
Dex's chart exposes `/healthz/live` and `/healthz/ready` on a telemetry port, a ConfigMap of
connectors and static clients, and secret environment variables.

**New:** a multi-stage container image (static or distroless, non-root, read-only root filesystem);
`GET /healthz/live` (process answers) and `GET /healthz/ready` (configuration admitted, signing key
valid now, storage reachable once `story:oidc-durable-state` lands, upstream discovery cached);
a Helm chart under `deploy/helm/mandate` rendering one Deployment (`replicas: 1`, `Recreate`), a
Service, ConfigMap-mounted connection and client documents, Secret-mounted client secrets, signing
keys and service-account key, a PersistentVolumeClaim (used by the durable-state story), probes, a
NetworkPolicy allowing egress only to the upstream hosts, and an HTTPRoute for Envoy Gateway; a
`--config-dir` flag that reads every document from mounted directories so the chart needs no
per-file argument list.

## Acceptance

- `routes::health_paths_are_not_command_shaped`: the two health routes join `ROUTES`, bind a
  `Document`, and the disjointness test still holds.
- `end_to_end::ready_reflects_signing_key`: readiness answers `503` before a valid signing key is
  admitted and `200` after; liveness answers `200` throughout.
- `control_plane::config_dir_equivalent_to_flags`: a directory of documents produces the same
  printed configuration as the equivalent repeated flags; an unknown file in it exits 2.
- `cargo xtask chart-check` (a Rust `xtask` step, no script): `helm template` of the chart with the
  example values renders, every mounted path matches a flag the binary admits, the pod runs
  non-root with a read-only root filesystem, and no Secret value appears in a ConfigMap.
- The image builds in CI from the tagged commit and runs `mandate-control-plane --version`.
- `examples/oidc-federation/README.md` shows one Google connection and one confidential client as
  values.
- No ESS change: health is a wire document (fork F14).

## Scope

- `deploy/docker/Dockerfile`, `deploy/helm/mandate/{Chart.yaml,values.yaml,templates/*}`,
  `examples/oidc-federation/`.
- `crates/mandate-server/src/routes.rs`, `metadata.rs` (health documents),
  `crates/mandate-server/tests/routes.rs`.
- `services/control-plane/src/main.rs` (`--config-dir`), `serve.rs` (dispatch).
- `xtask/src/` (chart check), `.github/workflows/ci.yml` (image build).

Collides with `story:oidc-discovery-and-code-flow` on `routes.rs` and `routes.rs` tests — merge
order matters, not parallel safety of logic.

## Out of scope

More than one replica, autoscaling, TLS in the process (terminated at the gateway), a published
registry or chart repository release (a release decision), the downstream platform's values.

## Depends on

Nothing for packaging and health. Readiness of storage waits for `story:oidc-durable-state`. Fork F22.

## Size

**M — 2 implementor-days.** Mechanical but broad: image, chart, two routes, one flag, one xtask
step. Risk is in the repository rule that checks are Rust — the chart check must be an `xtask`
step invoking `helm`, not a shell script.

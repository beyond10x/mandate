# The Mandate control plane as a container image.
#
# Build from the repository root, at the tagged commit:
#   docker build -f deploy/docker/Dockerfile -t mandate-control-plane .
#
# The image runs as a non-root user and writes nothing to its own filesystem, so it runs with a
# read-only root filesystem. Configuration is read from mounted files: every document and
# secret file, by `--config-dir` or by the repeated flags.

FROM rust:1.98.1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked --package mandate-control-plane

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /src/target/release/mandate-control-plane /usr/local/bin/mandate-control-plane
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/mandate-control-plane"]
CMD ["--help"]

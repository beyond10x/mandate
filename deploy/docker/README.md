# deploy/docker

`Dockerfile` builds `mandate-control-plane` into a distroless, non-root image that needs no
writable filesystem. Build it from the repository root:

```console
docker build -f deploy/docker/Dockerfile -t mandate-control-plane .
docker run --rm mandate-control-plane --version
```

The image's command is `--help`; a deployment passes `serve` and its flags. `serve --config-dir
DIR` reads every document from a mounted directory: `connections/`, `keys/`, `clients/` and
`resource-servers/` hold `*.json` documents, and each file of `client-secrets/` is the client
secret named for it. Any other entry is refused with exit status 2.

The probes are `GET /healthz/live` (the process answers) and `GET /healthz/ready` (`503` until a
signing key is admitted, `200` after).

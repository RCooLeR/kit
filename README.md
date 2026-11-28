# kit

Small Go packages for HTTP services: build information, secrets from files, an HTTP server with
health endpoints, JSON errors, retries, logging, Prometheus metrics, PostgreSQL and migrations,
MQTT and Home Assistant discovery, password hashing, and the client of the Herald notification service.

**Status: before 1.0.** No version is tagged yet, interfaces may still change, and there is no
compatibility promise. Changes are listed in [CHANGELOG.md](CHANGELOG.md). The TypeScript
counterpart is [web-kit](https://github.com/RCooLeR/web-kit).

Three rules shape the module:

- **Extracted, not designed.** A package is copied from the best existing implementation when a
  second service needs it. The first consumer is Herald, a notification service.
- **No published names.** The kit never composes a metric name, a topic, an entity ID, a health
  path or a response body. Those are inputs from the service, so adopting a package cannot rename
  anything a dashboard or another service depends on.
- **Split by weight.** Importing `kit/buildinfo` pulls in no PostgreSQL driver. `weight_test.go`
  checks the real import graph of every package against a list of heavy dependencies it must not
  reach.

## Packages

| Package | What it does | Depends on |
|---|---|---|
| `buildinfo` | `Version`, `Commit`, `Date` set with `-ldflags`, `Info()` | standard library |
| `secret` | Resolves a value or its `*_FILE`; `Strict` refuses both at once, `Legacy` keeps the older precedence | standard library |
| `healthcheck` | Probe URL from the listen address, one GET, 2xx check | standard library |
| `healthcheck/healthcheckcli` | The probe as a `healthcheck` subcommand | urfave/cli v3 |
| `httpserver` | Server with all four timeouts, graceful shutdown, liveness and readiness handlers | standard library |
| `jsonhttp` | `WriteJSON`, `WriteError` with the `{"error":{"code","message"}}` envelope | standard library |
| `retry` | Next backoff delay, jitter, context sleep, `Retry-After` | standard library |
| `herald` | Client of the Herald notification service: send events, register addresses, set a user's preferences, spool to disk while Herald is unreachable; verify the signed answer callbacks | standard library |
| `webauth` | argon2id password hashes, random tokens stored as digests, a login attempt limiter, authenticator app TOTP | x/crypto |
| [`webauth/oidcsso`](webauth/oidcsso/README.md) | OpenID Connect sign-in for independently registered applications, with PKCE and optional issuer MFA | go-oidc, x/oauth2 |
| [`webauth/federation`](webauth/federation/README.md) | The browser side of OpenID Connect sign-in for an application with its own accounts: the client file, `POST /api/v1/federation/start` and `GET /api/v1/federation/callback` with attempts bound to one browser and consumed once, passive checks, brokered social buttons, and linking a signed-in account | `webauth/oidcsso` |
| `hamqtt` | Home Assistant MQTT discovery configs and topics, with checks of every ID the caller passes | standard library |
| `cockpit` | An application's cockpit summary: `GET /api/v1/cockpit` behind a bearer key from a file (constant-time check, 404 without a key), and the answer's types | standard library |
| `mcpx` | An application's Model Context Protocol endpoint: `/mcp` over Streamable HTTP without sessions, behind a bearer key from a file (constant-time check, 404 without a key); body and time limits, panic recovery, one report per tool call without its arguments, and only deliberate errors reach the client | MCP Go SDK |
| `mcpx/mcpxtest` | Tests of an application's tools: an in-memory session, tool calls read as text, a check that no output shows a secret | MCP Go SDK |
| `mqttx` | MQTT client for publishing services: availability with a last will, QoS 1 publish, replay after a reconnect or a Home Assistant restart | Eclipse Paho |
| `logx` | A service's root zerolog logger, and a `log/slog` bridge | zerolog |
| `promx` | Private registry, `/metrics` handler, build-info gauge with the caller's name | client_golang |
| `dbpg` | pgx pool with a startup ping and an optional wait for a database that is still starting; password into a DSN | pgx |
| `dbmigrate` | golang-migrate over an embedded file system: `Up`, `Down`, `Check` | golang-migrate, pgx |
| `testpg` | A fresh schema per test in a disposable database | pgx |

A service stamps its version into the kit's package, so it needs no build-information package of
its own:

```sh
go build -ldflags "-X github.com/RCooLeR/kit/buildinfo.Version=1.4.0 \
  -X github.com/RCooLeR/kit/buildinfo.Commit=$(git rev-parse HEAD) \
  -X github.com/RCooLeR/kit/buildinfo.Date=$(date -u +%Y-%m-%dT%H:%M:%SZ)" ./cmd/service
```

Health endpoints take their exact answers from the service, because probes and dashboards depend
on them:

```go
noContent := httpserver.Response{Status: http.StatusNoContent}
mux.Handle("GET /healthz", httpserver.Live(noContent))
mux.Handle("GET /readyz", httpserver.Ready(store.Ping, noContent,
    httpserver.Response{Status: http.StatusServiceUnavailable}, logFailure))
```

`promx` leaves everything that changes the `/metrics` output off unless asked for (runtime
collectors, OpenMetrics, the handler's error counter), so an existing exporter that adopts it
scrapes as before. New services switch them on.

## Using the module

No version is tagged yet. Pin a commit of `main`:

```
go get github.com/RCooLeR/kit@<commit>
```

This writes a pseudo-version (`v0.0.0-<UTC time>-<12 hex digits>`) to `go.mod` and its hashes to
`go.sum`; no `replace` and no checkout next to the consumer. A build then needs to reach the module
proxy and the checksum database, as for any other module. Once versions are tagged
(`vMAJOR.MINOR.PATCH`), `go get github.com/RCooLeR/kit@<version>` moves to a release.

To try a change of the kit in a consumer before it is committed, a temporary
`replace github.com/RCooLeR/kit => ../kit` points at a local checkout; do not commit it.

## Development

Go 1.27.4 (`go.mod`); CI runs with `GOTOOLCHAIN=local`, so a mismatch fails instead of downloading
another toolchain.

```sh
go vet ./...
go test ./...                                   # database tests are skipped without a database
go run honnef.co/go/tools/cmd/staticcheck@v0.8.2 ./...
go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.15.0 run
go run golang.org/x/vuln/cmd/govulncheck@v1.10.0 ./...
```

The database tests (`dbpg`, `dbmigrate`, `testpg`) need a disposable PostgreSQL 18. Every test
creates and drops a schema, and the helper refuses any database not named `kit_test*`:

```sh
docker compose -f compose.test.yaml up -d --wait
KIT_TEST_DB_DSN=postgres://postgres:local-test-only@127.0.0.1:55451/kit_test go test -race -p 1 ./...
docker compose -f compose.test.yaml down
```

`-race` needs cgo and a C compiler. Without one, run the tests in a container on the Compose
network:

```sh
docker run --rm --network kit-tests_default -v "${PWD}:/src" -w /src \
  -e KIT_TEST_DB_DSN=postgres://postgres:local-test-only@test-db:5432/kit_test \
  golang:1.27.4 go test -race -count=1 -p 1 ./...
```

### Adding a package

1. A second service needs the code, and one existing implementation is clearly the best.
2. Copy it, keep its behaviour, and turn every name it composed into a parameter.
3. Give it a package comment that says what it owns and what stays with the service, and tests.
4. Add it to the weight table in `weight_test.go` and to the table above.

A service adopts a package behind a golden test that snapshots its `/metrics` names, discovery
payloads and health bodies; the switch must leave the snapshot unchanged.

## Licence

[MIT](LICENSE)

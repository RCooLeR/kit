# Changelog

Versions will follow semantic versioning once the first one is tagged. Before 1.0 a minor version
may change interfaces; such changes are listed here.

## Unreleased

First set of packages, extracted from existing services while building Herald.

- `webauth/oidcsso` supports OpenID Connect sign-in with S256 PKCE, lazy discovery,
  passive browser sign-in, and optional signed MFA assurance.

- `buildinfo`, `secret`, `healthcheck`, `healthcheck/healthcheckcli`, `httpserver`, `jsonhttp`,
  `retry`, `logx`, `promx`, `dbpg`, `dbmigrate`, `testpg`.
- `herald`: the client of the Herald notification service, with a disk spool. Only an event Herald
  refuses for its content is dropped; a refusal of the producer (`AccessError`: a key Herald does
  not accept, a route that is gone) keeps the spool, and `Options.OnAccessError` reports it.
- `herald`: `PutSettings` (a user's language, time zone, quiet hours and preferences), and
  `VerifyCallback`, `CallbackHandler` and `SignCallback` for the signed answer callbacks.
- `herald`: `ForwardAnswer` passes on a tap on an action button in the producer's own app (Web Push
  or FCM) to the service.
- `webauth`: argon2id password hashing, tokens stored as digests, an attempt limiter that never
  forgets a key with no attempts left to make room.
- `webauth`: TOTP enrollment and six-digit code matching. Persist the last accepted counter
  per credential and update it atomically to prevent replay.
- `secret`: `Strict` drops a UTF-8 byte order mark at the start of a file.
- `cockpit`: the handler and types of an application's cockpit summary (`GET /api/v1/cockpit` with
  a bearer key compared in constant time; 404 without a key).
- `mcpx`: an application's MCP endpoint on the official Go SDK (`/mcp`, Streamable HTTP without
  sessions, JSON answers) behind a bearer key compared in constant time, 404 without a key. Limits
  on the body (1 MiB by default) and on each tool call (30 s), recovery from panics, one `Call`
  report per tool call (tool, read-only, target, result, duration, cause; never the arguments),
  `Read` and `Write` tool descriptions with their hints, and errors: an `Error` reaches the client
  as written, any other error is replaced by a general message. `mcpx/mcpxtest`: an in-memory
  session, tool calls as text, and `FindSecret` / `NoSecret` for output checks; a JSON field named
  just `token` counts as an identifier, not a secret.
- `herald`: `Run` with an interval of zero or less replays every `DefaultReplayInterval` instead of
  panicking.
- `dbpg`: `Options.WaitFor` keeps trying a database that is still starting.
- `mqttx`: an MQTT client for services that publish (Eclipse Paho): retained availability with a
  last will, QoS 1 publish with a timeout, subscriptions and handlers renewed on every reconnect,
  and a replay when Home Assistant announces its birth. `Close` ends the handlers' context, and no
  connect publishes "online" once `Close` has begun. `DeferOnline` with `SetAvailability` lets a
  service mark itself online only once it has a good state.
- `hamqtt`: Home Assistant MQTT discovery configs (`default_entity_id` included) and topics, with
  checks of the IDs; standard library only.
- Licensed under MIT.
- The TypeScript packages (`@rcooler/*`) live in their own repository,
  [web-kit](https://github.com/RCooLeR/web-kit).

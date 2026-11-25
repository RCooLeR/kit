# Changelog

Versions will follow semantic versioning once the first one is tagged. Before 1.0 a minor version
may change interfaces; such changes are listed here.

## Unreleased

First set of packages, extracted from existing services while building Herald.

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
  forgets a key over its limit to make room.
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

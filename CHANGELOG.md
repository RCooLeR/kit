# Changelog

Versions will follow semantic versioning once the first one is tagged. Before 1.0 a minor version
may change interfaces; such changes are listed here.

## Unreleased

First set of packages, extracted from existing services while building Herald.

- `buildinfo`, `secret`, `healthcheck`, `healthcheck/healthcheckcli`, `httpserver`, `jsonhttp`,
  `retry`, `logx`, `promx`, `dbpg`, `dbmigrate`, `testpg`.
- `herald`: the client of the Herald notification service, with a disk spool.
- `webauth`: argon2id password hashing, tokens stored as digests, an attempt limiter.
- `dbpg`: `Options.WaitFor` keeps trying a database that is still starting.
- Licensed under MIT.
- The TypeScript packages (`@rcooler/*`) live in their own repository,
  [web-kit](https://github.com/RCooLeR/web-kit).

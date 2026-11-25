// Package kit is the root of a module of small packages for Go services: build information,
// secrets from files, HTTP serving and health checks, JSON errors, retries, logging, metrics,
// PostgreSQL and migrations, password hashing and an attempt limiter, MQTT publishing with Home
// Assistant discovery, and the client of the Herald notification service. It holds no code of its
// own: import the package you need, such as kit/buildinfo or kit/httpserver.
//
// The packages are split by weight. The ones a small service needs depend on the standard library
// only; PostgreSQL, Prometheus, zerolog and the command line library each stay behind the package
// that names them. weight_test.go keeps it that way.
package kit

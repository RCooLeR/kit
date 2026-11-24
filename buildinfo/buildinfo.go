// Package buildinfo carries the version stamped into a binary at build time.
//
// The linker sets the three variables, so a service points its -ldflags at this package instead of
// keeping a copy of its own:
//
//	-X github.com/RCooLeR/kit/buildinfo.Version=1.4.0
//	-X github.com/RCooLeR/kit/buildinfo.Commit=<git sha>
//	-X github.com/RCooLeR/kit/buildinfo.Date=<RFC 3339 build time>
//
// The package imports nothing, so the smallest service can use it. It names no metric and no log
// field: what a service does with the values is the service's decision.
package buildinfo

// Set with -ldflags. The defaults mark a build made without them, such as `go run` or a test.
var (
	Version = "dev"
	Commit  = "unknown"
	Date    = "unknown"
)

// Build is a snapshot of the build variables.
type Build struct {
	Version string
	Commit  string
	Date    string
}

// Info returns the build variables as one value.
func Info() Build {
	return Build{Version: Version, Commit: Commit, Date: Date}
}

// String formats the build for a --version line: "1.4.0 (commit 3f2a9c1, built 2026-11-24T10:00:00Z)".
func (b Build) String() string {
	return b.Version + " (commit " + b.Commit + ", built " + b.Date + ")"
}

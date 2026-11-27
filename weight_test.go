package kit_test

import (
	"os/exec"
	"strings"
	"testing"
)

const module = "github.com/RCooLeR/kit"

// Third-party module prefixes, named once so the table below reads as a policy.
const (
	zerolog    = "github.com/rs/zerolog"
	cli        = "github.com/urfave/cli"
	prometheus = "github.com/prometheus/"
	pgx        = "github.com/jackc/"
	migrate    = "github.com/golang-migrate/"
	paho       = "github.com/eclipse/paho"
	oidc       = "github.com/coreos/go-oidc"
	oauth2     = "golang.org/x/oauth2"
)

// TestPackagesStaySplitByWeight guards the promise that importing a small package does not pull a
// heavy dependency into the consumer's build. It reads the real import graph with `go list`.
func TestPackagesStaySplitByWeight(t *testing.T) {
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Skip("the go tool is not on PATH")
	}
	tests := []struct {
		pkg string
		// stdlibOnly allows nothing outside the standard library and this module.
		stdlibOnly bool
		// forbidden lists module prefixes that must not appear in the import graph.
		forbidden []string
	}{
		{pkg: "buildinfo", stdlibOnly: true},
		{pkg: "secret", stdlibOnly: true},
		{pkg: "healthcheck", stdlibOnly: true},
		{pkg: "httpserver", stdlibOnly: true},
		{pkg: "jsonhttp", stdlibOnly: true},
		{pkg: "retry", stdlibOnly: true},
		{pkg: "herald", stdlibOnly: true},
		{pkg: "hamqtt", stdlibOnly: true},
		{pkg: "cockpit", stdlibOnly: true},
		{pkg: "webauth", forbidden: []string{zerolog, cli, prometheus, pgx, migrate, paho, oidc, oauth2}},
		{pkg: "webauth/oidcsso", forbidden: []string{zerolog, cli, prometheus, pgx, migrate, paho}},
		{pkg: "mcpx", forbidden: []string{zerolog, cli, prometheus, pgx, migrate, paho}},
		{pkg: "mcpx/mcpxtest", forbidden: []string{zerolog, cli, prometheus, pgx, migrate, paho}},
		{pkg: "mqttx", forbidden: []string{zerolog, cli, prometheus, pgx, migrate}},
		{pkg: "logx", forbidden: []string{cli, prometheus, pgx, migrate, paho}},
		{pkg: "healthcheck/healthcheckcli", forbidden: []string{zerolog, prometheus, pgx, migrate, paho}},
		{pkg: "promx", forbidden: []string{zerolog, cli, pgx, migrate, paho}},
		{pkg: "dbpg", forbidden: []string{zerolog, cli, prometheus, migrate, paho}},
		{pkg: "testpg", forbidden: []string{zerolog, cli, prometheus, migrate, paho}},
		{pkg: "dbmigrate", forbidden: []string{zerolog, cli, prometheus, paho}},
	}
	for _, tc := range tests {
		t.Run(tc.pkg, func(t *testing.T) {
			out, err := exec.CommandContext(t.Context(), goTool, "list", "-deps",
				"-f", "{{if not .Standard}}{{.ImportPath}}{{end}}", "./"+tc.pkg).Output()
			if err != nil {
				t.Fatalf("go list -deps ./%s: %v", tc.pkg, err)
			}
			for dependency := range strings.FieldsSeq(string(out)) {
				if tc.stdlibOnly && !strings.HasPrefix(dependency, module) {
					t.Errorf("%s must depend on the standard library only, but imports %s", tc.pkg, dependency)
				}
				for _, prefix := range tc.forbidden {
					if strings.HasPrefix(dependency, prefix) {
						t.Errorf("%s pulls in %s, which belongs behind another package", tc.pkg, dependency)
					}
				}
			}
		})
	}
}

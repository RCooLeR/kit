// Package healthcheckcli wraps the healthcheck probe as an urfave/cli v3 subcommand. It is a
// package of its own so that importing healthcheck does not pull in the command line library.
package healthcheckcli

import (
	"context"

	"github.com/urfave/cli/v3"

	"github.com/RCooLeR/kit/healthcheck"
)

// Flag names of the subcommand.
const (
	flagURL     = "url"
	flagPath    = "path"
	flagTimeout = "timeout"
)

// Options tell the subcommand where the local server listens and which endpoint to ask.
type Options struct {
	// Addr returns the server's listen address, usually the value of the program's own listen
	// flag: func(c *cli.Command) string { return c.String("http-addr") }. A subcommand reads the
	// flags of its parents, so the address needs no second flag here.
	Addr func(command *cli.Command) string
	// Path is the endpoint to probe when --url is not given, for example "/readyz". Required.
	Path string
}

// Command returns the `healthcheck` subcommand: it sends one GET to the local server and fails
// unless the answer is a 2xx status. --url replaces the derived address, --path the endpoint and
// --timeout the wait.
func Command(opts Options) *cli.Command {
	return &cli.Command{
		Name:  "healthcheck",
		Usage: "exit 0 when the server on this machine is ready (for the container health check)",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: flagURL, Usage: "full URL to probe instead of the local server"},
			&cli.StringFlag{Name: flagPath, Value: opts.Path, Usage: "endpoint to probe on the local server"},
			&cli.DurationFlag{Name: flagTimeout, Value: healthcheck.DefaultTimeout, Usage: "how long to wait for the answer"},
		},
		Action: func(ctx context.Context, command *cli.Command) error {
			listenAddr := ""
			if opts.Addr != nil {
				listenAddr = opts.Addr(command)
			}
			probeURL, err := healthcheck.URL(command.String(flagURL), listenAddr, command.String(flagPath))
			if err != nil {
				return err
			}
			return healthcheck.Probe(ctx, probeURL, command.Duration(flagTimeout))
		},
	}
}

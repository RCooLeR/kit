package mcpx_test

import (
	"context"
	"net/http"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/RCooLeR/kit/mcpx"
)

type noteArgs struct {
	ID string `json:"id" jsonschema:"the note's ID, from list_notes"`
}

type note struct {
	ID   string `json:"id"`
	Text string `json:"text"`
}

func Example() {
	server := mcpx.New(mcpx.Options{
		Name: "notes", Version: "1.0.0",
		Key:    "the key read from the application's key file",
		OnCall: func(call mcpx.Call) { /* one log line: call.Tool, call.Target, call.Result, call.Duration */ },
	})
	mcpx.AddTool(server, mcpx.Read("get_note", "Reads one note by its ID; list_notes gives the IDs."),
		func(_ context.Context, _ *mcp.CallToolRequest, args noteArgs) (*mcp.CallToolResult, note, error) {
			if args.ID != "1" {
				return nil, note{}, mcpx.NotFound("note %s does not exist", args.ID)
			}
			return nil, note{ID: "1", Text: "first"}, nil
		})
	mux := http.NewServeMux()
	mux.Handle(mcpx.Path, server.Handler())
}

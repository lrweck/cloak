// Command context masks a value that was attached far from the log call that
// exposes it.
//
//	go run ./examples/context
package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/lrweck/cloak"

	"github.com/lrweck/cloak/examples/context/auth"
)

func main() {
	logger := slog.New(cloak.New(
		slog.NewJSONHandler(os.Stdout, nil),
		cloak.WithCompositeScan(),
		cloak.WithDefaultPII(),
		// One pull function per source of context data. Everything it returns goes
		// through the same masking as an attribute logged by hand, so a call site
		// cannot leak it by forgetting a field.
		cloak.WithContextAttrs(auth.LogAttrs),
	))

	// Middleware, somewhere with no logging in sight.
	ctx := auth.WithPrincipal(context.Background(), auth.Principal{
		ID:    7,
		Email: "jane@example.com",
	})

	// A checkout, somewhere else entirely.
	logger.InfoContext(ctx, "checkout started")

	// A second call site that never mentions the principal at all. It is masked the
	// same way, which is the property worth having.
	logger.InfoContext(context.Background(), "health check")
}

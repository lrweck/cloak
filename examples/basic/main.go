// Command basic is the smallest setup that does anything useful: wrap the handler
// you already have and turn on the preset.
//
//	go run ./examples/basic
package main

import (
	"log/slog"
	"os"

	"github.com/lrweck/cloak"
)

func main() {
	slog.SetDefault(slog.New(cloak.New(
		slog.NewJSONHandler(os.Stdout, nil),
		cloak.WithDefaultPII(),
	)))

	slog.Info("payment", "email", "john@example.com", "amount", 1299)
	slog.Info("nothing sensitive here", "count", 3)
}

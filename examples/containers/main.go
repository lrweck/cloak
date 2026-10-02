// Command containers reaches inside the data slog hands over as one opaque value.
// Without a composite option a struct arrives as %+v and nothing inside it is
// matched.
//
//	go run ./examples/containers
package main

import (
	"log/slog"
	"os"

	"github.com/lrweck/cloak"
)

type Address struct {
	Street string
	CEP    string
}

type User struct {
	ID     int
	Name   string
	Email  string
	ShipTo *Address // followed through the pointer
	Tags   []string
}

type secret struct {
	ID       int
	password string // unexported: dropped, since TextHandler would print it
	Note     string `slog:"-"`
}

func main() {
	// WithCompositeScan turns on struct, map and slice walking at once. Each one is
	// also available on its own, scoped to its own shape.
	//
	// JSONHandler, not TextHandler: cloak follows pointers, but %+v renders a struct
	// with a pointer field as the address, so a masked value behind a pointer would
	// reach the sink as 0x... on a text handler. JSON follows the pointer and shows
	// the masked fields.
	logger := slog.New(cloak.New(
		slog.NewJSONHandler(os.Stdout, nil),
		cloak.WithCompositeScan(),
		cloak.WithDefaultPII(),
	))

	logger.Info("loaded", slog.Any("user", User{
		ID:    7,
		Name:  "Jane",
		Email: "jane@example.com",
		ShipTo: &Address{
			Street: "Rua das Flores",
			CEP:    "01310-100",
		},
		Tags: []string{"admin", "jane@example.com"},
	}))

	// Maps are walked by value, never by key: masking the key would protect nothing.
	logger.Info("batch", slog.Any("rows", []map[string]any{
		{"email": "a@example.com", "score": 10},
		{"email": "b@example.com", "score": 20},
	}))

	// Groups are walked recursively and every attribute survives, matched or not.
	logger.Info("request", slog.Group("user",
		slog.Int("id", 7),
		slog.String("email", "jane@example.com"),
		slog.String("name", "Jane"),
	))

	logger.Info("unexported", slog.Any("acct", secret{ID: 7, password: "hunter2", Note: "n"}))

	// A value that knows how to log itself is resolved first, then masked, so the
	// LogValuer decides what gets exposed and the rules still apply to it.
	logger.Info("valuer", "mail", maskedEmail("jane@example.com"))
}

type maskedEmail string

func (maskedEmail) LogValue() slog.Value {
	return slog.StringValue("jane@example.com")
}

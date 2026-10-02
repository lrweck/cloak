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

// plain carries nothing a rule here would match, which is what makes it useful: the
// pointer to it is left exactly as it arrived, address and all.
type plain struct {
	Zone string
}

type holder struct {
	ID   int
	Next *plain
}

func main() {
	// WithCompositeScan turns on struct, map and slice walking at once. Each one is
	// also available on its own, scoped to its own shape.
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
		// The same email as the field above, in a slice this time. A slice element has
		// no key of its own, so no key rule can reach it and only the email detector
		// fires, which masks the local part instead of replacing the value:
		// [REDACTED] above, j***@example.com here. Both are correct, and the difference
		// is entirely which rule had a name to match.
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

	// A text handler, where fmt would render a nested pointer as an address and a
	// masked value behind it would be invisible. Cloak does not leave the address there:
	// a struct whose pointer field changed widens to a group, so the mask is visible.
	// The JSON above is untouched by any of this.
	text := slog.New(cloak.New(
		slog.NewTextHandler(os.Stdout, nil),
		cloak.WithStructScan(),
		cloak.WithKeys(cloak.Redact, "cep"),
	))
	text.Info("text handler", "user", User{
		ID:     7,
		Name:   "Jane",
		ShipTo: &Address{Street: "Rua X", CEP: "01310-100"},
	})
	// user.ID=7 user.Name=Jane user.Email="" user.ShipTo="&{Street:Rua X CEP:[REDACTED]}" user.Tags=[]

	// What still shows an address is a pointer whose target nothing matched. Rebuilding
	// for readability alone would cost the quiet path its pass-through, and fmt behaves
	// the same way with no cloak involved at all.
	text.Info("unmatched pointer", "h", holder{ID: 7, Next: &plain{Zone: "east"}})
	// h="{ID:7 Next:0xc000...}" — the address varies per run; what is stable is that a
	// struct nothing changed is passed through untouched, and fmt prints it as one value.
}

type maskedEmail string

func (maskedEmail) LogValue() slog.Value {
	return slog.StringValue("jane@example.com")
}

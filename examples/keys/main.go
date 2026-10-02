// Command keys shows the three ways to name a field, and the fixed order they are
// tried in.
//
//	go run ./examples/keys
package main

import (
	"log/slog"
	"os"

	"github.com/lrweck/cloak"
)

// A named type is masked wherever it appears, including under a key nobody added to
// a preset. slog stores it as KindAny, so no string detector would ever see it.
type Password string

type Account struct {
	ID       int
	Password Password
	APIKey   string `cloak:"secret"`
}

func main() {
	logger := slog.New(cloak.New(
		slog.NewTextHandler(os.Stdout, nil),
		// The strongest rule first: a type the compiler checks.
		cloak.WithType[Password](),
		// Then a struct tag, which survives renaming the field.
		cloak.WithStructScan(),
		cloak.WithTag(cloak.KeepFirst(4), "cloak", "secret"),
		// Then exact names, with case and separators folded.
		cloak.WithKeys(cloak.Redact, "card_number"),
		// Then a pattern, for names you cannot enumerate.
		cloak.WithKeyRegex(cloak.KeepLast(6), `_token$`),
		// Then a substring, which sees the qualified names exact matching cannot.
		cloak.WithKeysContaining(cloak.Redact, "ssn"),
	))

	logger.Info("login",
		slog.Any("account", Account{ID: 7, Password: "hunter2", APIKey: "sk_live_abcd1234"}),
		"card_number", "4111111111111111",
		"refresh_token", "eyJhbGciOi.J9",
		"user_ssn", "123-45-6789",
		"cardNumber", "4111111111111111", // same rule as card_number
	)

	// Two rules can name the same key. The stronger one wins, so the type rule here
	// overrides the key rule rather than the other way round.
	redacted := slog.New(cloak.New(
		slog.NewTextHandler(os.Stdout, nil),
		cloak.WithDefaultPII(),
		cloak.WithKeys(cloak.KeepLast(4), "card_number"),
	))
	redacted.Info("override", "card_number", "4111111111111111")
}

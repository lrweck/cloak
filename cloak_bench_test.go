package cloak

import (
	"io"
	"log/slog"
	"testing"
)

func benchHandler(b *testing.B, opts ...Option) *slog.Logger {
	b.Helper()
	return slog.New(New(slog.NewTextHandler(io.Discard, nil), opts...))
}

func BenchmarkLog(b *testing.B) {
	cases := []struct {
		name string
		opts []Option
	}{
		{"passthrough", nil},
		{"key_only", []Option{WithKey(Redact, "password", "email")}},
		{"default_pii", []Option{WithDefaultPII()}},
	}
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			logger := benchHandler(b, tc.opts...)
			for b.Loop() {
				logger.Info("payment", "id", 42, "ok", true, "duration_ms", 13)
			}
		})
	}
}

func BenchmarkLogWithPII(b *testing.B) {
	cases := []struct {
		name string
		opts []Option
	}{
		{"key_only", []Option{WithKey(Redact, "password")}},
		{"default_pii", []Option{WithDefaultPII()}},
	}
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			logger := benchHandler(b, tc.opts...)
			for b.Loop() {
				logger.Info("payment",
					"email", "john@example.com",
					"card", "4111 1111 1111 1111",
					"cpf", "529.982.247-25",
				)
			}
		})
	}
}

func BenchmarkKeyLookup(b *testing.B) {
	c := &config{keys: make(map[string]Masker), skip: make(map[string]struct{})}
	WithDefaultPIIKeys()(c)
	key := normalizeKey("email")
	for b.Loop() {
		if _, ok := c.maskerFor(key); !ok {
			b.Fatal("expected a rule")
		}
	}
}

package cloak

import (
	"io"
	"log/slog"
	"testing"
)

func benchHandler(b *testing.B, opts ...Options) *slog.Logger {
	b.Helper()
	return slog.New(New(slog.NewTextHandler(io.Discard, nil), opts...))
}

func BenchmarkLog(b *testing.B) {
	cases := []struct {
		name string
		opts []Options
	}{
		{"passthrough", nil},
		{"key_only", []Options{WithKey(Redact, "password", "email")}},
		{"default_pii", []Options{WithDefaultPII()}},
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
		opts []Options
	}{
		{"key_only", []Options{WithKey(Redact, "password")}},
		{"default_pii", []Options{WithDefaultPII()}},
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

func BenchmarkCompositeScan(b *testing.B) {
	type payload struct {
		ID    int
		Email string
		CPF   string
	}
	cases := []struct {
		name string
		opts []Options
	}{
		{"disabled", []Options{WithDefaultPII()}},
		{"struct", []Options{WithDefaultPII(), WithStructScan()}},
		{"map", []Options{WithDefaultPII(), WithMapScan()}},
		{"slice", []Options{WithDefaultPII(), WithSliceScan()}},
		{"composite", []Options{WithDefaultPII(), WithCompositeScan()}},
	}
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			logger := benchHandler(b, tc.opts...)
			for b.Loop() {
				logger.Info("m", "acct", payload{ID: 1, Email: "john@example.com", CPF: "529.982.247-25"})
			}
		})
	}
}

func BenchmarkKeyLookup(b *testing.B) {
	c := &config{keys: make(map[string]Masker), skip: make(map[string]struct{})}
	WithDefaultPIIKeys().apply(c)
	key := normalizeKey("email")
	for b.Loop() {
		if _, ok := c.maskerForKey(key, key); !ok {
			b.Fatal("expected a rule")
		}
	}
}

func BenchmarkDetectorsComposed(b *testing.B) {
	s := "payment settled for user 42 in 120ms"
	cases := []struct {
		name string
		opts []Options
	}{
		{"once", []Options{WithDefaultPIIValues()}},
		{"composed", []Options{WithDefaultPII(), WithDefaultPIIValues()}},
		{"twice", []Options{WithDefaultPII(), WithDefaultPII()}},
	}
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			c := &config{keys: make(map[string]Masker), skip: make(map[string]struct{})}
			for _, o := range tc.opts {
				o.apply(c)
			}
			h := &Handler{cfg: c}
			b.ReportAllocs()
			for b.Loop() {
				h.maskString(s)
			}
		})
	}
}

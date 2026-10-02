// Package compare benchmarks cloak against the other libraries that mask PII in Go
// logs, on the same record through the same sink.
//
// It lives in its own module so cloak keeps its zero-dependency promise: nothing here
// is reachable from the library, and bench/compare/go.mod is the only place these
// imports exist.
package compare

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"reflect"
	"testing"
	"time"

	"github.com/JAS0N-SMITH/redactlog"
	"github.com/alesr/redact"
	"github.com/lrweck/cloak"
	"github.com/m-mizutani/masq"
	redact2 "github.com/philiprehberger/go-slog-redact"
	"github.com/sudoki2015/sensitive"
)

// The keys every library is configured with, so the same work is being asked of each.
var sensitiveKeys = []string{"password", "email", "card_number"}

// A record with nothing to mask, which is what most records are.
var cleanRecord = []any{"user_id", 42, "status", 200, "latency_ms", 12, "route", "/v1/charges"}

// A record that trips a key rule.
var secretRecord = []any{"user_id", 42, "password", "hunter2", "status", 200}

// library is one masking library together with how to configure it for key rules.
type library struct {
	name string
	// buildKeys returns a logger writing to w, configured to mask those keys.
	buildKeys func(w io.Writer, keys []string) (*slog.Logger, error)
}

func libraries() []library {
	return []library{
		{name: "bare", buildKeys: func(w io.Writer, _ []string) (*slog.Logger, error) {
			return slog.New(slog.NewJSONHandler(w, nil)), nil
		}},
		{name: "cloak", buildKeys: func(w io.Writer, keys []string) (*slog.Logger, error) {
			return slog.New(cloak.New(slog.NewJSONHandler(w, nil),
				cloak.WithKeys(cloak.Redact, keys...))), nil
		}},
		{name: "masq", buildKeys: func(w io.Writer, keys []string) (*slog.Logger, error) {
			opts := make([]masq.Option, 0, len(keys))
			for _, k := range keys {
				opts = append(opts, masq.WithFieldName(k))
			}
			return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{
				ReplaceAttr: masq.New(opts...),
			})), nil
		}},
		{name: "masq+allowed-time", buildKeys: func(w io.Writer, keys []string) (*slog.Logger, error) {
			opts := make([]masq.Option, 0, len(keys)+1)
			for _, k := range keys {
				opts = append(opts, masq.WithFieldName(k))
			}
			// masq's escape hatch for the time attribute: it deep-clones whatever it
			// is handed, and a time.Time carries a *time.Location. This is the fair
			// configuration to compare, since the default one walks the whole zone
			// table on every record.
			opts = append(opts, masq.WithAllowedType(reflect.TypeFor[time.Time]()))
			return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{
				ReplaceAttr: masq.New(opts...),
			})), nil
		}},
		{name: "go-slog-redact", buildKeys: func(w io.Writer, keys []string) (*slog.Logger, error) {
			return slog.New(redact2.New(slog.NewJSONHandler(w, nil),
				redact2.WithSensitiveKeys(keys...))), nil
		}},
		{name: "redactlog", buildKeys: func(w io.Writer, keys []string) (*slog.Logger, error) {
			cfg := redactlog.Config{
				Logger:      slog.New(slog.NewJSONHandler(w, nil)),
				RedactPaths: keys,
			}
			h, err := cfg.Build()
			if err != nil {
				return nil, err
			}
			return slog.New(h), nil
		}},
		{name: "alesr/redact", buildKeys: func(w io.Writer, keys []string) (*slog.Logger, error) {
			p := redact.NewRedactionPipeline()
			for _, k := range keys {
				p.AddRedactField(k)
			}
			return slog.New(redact.NewRedactionHandler(
				slog.NewJSONHandler(w, nil), p)), nil
		}},
		{name: "sensitive", buildKeys: func(w io.Writer, keys []string) (*slog.Logger, error) {
			if err := sensitive.AddWithConfig(sensitive.StrategyFullRedact,
				sensitive.MaskOptions{}, keys...); err != nil {
				return nil, err
			}
			// sensitive has no slog integration of its own; a ReplaceAttr hook
			// calling RedactIfSensitive is the intended wiring.
			return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{
				ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
					if a.Value.Kind() != slog.KindString {
						return a
					}
					return slog.String(a.Key, sensitive.RedactIfSensitive(a.Key, a.Value.String()))
				},
			})), nil
		}},
	}
}

// Each library must actually mask before its speed means anything. Benchmarking a
// configuration that quietly does nothing would read as a very fast winner.
func TestEveryLibraryMasks(t *testing.T) {
	for _, l := range libraries() {
		if l.name == "bare" {
			continue
		}
		t.Run(l.name, func(t *testing.T) {
			var b bytes.Buffer
			logger, err := l.buildKeys(&b, sensitiveKeys)
			if err != nil {
				t.Fatalf("configuring %s: %v", l.name, err)
			}
			logger.InfoContext(context.Background(), "login", secretRecord...)

			if bytes.Contains(b.Bytes(), []byte("hunter2")) {
				t.Errorf("%s did not mask the password: %s", l.name, b.String())
			}
		})
	}
}

// A record where nothing matches: the cost the wrapper adds to every log line that was
// never going to leak. This is the common case, and it is measured with the built-in
// time attribute in place as it is in production.
func BenchmarkCleanRecord(b *testing.B) {
	benchRecord(b, cleanRecord, sensitiveKeys)
}

// A record with one sensitive value, which is the case the libraries exist for.
func BenchmarkSecretRecord(b *testing.B) {
	benchRecord(b, secretRecord, sensitiveKeys)
}

func benchRecord(b *testing.B, args []any, keys []string) {
	for _, l := range libraries() {
		logger, err := l.buildKeys(io.Discard, keys)
		if err != nil {
			b.Fatalf("configuring %s: %v", l.name, err)
		}
		b.Run(l.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				logger.Info("request", args...)
			}
		})
	}
}

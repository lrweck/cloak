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

// jsonOpts builds the sink's options, optionally dropping the built-in time attribute.
//
// The time attribute matters more than it looks. A ReplaceAttr hook is handed every
// attribute the handler builds, including `time`, and masq clones whatever it is
// handed: a time.Time carries a *time.Location, so cloning it walks the whole zone
// table. Measuring both ways separates the cost of masking from the cost of walking
// the clock, and the second number is the one that compares libraries.
func jsonOpts(stripTime bool, replace func([]string, slog.Attr) slog.Attr) *slog.HandlerOptions {
	if !stripTime {
		return &slog.HandlerOptions{ReplaceAttr: replace}
	}
	return &slog.HandlerOptions{ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
		if a.Key == slog.TimeKey && len(groups) == 0 {
			return slog.Attr{}
		}
		if replace == nil {
			return a
		}
		return replace(groups, a)
	}}
}

type lib struct {
	name string
	// build returns a logger writing to w. An error is a configuration failure for
	// that library, reported once rather than per iteration. stripTime drops the
	// built-in time attribute, which is what shows how much of masq's cost is the
	// clock rather than the masking.
	build func(w io.Writer, stripTime bool) (*slog.Logger, error)
}

func libraries() []lib {
	return []lib{
		{"cloak", func(w io.Writer, strip bool) (*slog.Logger, error) {
			return slog.New(cloak.New(slog.NewJSONHandler(w, jsonOpts(strip, nil)),
				cloak.WithKeys(cloak.Redact, sensitiveKeys...))), nil
		}},
		{"masq", func(w io.Writer, strip bool) (*slog.Logger, error) {
			opts := make([]masq.Option, 0, len(sensitiveKeys))
			for _, k := range sensitiveKeys {
				opts = append(opts, masq.WithFieldName(k))
			}
			return slog.New(slog.NewJSONHandler(w, jsonOpts(strip, masq.New(opts...)))), nil
		}},
		// masq's escape hatch for the time attribute: WithAllowedType tells it not to
		// clone that type at all. This is the fair configuration to compare against,
		// since the default one deep-clones *time.Location on every record.
		{"masq+allowed-time", func(w io.Writer, strip bool) (*slog.Logger, error) {
			opts := make([]masq.Option, 0, len(sensitiveKeys)+1)
			for _, k := range sensitiveKeys {
				opts = append(opts, masq.WithFieldName(k))
			}
			opts = append(opts, masq.WithAllowedType(reflect.TypeFor[time.Time]()))
			return slog.New(slog.NewJSONHandler(w, jsonOpts(strip, masq.New(opts...)))), nil
		}},
		{"go-slog-redact", func(w io.Writer, strip bool) (*slog.Logger, error) {
			return slog.New(redact2.New(slog.NewJSONHandler(w, jsonOpts(strip, nil)),
				redact2.WithSensitiveKeys(sensitiveKeys...))), nil
		}},
		{"redactlog", func(w io.Writer, strip bool) (*slog.Logger, error) {
			cfg := redactlog.Config{
				Logger:      slog.New(slog.NewJSONHandler(w, jsonOpts(strip, nil))),
				RedactPaths: sensitiveKeys,
			}
			h, err := cfg.Build()
			if err != nil {
				return nil, err
			}
			return slog.New(h), nil
		}},
		{"alesr/redact", func(w io.Writer, strip bool) (*slog.Logger, error) {
			p := redact.NewRedactionPipeline()
			for _, k := range sensitiveKeys {
				p.AddRedactField(k)
			}
			return slog.New(redact.NewRedactionHandler(
				slog.NewJSONHandler(w, jsonOpts(strip, nil)), p)), nil
		}},
		{"sensitive", func(w io.Writer, strip bool) (*slog.Logger, error) {
			if err := sensitive.AddWithConfig(sensitive.StrategyFullRedact,
				sensitive.MaskOptions{}, sensitiveKeys...); err != nil {
				return nil, err
			}
			// sensitive has no slog integration of its own; a ReplaceAttr hook
			// calling RedactIfSensitive is the intended wiring.
			return slog.New(slog.NewJSONHandler(w, jsonOpts(strip,
				func(_ []string, a slog.Attr) slog.Attr {
					if a.Value.Kind() != slog.KindString {
						return a
					}
					return slog.String(a.Key, sensitive.RedactIfSensitive(a.Key, a.Value.String()))
				}))), nil
		}},
		{"bare", func(w io.Writer, strip bool) (*slog.Logger, error) {
			return slog.New(slog.NewJSONHandler(w, jsonOpts(strip, nil))), nil
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
			logger, err := l.build(&b, false)
			if err != nil {
				t.Fatalf("configuring %s: %v", l.name, err)
			}
			logger.InfoContext(context.Background(), "login", secretRecord...)

			if bytes.Contains(b.Bytes(), []byte("hunter2")) {
				t.Errorf("%s did not mask the password: %s", l.name, b.String())
			}
			t.Logf("%s: %s", l.name, b.String())
		})
	}
}

// A record where nothing matches: the cost the wrapper adds to every log line that was
// never going to leak. This is the common case, and it is measured with the built-in
// time attribute in place as it is in production.
func BenchmarkCleanRecord(b *testing.B) {
	benchRecords(b, cleanRecord)
}

// A record with one sensitive value, which is the case the libraries exist for.
func BenchmarkSecretRecord(b *testing.B) {
	benchRecords(b, secretRecord)
}

func benchRecords(b *testing.B, args []any) {
	for _, l := range libraries() {
		logger, err := l.build(io.Discard, false)
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

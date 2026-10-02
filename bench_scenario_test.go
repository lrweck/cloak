package cloak_test

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/lrweck/cloak"
)

// Scenarios rather than microbenchmarks. A single number for "the cost of cloak" is
// meaningless on its own: the work depends entirely on whether a rule fired, how many
// attributes the record has, and whether reflection is on. So every scenario is
// measured against the same record logged straight to slog, and the interesting number
// is the difference between the two rows of a pair.
//
// Run with:
//
//	go test -bench Scenario -benchmem
//	go test -bench Scenario -benchmem -benchtime 2s   # steadier numbers
type benchRecord struct {
	name  string
	opts  []cloak.Options
	ctx   context.Context
	args  []any
	attrs int // how many attributes, for the ns/attr column in the writeup
}

// benchUser is walked by the composite scenarios.
type benchUser struct {
	ID    int
	Name  string
	Email string
	Phone string
}

func scenarioRecords() []benchRecord {
	ctx := context.WithValue(context.Background(), benchCtxKey{}, benchUser{
		ID: 7, Name: "Jane", Email: "jane@example.com", Phone: "+5511999999999",
	})
	pull := func(ctx context.Context) []slog.Attr {
		u, ok := ctx.Value(benchCtxKey{}).(benchUser)
		if !ok {
			return nil
		}
		return []slog.Attr{slog.Any("user", u)}
	}

	nothing := []any{"request completed", "status", 200, "duration_ms", 12}
	mixed := []any{
		"checkout", "user_id", 7, "email", "jane@example.com",
		"cpf", "529.982.247-25", "amount", 1299, "currency", "BRL",
	}
	wide := make([]any, 0, 42)
	wide = append(wide, "event")
	for i := range 20 {
		wide = append(wide, slog.Int("field_"+string(rune('a'+i%26))+string(rune('a'+i/26)), i))
	}

	return []benchRecord{
		{
			name: "no_pii_text", attrs: 4,
			opts: []cloak.Options{cloak.WithDefaultPII()},
			args: nothing,
		},
		{
			name: "key_rule_fires", attrs: 2,
			opts: []cloak.Options{cloak.WithKeys(cloak.Redact, "password")},
			args: []any{"login", "password", "hunter2"},
		},
		{
			name: "detector_fires", attrs: 2,
			opts: []cloak.Options{cloak.WithDefaultPIIValues()},
			args: []any{"contact", "john@example.com"},
		},
		{
			name: "preset_mixed_record", attrs: 6,
			opts: []cloak.Options{cloak.WithDefaultPII()},
			args: mixed,
		},
		{
			name: "preset_wide_record", attrs: 20,
			opts: []cloak.Options{cloak.WithDefaultPII()},
			args: wide,
		},
		{
			name: "groups_nested", attrs: 6,
			opts: []cloak.Options{cloak.WithDefaultPII()},
			args: []any{
				"checkout",
				slog.Group("req", slog.Int("id", 7), slog.String("ip", "192.168.1.42")),
				slog.Group("user", slog.Int("id", 7), slog.String("email", "jane@example.com")),
			},
		},
		{
			name: "struct_walk", attrs: 2,
			opts: []cloak.Options{cloak.WithStructScan(), cloak.WithDefaultPII()},
			args: []any{"loaded", slog.Any("user", benchUser{
				ID: 7, Name: "Jane", Email: "jane@example.com", Phone: "+5511999999999",
			})},
		},
		{
			name: "map_walk", attrs: 2,
			opts: []cloak.Options{cloak.WithMapScan(), cloak.WithDefaultPII()},
			args: []any{"loaded", slog.Any("user", map[string]any{
				"id": 7, "name": "Jane", "email": "jane@example.com",
			})},
		},
		{
			name: "slice_walk", attrs: 2,
			opts: []cloak.Options{cloak.WithSliceScan(), cloak.WithDefaultPIIValues()},
			args: []any{"batch", slog.Any("emails", []string{
				"a@example.com", "b@example.com", "c@example.com",
			})},
		},
		{
			name: "message_scan", attrs: 2,
			opts: []cloak.Options{cloak.WithDefaultPII(), cloak.WithMessageScan()},
			args: []any{"user jane@example.com logged in", "status", 200},
		},
		{
			name: "context_attrs", attrs: 3, ctx: ctx,
			opts: []cloak.Options{
				cloak.WithStructScan(), cloak.WithDefaultPII(),
				cloak.WithContextAttrs(pull),
			},
			args: []any{"checkout started", "order", 42},
		},
		{
			name: "key_only_no_detectors", attrs: 4,
			opts: []cloak.Options{cloak.WithDefaultPIIKeys()},
			args: nothing,
		},
	}
}

type benchCtxKey struct{}

// BenchmarkScenario measures each record twice: once straight to slog, once through
// cloak with that scenario's options. The gap is what cloak costs for that shape.
func BenchmarkScenario(b *testing.B) {
	recs := scenarioRecords()

	b.Run("bare_slog", func(b *testing.B) {
		logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
		msg := recs[0].args[0].(string)
		rest := recs[0].args[1:]
		b.ReportAllocs()
		for b.Loop() {
			logger.Info(msg, rest...)
		}
	})

	for _, rec := range recs {
		b.Run(rec.name, func(b *testing.B) {
			logger := slog.New(cloak.New(slog.NewJSONHandler(io.Discard, nil), rec.opts...))
			msg := rec.args[0].(string)
			rest := rec.args[1:]
			b.ReportAllocs()
			for b.Loop() {
				if rec.ctx != nil {
					logger.InfoContext(rec.ctx, msg, rest...)
				} else {
					logger.Info(msg, rest...)
				}
			}
		})
	}
}

// BenchmarkScenarioScaling isolates the per-attribute cost, since that is what
// decides whether the wrapper is affordable on a hot path.
func BenchmarkScenarioScaling(b *testing.B) {
	for _, n := range []int{1, 5, 10, 20, 50} {
		args := make([]any, 0, 2*n)
		for i := range n {
			args = append(args, slog.Int("field_"+string(rune('a'+i%26))+string(rune('a'+i/26)), i))
		}

		b.Run("bare_slog/"+itoa(n), func(b *testing.B) {
			logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
			b.ReportAllocs()
			for b.Loop() {
				logger.Info("event", args...)
			}
		})
		b.Run("key_rules/"+itoa(n), func(b *testing.B) {
			logger := slog.New(cloak.New(slog.NewJSONHandler(io.Discard, nil),
				cloak.WithKeys(cloak.Redact, "password"), cloak.WithDefaultPIIKeys()))
			b.ReportAllocs()
			for b.Loop() {
				logger.Info("event", args...)
			}
		})
	}
}

// itoa avoids importing strconv for two call sites in a benchmark.
func itoa(n int) string {
	if n < 10 {
		return string(rune('0' + n))
	}
	return string(rune('0'+n/10)) + string(rune('0'+n%10))
}

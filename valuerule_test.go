package cloak_test

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/lrweck/cloak"
)

// A value rule sees every kind, which is the gap ValueFunc could not cover: the
// format detectors only ever looked at strings.
func TestValueRuleSeesEveryKind(t *testing.T) {
	var seen []string
	rule := func(v slog.Value) (slog.Value, bool) {
		seen = append(seen, v.Kind().String())
		return v, false
	}

	logger := logWithRule(rule,
		"str", "hello",
		"int", 42,
		"uint", uint(42),
		"float", 1.5,
		"bool", true,
		"dur", 3*time.Second,
		"time", time.Unix(0, 0).UTC(),
	)
	_ = logger

	want := []string{"String", "Int64", "Uint64", "Float64", "Bool", "Duration", "Time"}
	for _, w := range want {
		if !slicesContains(seen, w) {
			t.Errorf("rule never saw a %s value, saw %v", w, seen)
		}
	}
}

func TestValueRuleCanMaskAnyKind(t *testing.T) {
	got := logWithOpts([]cloak.Option{
		cloak.WithValuePredicate(
			func(v slog.Value) bool { return v.Kind() == slog.KindInt64 },
			cloak.Redact,
		),
	}, "int", 4242424242, "str", "keep-me", "other_int", 7)

	if strings.Contains(got, "4242424242") {
		t.Errorf("int was not masked: %s", got)
	}
	if !strings.Contains(got, "keep-me") {
		t.Errorf("a string should be untouched: %s", got)
	}
	if strings.Contains(got, "other_int=7") {
		t.Errorf("only the first matching rule should decide, and it should not leak: %s", got)
	}
}

// WithValueRule may rewrite rather than only decide, which ValueFunc can do too but
// ValueRule does for any kind.
func TestValueRuleRewrites(t *testing.T) {
	got := logWithOpts([]cloak.Option{
		cloak.WithValueRule(func(v slog.Value) (slog.Value, bool) {
			if v.Kind() == slog.KindDuration {
				return slog.StringValue("slow"), true
			}
			return v, false
		}),
	}, "took", 3*time.Second, "count", 9)

	if !strings.Contains(got, "took=slow") {
		t.Errorf("duration was not rewritten: %s", got)
	}
	if !strings.Contains(got, "count=9") {
		t.Errorf("unrelated value must survive: %s", got)
	}
}

// A rule must not claim a group, since replacing one discards its structure rather
// than masking it.
func TestValueRuleSkipsGroups(t *testing.T) {
	got := logWithOpts([]cloak.Option{
		cloak.WithValuePredicate(func(slog.Value) bool { return true }, cloak.Redact),
	}, "user", slog.GroupValue(slog.String("name", "Jane"), slog.Int("id", 7)))

	// The group is not replaced wholesale, so its shape survives. Its children are
	// values in their own right and the rule claims each one.
	if !strings.Contains(got, "user.name=") || !strings.Contains(got, "user.id=") {
		t.Fatalf("a group must keep its structure: %s", got)
	}
	if strings.Contains(got, "Jane") {
		t.Fatalf("the rule should still claim the leaves: %s", got)
	}
}

// The skip list governs rules the same as it governs detectors.
func TestValueRuleRespectsSkip(t *testing.T) {
	got := logWithOpts([]cloak.Option{
		cloak.WithSkipValueScan("raw"),
		cloak.WithValuePredicate(func(slog.Value) bool { return true }, cloak.Redact),
	}, "raw", "verbatim", "other", "masked")

	if !strings.Contains(got, "raw=verbatim") {
		t.Errorf("skip should have been honoured: %s", got)
	}
	if !strings.Contains(got, "[REDACTED]") {
		t.Errorf("the other key should still be masked: %s", got)
	}
}

// Rules reach inside the composite walk: struct fields, map values, slice elements.
func TestValueRuleReachesContainers(t *testing.T) {
	type inner struct{ Amount int }
	opts := []cloak.Option{
		cloak.WithStructScan(), cloak.WithMapScan(), cloak.WithSliceScan(),
		cloak.WithValuePredicate(
			func(v slog.Value) bool { return v.Kind() == slog.KindInt64 && v.Int64() > 1_000_000 },
			cloak.Redact,
		),
	}

	var b bytes.Buffer
	logger := slog.New(cloak.New(slog.NewTextHandler(&b, nil), opts...))
	logger.Info("m",
		"struct", inner{Amount: 9999999},
		"map", map[string]int{"amount": 8888888},
		"slice", []int{7777777, 1},
		"small", 5,
	)

	got := b.String()
	for _, leaked := range []string{"9999999", "8888888", "7777777"} {
		if strings.Contains(got, leaked) {
			t.Errorf("leaked %q: %s", leaked, got)
		}
	}
	if !strings.Contains(got, "5") {
		t.Errorf("a value below the threshold must survive: %s", got)
	}
}

// A rule runs after key and type rules and before the format detectors, so an
// explicit rule beats an inferred mask.
func TestValueRuleBeatsDetectorButLosesToKey(t *testing.T) {
	// MaskEmail would turn this into j***@example.com; the rule claims it first.
	got := logWithOpts([]cloak.Option{
		cloak.WithDefaultPIIValues(),
		cloak.WithValueRule(func(v slog.Value) (slog.Value, bool) {
			if v.Kind() == slog.KindString && v.String() == "john@example.com" {
				return slog.StringValue("[custom]"), true
			}
			return v, false
		}),
	}, "note", "john@example.com")

	if !strings.Contains(got, "[custom]") {
		t.Errorf("the value rule should run before the detectors: %s", got)
	}

	// A key rule still wins over a value rule.
	got = logWithOpts([]cloak.Option{
		cloak.WithKey(cloak.KeepLast(3), "email"),
		cloak.WithValueRule(func(v slog.Value) (slog.Value, bool) {
			return slog.StringValue("[custom]"), true
		}),
	}, "email", "john@example.com")

	if !strings.Contains(got, "*************com") {
		t.Errorf("the key rule should win over the value rule: %s", got)
	}
}

func TestValueRuleUnconfiguredIsInert(t *testing.T) {
	got := logWithOpts([]cloak.Option{cloak.WithDefaultPII()},
		"latency_ms", 12345, "enabled", true)
	if !strings.Contains(got, "12345") {
		t.Fatalf("no rule registered, so nothing should change: %s", got)
	}
}

// Rules compose with each other: the first one that offers a replacement decides.
func TestValueRuleFirstMatchWins(t *testing.T) {
	got := logWithOpts([]cloak.Option{
		cloak.WithValueRule(func(v slog.Value) (slog.Value, bool) {
			return slog.StringValue("first"), true
		}),
		cloak.WithValueRule(func(v slog.Value) (slog.Value, bool) {
			return slog.StringValue("second"), true
		}),
	}, "k", "v")

	if !strings.Contains(got, "k=first") {
		t.Fatalf("the first rule should win: %s", got)
	}
}

func logWithRule(r cloak.ValueRule, args ...any) string {
	return logWithOpts([]cloak.Option{cloak.WithValueRule(r)}, args...)
}

func logWithOpts(opts []cloak.Option, args ...any) string {
	var b bytes.Buffer
	slog.New(cloak.New(slog.NewTextHandler(&b, nil), opts...)).Info("m", args...)
	return b.String()
}

func slicesContains(s []string, want string) bool {
	for _, v := range s {
		if v == want {
			return true
		}
	}
	return false
}

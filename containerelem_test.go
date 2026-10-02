package cloak_test

import (
	"log/slog"
	"strings"
	"testing"

	"github.com/lrweck/cloak"
)

// walkElem reads a plain string element straight from reflection, so it never gets
// boxed into an any only to be read back. It is not a second implementation of the
// masking: every rule walk would have applied still has to apply here, or the fast
// path becomes a bypass. Each case below would pass with walk and must pass with it.
func TestContainerElementsStillHonourEveryRule(t *testing.T) {
	cases := []struct {
		name  string
		opts  []cloak.Options
		attr  slog.Attr
		leaks string
	}{
		{
			name:  "detector on a slice element",
			opts:  []cloak.Options{cloak.WithSliceScan(), cloak.WithDefaultPIIValues()},
			attr:  slog.Any("v", []string{"john@example.com"}),
			leaks: "john@example.com",
		},
		{
			name:  "detector on a map value",
			opts:  []cloak.Options{cloak.WithMapScan(), cloak.WithDefaultPIIValues()},
			attr:  slog.Any("v", map[string]string{"contact": "john@example.com"}),
			leaks: "john@example.com",
		},
		{
			// A value rule, not a ValueFunc: the fast path has its own branch for
			// it, and WithContain would not reach it — that goes through maskString
			// with the detectors.
			name: "value rule on a slice element",
			opts: []cloak.Options{cloak.WithSliceScan(),
				cloak.WithValuePredicate(cloak.Fixed("[R]"), func(v slog.Value) bool {
					return v.Kind() == slog.KindString && v.String() == "hit"
				})},
			attr:  slog.Any("v", []string{"hit"}),
			leaks: "hit",
		},
		{
			name: "value rule on a map value",
			opts: []cloak.Options{cloak.WithMapScan(),
				cloak.WithValuePredicate(cloak.Fixed("[R]"), func(v slog.Value) bool {
					return v.Kind() == slog.KindString && v.String() == "hit"
				})},
			attr:  slog.Any("v", map[string]string{"note": "hit"}),
			leaks: "hit",
		},
		{
			name:  "value function on a slice element",
			opts:  []cloak.Options{cloak.WithSliceScan(), cloak.WithContain("s3cr3t")},
			attr:  slog.Any("v", []string{"prefix s3cr3t suffix"}),
			leaks: "s3cr3t",
		},
		{
			name:  "value function on a map value",
			opts:  []cloak.Options{cloak.WithMapScan(), cloak.WithContain("s3cr3t")},
			attr:  slog.Any("v", map[string]string{"note": "prefix s3cr3t suffix"}),
			leaks: "s3cr3t",
		},
		{
			name:  "key rule reaches the map value",
			opts:  []cloak.Options{cloak.WithMapScan(), cloak.WithKeys(cloak.Redact, "password")},
			attr:  slog.Any("v", map[string]string{"password": "hunter2"}),
			leaks: "hunter2",
		},
		{
			name:  "skip list leaves the map value alone",
			opts:  []cloak.Options{cloak.WithMapScan(), cloak.WithDefaultPIIValues(), cloak.WithSkipValueScan("payload")},
			attr:  slog.Any("v", map[string]string{"payload": "john@example.com"}),
			leaks: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := logWith(tc.opts, func(l *slog.Logger) { l.Info("m", tc.attr) })
			if tc.leaks != "" && strings.Contains(got, tc.leaks) {
				t.Errorf("the fast path bypassed a rule: %s", got)
			}
			if tc.leaks == "" && !strings.Contains(got, "john@example.com") {
				t.Errorf("the skip list was ignored: %s", got)
			}
		})
	}
}

// A named string type arrives as KindAny, so walkElem defers to walk for it. The
// masking has to be identical either way; only the allocation differs.
type containerEmail string

func TestNamedStringElementTakesTheOrdinaryPath(t *testing.T) {
	got := logWith([]cloak.Options{
		cloak.WithSliceScan(), cloak.WithMapScan(), cloak.WithDefaultPIIValues(),
	}, func(l *slog.Logger) {
		l.Info("m",
			slog.Any("slice", []containerEmail{"john@example.com"}),
			slog.Any("map", map[string]containerEmail{"contact": containerEmail("john@example.com")}),
		)
	})

	if strings.Contains(got, "john@example.com") {
		t.Fatalf("a named string type leaked: %s", got)
	}
}

// A type rule has to keep working on a plain string element, which is the one case
// walkElem answers without walking: it checks typeMasks by the field's type directly.
func TestTypeRuleOnPlainStringElement(t *testing.T) {
	got := logWith([]cloak.Options{
		cloak.WithSliceScan(), cloak.WithType[string](),
	}, func(l *slog.Logger) {
		l.Info("m", slog.Any("v", []string{"anything"}))
	})

	if strings.Contains(got, "anything") {
		t.Fatalf("the type rule did not reach the element: %s", got)
	}
}

// A slice where nothing matched must not pay for the rebuilt slice or the widened
// fallback, at any width. Asserted as a slope so a fixed offset from the sink or the
// race detector does not decide the result.
func TestPassthroughSliceCostDoesNotGrowWithWidth(t *testing.T) {
	opts := func() []cloak.Options {
		return []cloak.Options{cloak.WithSliceScan(), cloak.WithDefaultPIIValues()}
	}
	narrow := extraAllocs(opts(), slog.Any("v", []string{"abc", "def"}))
	wide := extraAllocs(opts(), slog.Any("v", []string{
		"a", "b", "c", "d", "e", "f", "g", "h", "i", "j",
		"k", "l", "m", "n", "o", "p", "q", "r", "s", "t",
	}))

	if wide > narrow+3 {
		t.Errorf("a slice where nothing matched cost %d extra at 20 elements against %d at 2: "+
			"the walk is rebuilding or boxing something it discards", wide, narrow)
	}
}

// The widened slice has to carry every element, including the ones after the element
// that broke the shape.
func TestWidenedSliceKeepsEveryElement(t *testing.T) {
	// A value rule that turns an int into a string breaks the element type, so the
	// slice widens; the elements around it still have to survive.
	got := logWith([]cloak.Options{
		cloak.WithSliceScan(),
		cloak.WithValuePredicate(cloak.Fixed("X"), func(v slog.Value) bool {
			return v.Kind() == slog.KindInt64 && v.Int64() == 2
		}),
	}, func(l *slog.Logger) {
		l.Info("m", slog.Any("v", []int64{1, 2, 3}))
	})

	for _, want := range []string{"1", "X", "3"} {
		if !strings.Contains(got, want) {
			t.Errorf("expected %q in the widened slice: %s", want, got)
		}
	}
}

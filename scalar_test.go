package cloak_test

import (
	"log/slog"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/lrweck/cloak"
)

// setScalar writes a masked slog.Value straight into a field of the matching type,
// skipping the any round trip convert would take. Each branch has to be exercised:
// a Set of the wrong kind panics, and a masking library panicking inside a log call
// is worse than the allocation it saves.
//
// The predicate matches the field's Go type — a struct field arrives as KindAny — and
// the masker returns the kind setScalar's branch expects, which is what makes the
// direct path reachable at all.
func TestMaskedScalarKindsKeepTheirType(t *testing.T) {
	// returns is a Masker that always yields the given value, so a field of the
	// matching Go type takes setScalar's direct path.
	returns := func(v slog.Value) cloak.Masker {
		return func(slog.Value) slog.Value { return v }
	}
	// Any() is the value slog.Value kind carries, so this matches a field of the
	// declared Go type whatever kind AnyValue gave it.
	isType := func(want reflect.Type) func(slog.Value) bool {
		return func(v slog.Value) bool { return reflect.TypeOf(v.Any()) == want }
	}
	at := time.Date(2020, 3, 4, 5, 6, 7, 0, time.UTC)

	cases := []struct {
		name  string
		field any
		opt   cloak.Options
		want  string
	}{
		{
			"string",
			struct{ N string }{"secret"},
			cloak.WithValuePredicate(returns(slog.StringValue("[X]")), isType(reflect.TypeFor[string]())),
			"N:[X]",
		},
		{
			"int64",
			struct{ N int64 }{42},
			cloak.WithValuePredicate(returns(slog.Int64Value(-1)), isType(reflect.TypeFor[int64]())),
			"N:-1",
		},
		{
			"uint64",
			struct{ N uint64 }{42},
			cloak.WithValuePredicate(returns(slog.Uint64Value(7)), isType(reflect.TypeFor[uint64]())),
			"N:7",
		},
		{
			"float64",
			struct{ N float64 }{4.5},
			cloak.WithValuePredicate(returns(slog.Float64Value(1.25)), isType(reflect.TypeFor[float64]())),
			"N:1.25",
		},
		{
			"bool",
			struct{ N bool }{true},
			cloak.WithValuePredicate(returns(slog.BoolValue(false)), isType(reflect.TypeFor[bool]())),
			"N:false",
		},
		{
			"time.Duration",
			struct{ N time.Duration }{time.Second},
			cloak.WithValuePredicate(returns(slog.DurationValue(90*time.Second)), isType(reflect.TypeFor[time.Duration]())),
			"N:1m30s",
		},
		{
			"time.Time",
			struct{ N time.Time }{at},
			cloak.WithValuePredicate(returns(slog.TimeValue(at.Add(time.Hour))), isType(reflect.TypeFor[time.Time]())),
			"06:06:07 +0000 UTC",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := logWith([]cloak.Options{cloak.WithStructScan(), tc.opt},
				func(l *slog.Logger) { l.Info("m", slog.Any("v", tc.field)) })

			if !strings.Contains(got, tc.want) {
				t.Errorf("expected %q: %s", tc.want, got)
			}
			// A group renders as `v.N=...`; a struct keeps its braces, quoted when
			// a %+v rendering like time.Time's contains spaces.
			if strings.Contains(got, "v.N=") {
				t.Errorf("the masked value fit, so the struct should not have widened: %s", got)
			}
		})
	}
}

// A named type is not the same as its underlying type for assignability, so it must
// fall through to convert rather than take the direct path. It widens to a group,
// which is the pre-existing behaviour and the reason the fallback exists.
func TestNamedScalarFallsBackToConvert(t *testing.T) {
	returns := func(v slog.Value) cloak.Masker {
		return func(slog.Value) slog.Value { return v }
	}
	type Weight int64
	got := logWith([]cloak.Options{
		cloak.WithStructScan(),
		cloak.WithValuePredicate(returns(slog.Int64Value(0)), func(v slog.Value) bool {
			return reflect.TypeOf(v.Any()) == reflect.TypeFor[Weight]()
		}),
	}, func(l *slog.Logger) { l.Info("m", slog.Any("v", struct{ N Weight }{N: 42})) })

	if !strings.Contains(got, "v.N=0") {
		t.Errorf("a named type cannot take the direct Set path, so it widens: %s", got)
	}
}

// An int64 field is also worth checking against a mask that returns the wrong kind:
// it must widen rather than panic or silently keep the original.
func TestWrongKindMaskWidensRatherThanPanics(t *testing.T) {
	got := logWith([]cloak.Options{
		cloak.WithStructScan(),
		cloak.WithKeys(cloak.KeepLast(2), "n"),
	}, func(l *slog.Logger) { l.Info("m", slog.Any("v", struct{ N int64 }{123456})) })

	// KeepLast returns a string, which no int64 field can hold.
	if !strings.Contains(got, "v.N=****56") {
		t.Errorf("expected the string mask in a widened group: %s", got)
	}
}

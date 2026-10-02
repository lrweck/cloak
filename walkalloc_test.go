package cloak_test

import (
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/lrweck/cloak"
)

// The rebuild is deferred to the first change, so the copy has to carry whatever the
// walk already passed over. A change before and after an unchanged run is the case
// that catches a prefix taken from the wrong source, since the deferred copy must
// still see the first field's masked value.
func TestLazyRebuildCarriesEveryField(t *testing.T) {
	type four struct{ Alpha, Beta, Gamma, Delta string }

	cases := []struct {
		name string
		in   four
		opts []cloak.Options
		want []string
	}{
		{
			name: "first and last change",
			in:   four{"hit", "b", "c", "hit"},
			want: []string{"Alpha:[REDACTED]", "Beta:b", "Gamma:c", "Delta:[REDACTED]"},
		},
		{
			name: "only the first changes",
			in:   four{"hit", "b", "c", "d"},
			want: []string{"Alpha:[REDACTED]", "Beta:b", "Gamma:c", "Delta:d"},
		},
		{
			name: "only the last changes",
			in:   four{"a", "b", "c", "hit"},
			want: []string{"Alpha:a", "Beta:b", "Gamma:c", "Delta:[REDACTED]"},
		},
		{
			name: "nothing changes, so nothing is rebuilt",
			in:   four{"a", "b", "c", "d"},
			want: []string{"Alpha:a", "Beta:b", "Gamma:c", "Delta:d"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The match is decided by the value, not the name: a key rule would
			// redact Alpha and Delta in every case and prove nothing about which
			// fields the rebuild carried over.
			got := logWith([]cloak.Options{
				cloak.WithStructScan(),
				cloak.WithValueFunc(func(s string) (string, bool) {
					if s == "hit" {
						return "[REDACTED]", true
					}
					return s, false
				}),
			}, func(l *slog.Logger) { l.Info("m", slog.Any("v", tc.in)) })

			for _, want := range tc.want {
				if !strings.Contains(got, want) {
					t.Errorf("expected %q: %s", want, got)
				}
			}
		})
	}
}

// A dropped field forces the rebuild even when no rule matched, and the fields around
// it still have to survive.
func TestLazyRebuildAroundADroppedField(t *testing.T) {
	type withPrivate struct {
		Alpha   string
		hidden  string
		Delta   string
		Another string
	}
	got := logWith([]cloak.Options{cloak.WithStructScan()}, func(l *slog.Logger) {
		l.Info("m", slog.Any("v", withPrivate{Alpha: "a", hidden: "hunter2", Delta: "d", Another: "e"}))
	})

	if strings.Contains(got, "hunter2") {
		t.Errorf("the unexported field reached the sink: %s", got)
	}
	for _, want := range []string{"Alpha:a", "Delta:d", "Another:e"} {
		if !strings.Contains(got, want) {
			t.Errorf("expected %q to survive the rebuild: %s", want, got)
		}
	}
}

// extraAllocs is what cloak costs over the same record through a bare handler. The
// sink's own cost is subtracted rather than assumed, because it depends on the shape:
// the JSON encoder allocates per field, and under -race it allocates more. A fixed
// number would drift with the Go version and the sink; a delta against the same record
// measures the masking and nothing else.
func extraAllocs(opts []cloak.Options, attr slog.Attr) int {
	cloaked := slog.New(cloak.New(slog.NewJSONHandler(io.Discard, nil), opts...))
	bare := slog.New(slog.NewJSONHandler(io.Discard, nil))
	with := int(testing.AllocsPerRun(300, func() { cloaked.Info("m", attr) }))
	without := int(testing.AllocsPerRun(300, func() { bare.Info("m", attr) }))
	return with - without
}

// twentyFields is wide enough that a per-field cost is unmistakable against the
// race detector's own variance, which is about one allocation per measurement.
type twentyFields struct {
	A, B, C, D, E, F, G, H, I, J string
	K, L, M, N, O, P, Q, R, S, T string
}

// The quiet path is the one worth protecting: a struct where nothing matched must not
// cost more at twenty fields than at two. It used to box every field into a group it
// then threw away, which made the extra cost grow with the width — about 18 more
// allocations across these two, against a tolerance of 3.
func TestPassthroughStructCostDoesNotGrowWithWidth(t *testing.T) {
	opts := func() []cloak.Options {
		return []cloak.Options{cloak.WithStructScan(), cloak.WithDefaultPII()}
	}
	narrow := extraAllocs(opts(), slog.Any("v", struct{ A, B string }{"a", "b"}))
	wide := extraAllocs(opts(), slog.Any("v", twentyFields{
		A: "a", B: "b", C: "c", D: "d", E: "e", F: "f", G: "g", H: "h",
		I: "i", J: "j", K: "k", L: "l", M: "m", N: "n", O: "o", P: "p",
		Q: "q", R: "r", S: "s", T: "t",
	}))

	if wide > narrow+3 {
		t.Errorf("a struct where nothing matched cost %d extra at 20 fields against %d at 2: "+
			"the walk is paying per field for something it discards", wide, narrow)
	}
}

// A masked field still costs something — a new string has to exist — but only the
// match, not a per-field toll. Measured as a delta so the sink's per-field cost, which
// grows with width on its own, does not mask the signal.
func TestMatchedFieldCostDoesNotGrowWithWidth(t *testing.T) {
	opts := func() []cloak.Options {
		return []cloak.Options{cloak.WithStructScan(), cloak.WithKeys(cloak.Redact, "email")}
	}
	narrow := extraAllocs(opts(), slog.Any("v", struct{ Email string }{Email: "x"}))
	wide := extraAllocs(opts(), slog.Any("v", struct {
		A, B, C, D, E, F, G, H, I, J string
		Email                        string
	}{Email: "x"}))

	// One masked field among eleven must not cost eleven times one among one.
	if wide > narrow+3 {
		t.Errorf("one masked field among 11 cost %d extra against %d for one among 1: "+
			"the per-field cost is back", wide, narrow)
	}
}

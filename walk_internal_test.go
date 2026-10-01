package cloak

import (
	"io"
	"log/slog"
	"testing"
)

func TestNoReflectWithoutCompositeOption(t *testing.T) {
	walkCalls = 0
	logger := slog.New(New(slog.NewTextHandler(io.Discard, nil), WithDefaultPII()))
	logger.Info("m",
		"struct", struct{ Email string }{Email: "a@b.com"},
		"map", map[string]any{"email": "a@b.com"},
		"slice", []string{"a@b.com"},
		"ptr", &struct{ Email string }{Email: "a@b.com"},
	)
	if walkCalls != 0 {
		t.Fatalf("walk ran %d times without a composite option", walkCalls)
	}
}

func TestReflectRunsWithCompositeOption(t *testing.T) {
	walkCalls = 0
	logger := slog.New(New(slog.NewTextHandler(io.Discard, nil),
		WithDefaultPII(), WithCompositeScan()))
	logger.Info("m", "struct", struct{ Email string }{Email: "a@b.com"})
	if walkCalls == 0 {
		t.Fatal("walk did not run with WithCompositeScan")
	}
}

// Each option must reach only the shape it names.
func TestClassify(t *testing.T) {
	type s struct{ A string }
	cases := []struct {
		name string
		in   any
		want composite
	}{
		{"struct", s{}, compositeStruct},
		{"map", map[string]any{}, compositeMap},
		{"slice", []string{}, compositeSlice},
		{"bytes", []byte{}, 0},
		{"string", "x", 0},
		{"int", 1, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classify(tc.in); got != tc.want {
				t.Errorf("classify(%s) = %d, want %d", tc.name, got, tc.want)
			}
		})
	}
}

func TestOptionScoping(t *testing.T) {
	cases := []struct {
		opt  Option
		name string
		want composite
	}{
		{WithStructScan(), "struct", compositeStruct | compositePtr},
		{WithMapScan(), "map", compositeMap | compositePtr},
		{WithSliceScan(), "slice", compositeSlice | compositePtr},
		{WithCompositeScan(), "all", compositeStruct | compositeMap | compositeSlice | compositePtr},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &config{keys: map[string]Masker{}, skip: map[string]struct{}{}}
			tc.opt(c)
			if c.scan != tc.want {
				t.Errorf("scan = %d, want %d", c.scan, tc.want)
			}
		})
	}
}

// A pointer is followed by every option, because a pointer is only an address to the
// value behind it. Passing a struct by pointer is the common case.
func TestPointerIsWalkedByEveryOption(t *testing.T) {
	for _, opt := range []Option{WithStructScan(), WithMapScan(), WithSliceScan(), WithCompositeScan()} {
		c := &config{keys: map[string]Masker{}, skip: map[string]struct{}{}}
		opt(c)
		if !c.scans(&struct{ Email string }{}) {
			t.Error("pointer attr would not be walked")
		}
	}
}

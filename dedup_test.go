package cloak_test

import (
	"bytes"
	"log/slog"
	"regexp"
	"strings"
	"testing"

	"github.com/lrweck/cloak"
)

// Declaring the same rule twice must not scan twice, and must not change which rule
// applies. Every keyed rule replaces: a new rule for a key already present takes over,
// at the position it already had.
func TestRepeatedRulesReplaceRatherThanAccumulate(t *testing.T) {
	t.Run("substring", func(t *testing.T) {
		got := maskWith(t, []cloak.Options{
			cloak.WithKeysContaining(cloak.Redact, "pass"),
			cloak.WithKeysContaining(cloak.Redact, "pass"),
			cloak.WithKeysContaining(cloak.Redact, "pass"),
		}, "Password", "p1")
		if strings.Count(got, "[REDACTED]") != 1 {
			t.Fatalf("expected one redaction: %s", got)
		}
	})

	t.Run("pattern", func(t *testing.T) {
		got := maskWith(t, []cloak.Options{
			cloak.WithKeyRegex(cloak.Redact, `_key$`),
			cloak.WithKeyRegex(cloak.Redact, `_key$`),
		}, "api_key", "k1", "other", "k2")
		if strings.Count(got, "[REDACTED]") != 1 {
			t.Fatalf("expected one redaction: %s", got)
		}
		if !strings.Contains(got, "k2") {
			t.Errorf("unrelated key must survive: %s", got)
		}
	})

	t.Run("tag", func(t *testing.T) {
		got := maskWith(t, []cloak.Options{
			cloak.WithStructScan(),
			cloak.WithTag(cloak.Redact, "cloak", "secret"),
			cloak.WithTag(cloak.Redact, "cloak", "secret"),
		}, slog.Any("v", tagged{Password: "hunter2"}))
		if strings.Count(got, "[REDACTED]") != 1 {
			t.Fatalf("expected one redaction: %s", got)
		}
	})

	t.Run("string and precompiled are the same rule", func(t *testing.T) {
		got := maskWith(t, []cloak.Options{
			cloak.WithKeyRegex(cloak.Redact, `_key$`),
			cloak.WithKeyRegexp(cloak.Redact, regexp.MustCompile(`_key$`)),
		}, "api_key", "k1")
		if strings.Count(got, "[REDACTED]") != 1 {
			t.Fatalf("expected one redaction: %s", got)
		}
	})
}

// The newest masker wins for the same rule, which is what a map does everywhere else
// in the library.
func TestLastMaskerWins(t *testing.T) {
	cases := []struct {
		name string
		opts []cloak.Options
		key  string
		val  any
		want string
	}{
		{
			"substring",
			[]cloak.Options{cloak.WithKeysContaining(cloak.Redact, "pw"), cloak.WithKeysContaining(cloak.KeepLast(2), "pw")},
			"pw", "hunter2", "*****r2",
		},
		{
			"pattern",
			[]cloak.Options{cloak.WithKeyRegex(cloak.Redact, `^pw$`), cloak.WithKeyRegex(cloak.KeepLast(2), `^pw$`)},
			"pw", "hunter2", "*****r2",
		},
		{
			"exact key, for comparison",
			[]cloak.Options{cloak.WithKeys(cloak.Redact, "pw"), cloak.WithKeys(cloak.KeepLast(2), "pw")},
			"pw", "hunter2", "*****r2",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := maskWith(t, tc.opts, tc.key, tc.val)
			if !strings.Contains(got, tc.want) {
				t.Fatalf("want %q, got %s", tc.want, got)
			}
		})
	}
}

// Two different substring rules must both stay, and their relative order decides the
// winner — deduplication must not turn the list into a set.
func TestDistinctRulesKeepTheirOrder(t *testing.T) {
	got := maskWith(t, []cloak.Options{
		cloak.WithKeysContaining(cloak.KeepLast(2), "pass"),
		cloak.WithKeysContaining(cloak.Redact, "secret"),
	}, "user_password_secret", "hunter2")

	// "pass" is registered first and both parts match, so it wins.
	if !strings.Contains(got, "*****r2") {
		t.Fatalf("the first matching rule should win: %s", got)
	}
}

// The same holds for patterns: two distinct patterns both stay registered.
func TestDistinctPatternsBothStay(t *testing.T) {
	got := maskWith(t, []cloak.Options{
		cloak.WithKeyRegex(cloak.Redact, `_key$`),
		cloak.WithKeyRegex(cloak.KeepLast(2), `^x-`),
	}, "x-api_key", "abcdef", "other", "zz")

	if strings.Contains(got, "abcdef") || !strings.Contains(got, "zz") {
		t.Fatalf("unexpected: %s", got)
	}
	// Two patterns match x-api_key; the first registered decides.
	if strings.Count(got, "REDACTED") != 1 {
		t.Fatalf("expected exactly one rule to apply: %s", got)
	}
}

// maskWith logs one record under the given options and returns the output.
func maskWith(t *testing.T, opts []cloak.Options, args ...any) string {
	t.Helper()
	var b bytes.Buffer
	logger := slog.New(cloak.New(slog.NewTextHandler(&b, nil), opts...))
	logger.Info("m", args...)
	return b.String()
}

// KeepLast(4) and KeepLast(9) share a code pointer. The library must not treat them as
// the same rule, or one of them would be dropped with no symptom.
func TestClosuresSharingCodePointerAreDistinct(t *testing.T) {
	got := maskWith(t, []cloak.Options{
		cloak.WithKeys(cloak.KeepLast(4), "a"),
		cloak.WithKeys(cloak.KeepLast(9), "b"),
	}, "a", "abcdefghijkl", "b", "xyzabcdefghijkl")

	// Both rules applied: KeepLast(4) keeps four characters, KeepLast(9) keeps nine.
	for _, want := range []string{"a=********ijkl", "b=******defghijkl"} {
		if !strings.Contains(got, want) {
			t.Fatalf("expected %q, so that neither rule was dropped: %s", want, got)
		}
	}
}

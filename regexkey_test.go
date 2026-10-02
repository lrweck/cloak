package cloak_test

import (
	"bytes"
	"log/slog"
	"regexp"
	"strings"
	"testing"

	"github.com/lrweck/cloak"
)

func logRegex(opts []cloak.Option, args ...any) string {
	var b bytes.Buffer
	logger := slog.New(cloak.New(slog.NewTextHandler(&b, nil), opts...))
	logger.Info("m", args...)
	return b.String()
}

func TestKeyRegexAnchored(t *testing.T) {
	// The whole point: anchors only work against the name as written.
	got := logRegex([]cloak.Option{cloak.WithKeyRegex(`_key$`, cloak.Redact)},
		"api_key", "sk-123", "x_api_key", "sk-456", "key_id", "k-1")

	if strings.Contains(got, "sk-123") || strings.Contains(got, "sk-456") {
		t.Errorf("_key$ should have matched: %s", got)
	}
	if !strings.Contains(got, "k-1") {
		t.Errorf("key_id must not match _key$: %s", got)
	}
}

func TestKeyRegexHyphenPrefix(t *testing.T) {
	got := logRegex([]cloak.Option{cloak.WithKeyRegex(`^x-.*-token$`, cloak.Redact)},
		"x-auth-token", "t-1", "x-api-key", "k-2")

	if strings.Contains(got, "t-1") {
		t.Errorf("pattern should have matched: %s", got)
	}
	if !strings.Contains(got, "k-2") {
		t.Errorf("x-api-key must not match: %s", got)
	}
}

// An invalid pattern must fail loudly at construction, not silently match nothing.
func TestKeyRegexPanicsOnBadPattern(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected a panic on an invalid pattern")
		}
	}()
	cloak.WithKeyRegex("[unclosed", cloak.Redact)
}

// A discarded compile error hands over a nil regexp. It must fail here, not during a
// log call with no stack pointing at the mistake.
func TestKeyRegexpRejectsNil(t *testing.T) {
	re, err := regexp.Compile("[unclosed")
	if err == nil || re != nil {
		t.Fatalf("expected a nil regexp and an error, got %v %v", re, err)
	}
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected a panic on a nil pattern")
		}
	}()
	cloak.WithKeyRegexp(re, cloak.Redact)
}

func TestKeyRegexCaseInsensitiveAlternation(t *testing.T) {
	got := logRegex([]cloak.Option{cloak.WithKeyRegex(`(?i)pass|secret|token`, cloak.Redact)},
		"Password", "p1", "user_secret", "s1", "ACCESS_TOKEN", "t1", "user_id", "u1")

	for _, leaked := range []string{"p1", "s1", "t1"} {
		if strings.Contains(got, leaked) {
			t.Errorf("leaked %q: %s", leaked, got)
		}
	}
	if !strings.Contains(got, "u1") {
		t.Errorf("user_id must not match: %s", got)
	}
}

// A case-sensitive literal must not be dragged into case-insensitivity by the
// normalization WithKeyContains also applies.
func TestKeyRegexCaseSensitiveLiteral(t *testing.T) {
	got := logRegex([]cloak.Option{cloak.WithKeyRegex(`Secret`, cloak.Redact)},
		"Secret", "s1", "secret", "s2")

	if strings.Contains(got, "s1") {
		t.Errorf("exact-case literal should have matched: %s", got)
	}
	if !strings.Contains(got, "s2") {
		t.Errorf("lowercase must not match a case-sensitive literal: %s", got)
	}
}

// An explicit key rule is more specific than a pattern.
func TestKeyRegexLosesToExactKey(t *testing.T) {
	got := logRegex([]cloak.Option{
		cloak.WithKeyRegex(`(?i)pass`, cloak.Redact),
		cloak.WithKey(cloak.KeepLast(2), "Password"),
	}, "Password", "hunter2")

	// KeepLast(2) on "hunter2" is five stars plus "r2".
	if !strings.Contains(got, "*****r2") {
		t.Errorf("the exact key rule must win: %s", got)
	}
}

// And a pattern beats a substring rule.
func TestKeyRegexBeatsKeyContains(t *testing.T) {
	got := logRegex([]cloak.Option{
		cloak.WithKeyContains(cloak.Redact, "pass"),
		cloak.WithKeyRegex(`^Password$`, cloak.KeepLast(3)),
	}, "Password", "hunter2")

	if !strings.Contains(got, "****er2") {
		t.Errorf("the pattern must win over the substring rule: %s", got)
	}
}

// The rule applies wherever a key applies, including inside containers.
func TestKeyRegexReachesContainers(t *testing.T) {
	got := logRegex([]cloak.Option{
		cloak.WithMapScan(), cloak.WithStructScan(),
		cloak.WithKeyRegex(`(?i)secret`, cloak.Redact),
	},
		"m", map[string]string{"user_secret": "s1"},
		"s", struct{ ClientSecret string }{ClientSecret: "s2"},
	)

	if strings.Contains(got, "s1") || strings.Contains(got, "s2") {
		t.Errorf("pattern did not reach the containers: %s", got)
	}
}

// A pattern naming something present in ordinary text must not fire on values, only
// on keys.
func TestKeyRegexDoesNotTouchValues(t *testing.T) {
	got := logRegex([]cloak.Option{cloak.WithKeyRegex(`(?i)pass`, cloak.Redact)},
		"note", "password is required")

	if !strings.Contains(got, "password is required") {
		t.Errorf("a key rule must not rewrite values: %s", got)
	}
}

// With no pattern registered the fast path must cost nothing measurable.
func TestKeyRegexUnconfiguredIsInert(t *testing.T) {
	// request_id is not a default PII key, so only a pattern could match it.
	got := logRegex([]cloak.Option{cloak.WithDefaultPII()},
		"request_id", "req-123")
	if !strings.Contains(got, "req-123") {
		t.Fatalf("no pattern registered, so nothing should match: %s", got)
	}
}

func BenchmarkKeyRegexLiteral(b *testing.B) {
	var buf bytes.Buffer
	logger := slog.New(cloak.New(slog.NewTextHandler(&buf, nil),
		cloak.WithKeyRegex(`(?i)pass|secret|token`, cloak.Redact),
		cloak.WithKeyRegex(`_key$`, cloak.Redact),
		cloak.WithKeyRegex(`^authorization$`, cloak.Redact)))
	b.ReportAllocs()
	for b.Loop() {
		logger.Info("payment settled", "id", 42, "ok", true)
	}
}

// The same rules spelled as three substring matches, for the cost comparison.
func BenchmarkKeyContainsBaseline(b *testing.B) {
	var buf bytes.Buffer
	logger := slog.New(cloak.New(slog.NewTextHandler(&buf, nil),
		cloak.WithKeyContains(cloak.Redact, "pass", "secret", "token", "_key", "authorization")))
	b.ReportAllocs()
	for b.Loop() {
		logger.Info("payment settled", "id", 42, "ok", true)
	}
}

// Same regex semantics, two paths. The parenthesised form defeats the literal
// extractor while matching identically, so the difference is the AOT layer and
// nothing else.
func BenchmarkKeyRegexAOTvsSlowPath(b *testing.B) {
	cases := []struct {
		name    string
		pattern string
		aot     bool
	}{
		{"alternation_aot", `(?i)pass|secret|token`, true},
		{"alternation_regex", `(?i)(pass|secret|token)`, false},
		{"literal_aot", `authorization`, true},
		{"literal_regex", `(authorization)`, false},
	}
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			var buf bytes.Buffer
			logger := slog.New(cloak.New(slog.NewTextHandler(&buf, nil),
				cloak.WithKeyRegex(tc.pattern, cloak.Redact)))
			b.ReportAllocs()
			for b.Loop() {
				logger.Info("payment settled", "id", 42, "ok", true, "user_email", "a@b.com")
			}
		})
	}
}

// The fast path must never mask less than the regexp it replaces. A missed key is a
// leak, and it is the one failure this library cannot have.
func TestKeyRegexFastPathNeverMasksLess(t *testing.T) {
	pairs := []struct{ fast, slow string }{
		{`(?i)pass|secret|token`, `(?i)(pass|secret|token)`},
		{`authorization`, `(authorization)`},
		{`(?i)api_key`, `(?i)(api_key)`},
		{`secret`, `(secret)`},
	}
	keys := []string{
		"password", "PASS", "user_secret", "access_token", "authorization",
		"api_key", "apiKey", "api-key", "secret", "Secret", "SECRET",
		"mysecretvalue", "request_id", "latency_ms", "id", "", "tok",
	}
	for _, p := range pairs {
		t.Run(p.fast, func(t *testing.T) {
			for _, k := range keys {
				if k == "" {
					continue // slog drops an empty key
				}
				fast := logRegex([]cloak.Option{cloak.WithKeyRegex(p.fast, cloak.Redact)}, k, "v")
				slow := logRegex([]cloak.Option{cloak.WithKeyRegex(p.slow, cloak.Redact)}, k, "v")
				fastMasked := strings.Contains(fast, "[REDACTED]")
				slowMasked := strings.Contains(slow, "[REDACTED]")
				if slowMasked && !fastMasked {
					t.Errorf("fast path missed %q that the regexp masked", k)
				}
				t.Logf("%-16q fast=%-5v slow=%-5v", k, fastMasked, slowMasked)
			}
		})
	}
}

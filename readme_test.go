package cloak_test

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/lrweck/cloak"
)

// The README shows this exact import path and package name.
var _ = cloak.WithDefaultPII

func TestReadmeBasicUsage(t *testing.T) {
	var out bytes.Buffer
	handler := cloak.New(slog.NewJSONHandler(&out, nil), cloak.WithDefaultPII())
	slog.New(handler).Info("payment", "email", "john@example.com", "card", "4111111111111111")

	got := out.String()
	for _, leaked := range []string{"john@example.com", "4111111111111111"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("README claims no leak, but %q appears in %s", leaked, got)
		}
	}
	t.Logf("json: %s", strings.TrimSpace(got))
}

func TestReadmeKeyMaskingExample(t *testing.T) {
	var out bytes.Buffer
	next := slog.NewTextHandler(&out, nil)
	handler := cloak.New(next, cloak.WithKey(cloak.KeepLast(4), "card_number"))
	slog.New(handler).Info("m", "card_number", "4111111111111111")
	if !strings.Contains(out.String(), "card_number=************1111") {
		t.Fatalf("README table wrong: %s", out.String())
	}
}

func TestReadmeMaskerTable(t *testing.T) {
	cases := []struct {
		name, want string
		masker     cloak.Masker
	}{
		{"Redact", "[REDACTED]", cloak.Redact},
		{"Fixed", "***", cloak.Fixed("***")},
		{"KeepLast", "************1111", cloak.KeepLast(4)},
		{"KeepFirst", "4111************", cloak.KeepFirst(4)},
		{"KeepEnds", "4111********1111", cloak.KeepEnds(4, 4)},
		{"MaskMiddle", "4111********1111", cloak.MaskMiddle(4, 4)},
	}
	for _, tc := range cases {
		got := tc.masker(slog.StringValue("4111111111111111")).String()
		if got != tc.want {
			t.Errorf("%s = %q, README says %q", tc.name, got, tc.want)
		}
	}
}

func TestReadmeNormalizationClaim(t *testing.T) {
	var out bytes.Buffer
	next := slog.NewTextHandler(&out, nil)
	handler := cloak.New(next, cloak.WithKey(cloak.Redact, "card_number"))
	l := slog.New(handler)
	l.Info("m", "card_number", "a")
	l.Info("m", "cardNumber", "a")
	l.Info("m", "CARD-NUMBER", "a")
	l.Info("m", "Card Number", "a")

	if n := strings.Count(out.String(), "[REDACTED]"); n != 4 {
		t.Fatalf("README says all 4 spellings match one rule, got %d redactions: %s", n, out.String())
	}
}

func TestReadmeGroupClaim(t *testing.T) {
	var out bytes.Buffer
	next := slog.NewTextHandler(&out, nil)
	handler := cloak.New(next, cloak.WithDefaultPII())
	slog.New(handler).Info("m", slog.Group("user",
		slog.Int("id", 7),
		slog.String("email", "john@example.com"),
		slog.String("name", "Jane"),
	))
	got := out.String()
	for _, want := range []string{"user.id=7", "user.name=Jane"} {
		if !strings.Contains(got, want) {
			t.Errorf("README promises %q: %s", want, got)
		}
	}
	if strings.Contains(got, "john@example.com") {
		t.Errorf("email leaked: %s", got)
	}
	t.Logf("group: %s", strings.TrimSpace(got))
}

func TestReadmeSkipClaim(t *testing.T) {
	var out bytes.Buffer
	next := slog.NewTextHandler(&out, nil)
	handler := cloak.New(next, cloak.WithValueFunc(cloak.MaskEmail), cloak.WithSkipValueScan("raw_payload"))
	slog.New(handler).Info("m", "raw_payload", "a@b.com", "message", "c@d.com")
	got := out.String()
	if !strings.Contains(got, "raw_payload=a@b.com") {
		t.Errorf("skip failed: %s", got)
	}
	if !strings.Contains(got, "message=c***@d.com") {
		t.Errorf("other keys must still be scanned: %s", got)
	}
}

func TestReadmeDetectorExamples(t *testing.T) {
	cases := []struct{ in, want string }{
		{"cpf 529.982.247-25", "cpf ***.***.***-**"},
		{"user 42 cpf 529.982.247-25", "user 42 cpf ***.***.***-**"},
		{"card 4111 1111 1111 1111 order 42", "card ****1111 order 42"},
	}
	for _, tc := range cases {
		// README claims all detectors together produce this, as WithDefaultPII would.
		var out bytes.Buffer
		next := slog.NewTextHandler(&out, nil)
		handler := cloak.New(next, cloak.WithDefaultPIIValues())
		slog.New(handler).Info("m", "text", tc.in)
		if !strings.Contains(out.String(), tc.want) {
			t.Errorf("README says %q -> %q; got %s", tc.in, tc.want, strings.TrimSpace(out.String()))
		}
	}
}

func TestReadmeNilNext(t *testing.T) {
	slog.New(cloak.New(nil, cloak.WithDefaultPII())).Info("m", "password", "x")
}

func TestReadmeMainExampleCompiles(t *testing.T) {
	// Matches the README "Usage" block, writing to a buffer instead of stdout.
	var out bytes.Buffer
	handler := cloak.New(
		slog.NewJSONHandler(&out, nil),
		cloak.WithDefaultPII(),
		cloak.WithMessageScan(),
		cloak.WithAnyScan(),
	)
	slog.New(handler).Info("user john@example.com logged in", "customer", struct{ Email string }{Email: "a@b.com"})
	t.Logf("full preset: %s", strings.TrimSpace(out.String()))
	if strings.Contains(out.String(), "john@example.com") || strings.Contains(out.String(), "a@b.com") {
		t.Fatalf("leak under the full preset: %s", out.String())
	}
}

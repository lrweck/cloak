package cloak_test

import (
	"log/slog"
	"strings"
	"testing"

	"github.com/lrweck/cloak"
)

// The message is a property of the handler, not of any rule: whatever asks for a full
// redaction, the answer is the same string.
func TestWithRedactedValueIsInstanceWide(t *testing.T) {
	cases := []struct {
		name string
		opt  cloak.Options
		attr slog.Attr
	}{
		{"key rule", cloak.WithKey(cloak.Redact, "password"), slog.String("password", "x")},
		{"type rule", nil, slog.Any("v", redactedType("x"))},
		{"pattern rule", cloak.WithKeyRegex(`^pw$`, cloak.Redact), slog.String("pw", "x")},
		{"substring rule", cloak.WithKeyContains(cloak.Redact, "pw"), slog.String("pw", "x")},
		{"tag rule", nil, slog.Any("v", tagged{Password: "x"})},
		{"preset", nil, slog.String("cpf", "529.982.247-25")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts := []cloak.Options{
				cloak.WithRedactedValue("***"),
				cloak.WithDefaultPIIKeys(),
				cloak.WithDefaultPIIValues(),
				cloak.WithStructScan(),
				cloak.WithType[redactedType](),
				cloak.WithTag("cloak", "secret", cloak.Redact),
				cloak.WithMessageScan(),
			}
			if tc.opt != nil {
				opts = append(opts, tc.opt)
			}
			got := logWithOpts(opts, tc.attr)
			if !strings.Contains(got, "***") {
				t.Errorf("expected the custom message: %s", got)
			}
			if strings.Contains(got, cloak.Placeholder) {
				t.Errorf("the default message leaked through: %s", got)
			}
		})
	}
}

// Order must not matter, which is the reason the message is resolved after every
// option rather than when a rule is registered.
func TestWithRedactedValueIsOrderIndependent(t *testing.T) {
	before := logWithOpts([]cloak.Options{
		cloak.WithRedactedValue("***"), cloak.WithKey(cloak.Redact, "password"),
	}, slog.String("password", "x"))
	after := logWithOpts([]cloak.Options{
		cloak.WithKey(cloak.Redact, "password"), cloak.WithRedactedValue("***"),
	}, slog.String("password", "x"))

	if before != after {
		t.Fatalf("order changed the result:\n before: %s\n after:  %s", before, after)
	}
	if !strings.Contains(before, "***") {
		t.Fatalf("expected the custom message: %s", before)
	}
}

// A partial masker states its own output, so it must not be rewritten.
func TestRedactedValueLeavesPartialMaskersAlone(t *testing.T) {
	got := logWithOpts([]cloak.Options{
		cloak.WithRedactedValue("***"),
		cloak.WithKey(cloak.KeepLast(4), "card"),
	}, slog.String("card", "4111111111111111"))

	// The masked output is asterisks, so assert on the kept digits: a custom
	// redacted message would replace the whole value and leave none.
	if !strings.Contains(got, "1111") {
		t.Errorf("KeepLast must keep its own output: %s", got)
	}
	if strings.Contains(got, "4111") {
		t.Errorf("KeepLast(4) must hide the leading digits: %s", got)
	}
}

// WithContain is a value rule and answers with the same message.
func TestWithRedactedValueAppliesToContain(t *testing.T) {
	got := logWithOpts([]cloak.Options{
		cloak.WithRedactedValue("***"), cloak.WithContain("s3cr3t"),
	}, slog.String("note", "value s3cr3t here"))

	if strings.Contains(got, "***") == false {
		t.Errorf("expected the custom message: %s", got)
	}
	if strings.Contains(got, cloak.Placeholder) {
		t.Errorf("the default message leaked through: %s", got)
	}
}

// The default is unchanged when nothing says otherwise.
func TestDefaultPlaceholderUnchanged(t *testing.T) {
	got := logWithOpts([]cloak.Options{cloak.WithDefaultPII()},
		slog.String("password", "x"))
	if !strings.Contains(got, cloak.Placeholder) {
		t.Errorf("expected %s by default: %s", cloak.Placeholder, got)
	}
}

// A masked value is still masked under a custom message: the point is that the type is
// never disclosed either way.
func TestRedactedValueDisclosesNothing(t *testing.T) {
	got := logWithOpts([]cloak.Options{
		cloak.WithRedactedValue(""), cloak.WithDefaultPII(),
	}, slog.String("password", "x"))

	if !strings.Contains(got, "password=") {
		t.Fatalf("the key should remain: %s", got)
	}
	if strings.Contains(got, "x") && !strings.Contains(got, `password= x`) {
		// The value is empty, which is the documented behaviour of an empty message.
		if !strings.HasSuffix(strings.TrimSpace(got), "password=") {
			t.Fatalf("expected an empty value: %s", got)
		}
	}
}

// JoinOptions is the json/v2 shape: a set of options as one storable value.
func TestJoinOptionsComposes(t *testing.T) {
	got := logWithOpts([]cloak.Options{
		cloak.JoinOptions(cloak.WithDefaultPIIKeys(), cloak.WithMapScan()),
	}, slog.Any("m", map[string]string{"password": "x"}))

	if strings.Contains(got, "x") {
		t.Errorf("joined options did not apply: %s", got)
	}
}

// A joined value behaves exactly like the options it contains, in the same order.
func TestJoinOptionsMatchesItsParts(t *testing.T) {
	one := logWithOpts([]cloak.Options{cloak.WithDefaultPII()}, slog.String("email", "a@b.com"))
	two := logWithOpts([]cloak.Options{
		cloak.JoinOptions(cloak.WithDefaultPII()),
	}, slog.String("email", "a@b.com"))

	if stripTime(one) != stripTime(two) {
		t.Fatalf("joined differs from the parts:\n parts: %s\n joined: %s",
			stripTime(one), stripTime(two))
	}
}

// Joining flattens, so a joined value nested in another join is still one option.
func TestJoinOptionsIsAssociative(t *testing.T) {
	a := cloak.WithKey(cloak.Redact, "password")
	b := cloak.WithKey(cloak.KeepLast(2), "card")
	c := cloak.WithKey(cloak.KeepFirst(1), "name")

	flat := logWithOpts([]cloak.Options{cloak.JoinOptions(a, b, c)},
		slog.String("password", "hunter2"), slog.String("card", "abcdef"), slog.String("name", "abcdef"))
	nested := logWithOpts([]cloak.Options{
		cloak.JoinOptions(cloak.JoinOptions(a, b), cloak.JoinOptions(c)),
	}, slog.String("password", "hunter2"), slog.String("card", "abcdef"), slog.String("name", "abcdef"))

	if stripTime(flat) != stripTime(nested) {
		t.Fatalf("nesting changed the result:\n flat:    %s\n nested: %s",
			stripTime(flat), stripTime(nested))
	}
}

func TestJoinOptionsEmpty(t *testing.T) {
	got := logWithOpts([]cloak.Options{cloak.JoinOptions()}, slog.String("k", "v"))
	if !strings.Contains(got, "k=v") {
		t.Fatalf("an empty join should change nothing: %s", got)
	}
}

type redactedType string

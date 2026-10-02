package cloak_test

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/lrweck/cloak"
)

type (
	emailAddr string
	password  string
	apiToken  string
)

func logAny(opts []cloak.Options, attr slog.Attr) string {
	var b bytes.Buffer
	logger := slog.New(cloak.New(slog.NewTextHandler(&b, nil), opts...))
	logger.Info("m", attr)
	return b.String()
}

func TestTypeMasksAttribute(t *testing.T) {
	got := logAny([]cloak.Options{cloak.WithType[emailAddr]()},
		slog.Any("mail", emailAddr("john@example.com")))
	if strings.Contains(got, "john@example.com") {
		t.Errorf("typed value leaked: %s", got)
	}
	if !strings.Contains(got, "[REDACTED]") {
		t.Errorf("expected redaction: %s", got)
	}
}

// A named string type is not KindString to slog, so the value detectors cannot see it.
// That is exactly why a type rule is worth having.
func TestTypeReachesWhatDetectorsCannot(t *testing.T) {
	got := logAny([]cloak.Options{
		cloak.WithDefaultPIIValues(),
		cloak.WithType[emailAddr](),
	}, slog.Any("mail", emailAddr("john@example.com")))

	if strings.Contains(got, "john@example.com") {
		t.Fatalf("leaked: %s", got)
	}
}

// An ordinary string of the same content is left alone: the rule is about the type.
func TestTypeDoesNotMatchPlainString(t *testing.T) {
	got := logAny([]cloak.Options{cloak.WithType[emailAddr]()},
		slog.String("note", "john@example.com"))
	if !strings.Contains(got, "john@example.com") {
		t.Fatalf("a plain string must survive: %s", got)
	}
}

func TestTypeCustomMasker(t *testing.T) {
	got := logAny([]cloak.Options{cloak.WithType[password](cloak.KeepFirst(2))},
		slog.Any("pw", password("hunter2")))
	if !strings.Contains(got, "hu*****") {
		t.Errorf("expected KeepFirst(2): %s", got)
	}
}

// Types reach inside structs, slices and maps, without needing a composite option for
// the container itself: the field is matched on its own type.
func TestTypeInsideStruct(t *testing.T) {
	type creds struct {
		User  string
		Token apiToken
	}
	var b bytes.Buffer
	logger := slog.New(cloak.New(slog.NewTextHandler(&b, nil),
		cloak.WithStructScan(), cloak.WithType[apiToken]()))
	logger.Info("m", "c", creds{User: "jane", Token: "abc123"})

	got := b.String()
	if strings.Contains(got, "abc123") {
		t.Errorf("typed struct field leaked: %s", got)
	}
	if !strings.Contains(got, "jane") {
		t.Errorf("sibling must survive: %s", got)
	}
}

func TestTypeInsideSliceAndMap(t *testing.T) {
	var b bytes.Buffer
	logger := slog.New(cloak.New(slog.NewTextHandler(&b, nil),
		cloak.WithCompositeScan(), cloak.WithType[apiToken]()))
	logger.Info("m", "s", []apiToken{"abc123", "def456"})
	logger.Info("m", "mp", map[string]apiToken{"k": "ghi789"})

	got := b.String()
	for _, leaked := range []string{"abc123", "def456", "ghi789"} {
		if strings.Contains(got, leaked) {
			t.Errorf("leaked %q: %s", leaked, got)
		}
	}
}

// An explicit key rule is more specific, so it wins.
func TestTypePrecedenceAgainstKeyRule(t *testing.T) {
	got := logAny([]cloak.Options{
		cloak.WithType[password](),
		cloak.WithKeys(cloak.KeepLast(2), "pw"),
	}, slog.Any("pw", password("hunter2")))
	if !strings.Contains(got, "***r2") {
		t.Errorf("key rule must win over a type rule: %s", got)
	}
}

// A LogValuer is resolved before its type is checked, so the type that gets masked is
// the one that would have been logged.
func TestTypeResolvesLogValuerFirst(t *testing.T) {
	got := logAny([]cloak.Options{cloak.WithType[secret]()},
		slog.Any("v", typedLogValuer{secret("hunter2")}))
	if strings.Contains(got, "hunter2") {
		t.Errorf("LogValue output leaked: %s", got)
	}
}

type secret string

type typedLogValuer struct{ v secret }

func (t typedLogValuer) LogValue() slog.Value { return slog.AnyValue(t.v) }

// Registering a type twice keeps the last rule, matching WithKeys.
func TestTypeLastRuleWins(t *testing.T) {
	got := logAny([]cloak.Options{
		cloak.WithType[password](),
		cloak.WithType[password](cloak.KeepFirst(2)),
	}, slog.Any("pw", password("hunter2")))
	if !strings.Contains(got, "hu*****") {
		t.Errorf("expected the last rule to win: %s", got)
	}
}

// No type rules configured means the type means nothing. The attribute name is
// deliberately outside the default key list so only the type rule could mask it.
func TestTypeUnconfiguredIsInert(t *testing.T) {
	got := logAny([]cloak.Options{cloak.WithDefaultPII()},
		slog.Any("note", emailAddr("keep-me@example.com")))
	if !strings.Contains(got, "keep-me@example.com") {
		t.Fatalf("an unregistered type must survive: %s", got)
	}
}

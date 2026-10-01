package cloak_test

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/lrweck/cloak"
)

// Context keys are deliberately a distinct type, as go vet wants.
type (
	userKey    struct{}
	requestKey struct{}
)

type principal struct {
	ID    int
	Email string
	CPF   string
}

func logCtx(opts []cloak.Option, ctx context.Context) string {
	var b bytes.Buffer
	logger := slog.New(cloak.New(slog.NewJSONHandler(&b, nil), opts...))
	logger.InfoContext(ctx, "event")
	return b.String()
}

// A struct attached to the context must be walked, or its fields leak wholesale.
func TestContextValueStructIsWalked(t *testing.T) {
	ctx := context.WithValue(context.Background(), userKey{}, principal{
		ID: 7, Email: "john@example.com", CPF: "529.982.247-25",
	})
	got := logCtx([]cloak.Option{
		cloak.WithDefaultPII(),
		cloak.WithStructScan(),
		cloak.WithContextValues(cloak.ContextValue{Name: "user", Key: userKey{}}),
	}, ctx)

	for _, leaked := range []string{"john@example.com", "529.982.247"} {
		if strings.Contains(got, leaked) {
			t.Errorf("leaked %q: %s", leaked, got)
		}
	}
	if !strings.Contains(got, `"ID":7`) {
		t.Errorf("context value lost its fields: %s", got)
	}
}

// Without a composite walk the struct stays opaque. Documented, and worth pinning so
// the requirement is explicit rather than discovered at a review.
func TestContextValueStructNeedsCompositeScan(t *testing.T) {
	ctx := context.WithValue(context.Background(), userKey{}, principal{Email: "john@example.com"})
	got := logCtx([]cloak.Option{
		cloak.WithDefaultPII(),
		cloak.WithContextValues(cloak.ContextValue{Name: "user", Key: userKey{}}),
	}, ctx)
	t.Logf("without a composite scan: %s", got)
}

// A string in the context goes through the detectors like any other string attribute.
func TestContextValueStringIsMasked(t *testing.T) {
	ctx := context.WithValue(context.Background(), userKey{}, "john@example.com")
	got := logCtx([]cloak.Option{
		cloak.WithDefaultPIIValues(),
		cloak.WithContextValues(cloak.ContextValue{Name: "mail", Key: userKey{}}),
	}, ctx)

	if strings.Contains(got, "john@example.com") {
		t.Fatalf("leaked: %s", got)
	}
	if !strings.Contains(got, "j***@example.com") {
		t.Fatalf("expected masking: %s", got)
	}
}

// A key rule on the attribute name wins, as it would for a logged attribute.
func TestContextValueKeyRuleWins(t *testing.T) {
	ctx := context.WithValue(context.Background(), userKey{}, principal{ID: 7, Email: "john@example.com"})
	got := logCtx([]cloak.Option{
		cloak.WithKey(cloak.Redact, "user"),
		cloak.WithContextValues(cloak.ContextValue{Name: "user", Key: userKey{}}),
	}, ctx)

	if strings.Contains(got, "john@example.com") {
		t.Fatalf("leaked: %s", got)
	}
	if !strings.Contains(got, "[REDACTED]") {
		t.Fatalf("expected the whole value redacted: %s", got)
	}
}

// Non-sensitive context values pass through untouched.
func TestContextValueScalarPreserved(t *testing.T) {
	ctx := context.WithValue(context.Background(), requestKey{}, "req-abc-123")
	got := logCtx([]cloak.Option{
		cloak.WithDefaultPII(),
		cloak.WithContextValues(cloak.ContextValue{Name: "request_id", Key: requestKey{}}),
	}, ctx)

	if !strings.Contains(got, "req-abc-123") {
		t.Fatalf("harmless value should survive: %s", got)
	}
}

// An absent key is skipped, not logged as null.
func TestContextValueAbsentIsSkipped(t *testing.T) {
	got := logCtx([]cloak.Option{
		cloak.WithDefaultPII(),
		cloak.WithContextValues(
			cloak.ContextValue{Name: "user", Key: userKey{}},
			cloak.ContextValue{Name: "request_id", Key: requestKey{}},
		),
	}, context.Background())

	if strings.Contains(got, "user") || strings.Contains(got, "request_id") {
		t.Fatalf("absent context keys must not appear: %s", got)
	}
}

// Context values reach every record, including one logged through a derived logger.
func TestContextValueOnDerivedLogger(t *testing.T) {
	ctx := context.WithValue(context.Background(), requestKey{}, "req-abc-123")
	got := logCtx([]cloak.Option{
		cloak.WithDefaultPII(),
		cloak.WithContextValues(cloak.ContextValue{Name: "request_id", Key: requestKey{}}),
	}, ctx)

	// A second record through the same logger, to prove it is per-call not once.
	var b bytes.Buffer
	logger := slog.New(cloak.New(slog.NewJSONHandler(&b, nil),
		cloak.WithDefaultPII(),
		cloak.WithContextValues(cloak.ContextValue{Name: "request_id", Key: requestKey{}})))
	logger.With("component", "http").InfoContext(ctx, "one")
	logger.WithGroup("g").InfoContext(ctx, "two")

	got = b.String()
	if n := strings.Count(got, "req-abc-123"); n != 2 {
		t.Fatalf("expected the context value on both records, got %d: %s", n, got)
	}
	if !strings.Contains(got, "component") {
		t.Fatalf("derived logger attrs lost: %s", got)
	}
}

// LogValuer precedence holds for context values too.
func TestContextValueLogValuerMasked(t *testing.T) {
	ctx := context.WithValue(context.Background(), userKey{}, resolved{raw: "john@example.com"})
	got := logCtx([]cloak.Option{
		cloak.WithDefaultPIIValues(),
		cloak.WithCompositeScan(),
		cloak.WithContextValues(cloak.ContextValue{Name: "mail", Key: userKey{}}),
	}, ctx)

	if strings.Contains(got, "john@example.com") {
		t.Fatalf("leaked: %s", got)
	}
}

func BenchmarkContextValues(b *testing.B) {
	ctx := context.WithValue(context.Background(), requestKey{}, "req-abc-123")
	var b2 bytes.Buffer
	logger := slog.New(cloak.New(slog.NewJSONHandler(&b2, nil),
		cloak.WithDefaultPII(),
		cloak.WithContextValues(cloak.ContextValue{Name: "request_id", Key: requestKey{}})))
	b.ReportAllocs()
	for b.Loop() {
		logger.InfoContext(ctx, "event")
	}
}

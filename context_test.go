package cloak_test

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/lrweck/cloak"
)

// The idiomatic context key is an unexported type. These tests live in package
// cloak_test precisely so that naming it here would not compile — which is the point:
// the pull function is defined where the key is reachable, and the key never escapes.
type (
	userKey    struct{}
	requestKey struct{}
	absentKey  struct{}
)

type principal struct {
	ID    int
	Email string
	CPF   string
}

func withUser(ctx context.Context, p principal) context.Context {
	return context.WithValue(ctx, userKey{}, p)
}

// This is what an application package would export: the extractor, not the key.
func userAttrs(ctx context.Context) []slog.Attr {
	u, ok := ctx.Value(userKey{}).(principal)
	if !ok {
		return nil
	}
	return []slog.Attr{slog.Any("user", u)}
}

func requestAttrs(ctx context.Context) []slog.Attr {
	id, ok := ctx.Value(requestKey{}).(string)
	if !ok {
		return nil
	}
	return []slog.Attr{slog.String("request_id", id)}
}

// Two pull functions, one option.
func requestAndUserAttrs(ctx context.Context) []slog.Attr {
	return append(requestAttrs(ctx), userAttrs(ctx)...)
}

func logCtx(opts []cloak.Options, ctx context.Context) string {
	var b bytes.Buffer
	logger := slog.New(cloak.New(slog.NewJSONHandler(&b, nil), opts...))
	logger.InfoContext(ctx, "event")
	return b.String()
}

// A struct attached to the context must be walked, or its fields leak wholesale.
func TestContextStructIsWalked(t *testing.T) {
	ctx := withUser(context.Background(), principal{ID: 7, Email: "john@example.com", CPF: "529.982.247-25"})
	got := logCtx([]cloak.Options{
		cloak.WithDefaultPII(),
		cloak.WithStructScan(),
		cloak.WithContextAttrs(userAttrs),
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

// Without a composite walk the struct stays opaque. Pinned so the requirement is
// explicit rather than discovered at a review.
func TestContextStructNeedsCompositeScan(t *testing.T) {
	ctx := withUser(context.Background(), principal{Email: "john@example.com"})
	got := logCtx([]cloak.Options{
		cloak.WithDefaultPII(),
		cloak.WithContextAttrs(userAttrs),
	}, ctx)
	t.Logf("without a composite scan: %s", got)
}

// mailAttrs reads a plain string out of the context, the other common shape.
func mailAttrs(ctx context.Context) []slog.Attr {
	mail, ok := ctx.Value(userKey{}).(string)
	if !ok {
		return nil
	}
	return []slog.Attr{slog.String("mail", mail)}
}

func TestContextStringIsMasked(t *testing.T) {
	ctx := context.WithValue(context.Background(), userKey{}, "john@example.com")
	got := logCtx([]cloak.Options{
		cloak.WithDefaultPIIValues(),
		cloak.WithContextAttrs(mailAttrs),
	}, ctx)

	if strings.Contains(got, "john@example.com") {
		t.Fatalf("leaked: %s", got)
	}
	if !strings.Contains(got, "j***@example.com") {
		t.Fatalf("expected masking: %s", got)
	}
}

// A key rule on the attribute name wins, as it would for a logged attribute.
func TestContextKeyRuleWins(t *testing.T) {
	ctx := withUser(context.Background(), principal{ID: 7, Email: "john@example.com"})
	got := logCtx([]cloak.Options{
		cloak.WithKey(cloak.Redact, "user"),
		cloak.WithContextAttrs(userAttrs),
	}, ctx)

	if strings.Contains(got, "john@example.com") {
		t.Fatalf("leaked: %s", got)
	}
	if !strings.Contains(got, "[REDACTED]") {
		t.Fatalf("expected the whole value redacted: %s", got)
	}
}

func TestContextScalarPreserved(t *testing.T) {
	ctx := context.WithValue(context.Background(), requestKey{}, "req-abc-123")
	got := logCtx([]cloak.Options{
		cloak.WithDefaultPII(),
		cloak.WithContextAttrs(requestAttrs),
	}, ctx)

	if !strings.Contains(got, "req-abc-123") {
		t.Fatalf("harmless value should survive: %s", got)
	}
}

// A pull that returns nil must not contribute anything at all.
func TestContextAbsentIsSkipped(t *testing.T) {
	got := logCtx([]cloak.Options{
		cloak.WithDefaultPII(),
		cloak.WithContextAttrs(requestAndUserAttrs, func(context.Context) []slog.Attr { return nil }),
	}, context.WithValue(context.Background(), absentKey{}, "x"))

	if strings.Contains(got, "request_id") || strings.Contains(got, "user") {
		t.Fatalf("absent context values must not appear: %s", got)
	}
}

// Several pulls in one option, and several options.
func TestContextMultiplePulls(t *testing.T) {
	ctx := context.WithValue(withUser(context.Background(), principal{ID: 7, Email: "john@example.com"}),
		requestKey{}, "req-abc-123")
	got := logCtx([]cloak.Options{
		cloak.WithDefaultPII(),
		cloak.WithStructScan(),
		cloak.WithContextAttrs(requestAttrs, userAttrs),
	}, ctx)

	if strings.Contains(got, "john@example.com") {
		t.Fatalf("leaked: %s", got)
	}
	for _, want := range []string{"req-abc-123", `"ID":7`, "[REDACTED]"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q: %s", want, got)
		}
	}
}

// The pull runs per record, not once at construction.
func TestContextRunsPerRecord(t *testing.T) {
	ctx := context.WithValue(context.Background(), requestKey{}, "req-abc-123")
	var b bytes.Buffer
	logger := slog.New(cloak.New(slog.NewJSONHandler(&b, nil),
		cloak.WithDefaultPII(), cloak.WithContextAttrs(requestAttrs)))
	logger.With("component", "http").InfoContext(ctx, "one")
	logger.WithGroup("g").InfoContext(ctx, "two")

	got := b.String()
	if n := strings.Count(got, "req-abc-123"); n != 2 {
		t.Fatalf("expected the value on both records, got %d: %s", n, got)
	}
	if !strings.Contains(got, "component") {
		t.Fatalf("derived logger attrs lost: %s", got)
	}
}

// A pull may compute a value rather than read one.
func TestContextComputedValue(t *testing.T) {
	got := logCtx([]cloak.Options{
		cloak.WithDefaultPII(),
		cloak.WithContextAttrs(func(ctx context.Context) []slog.Attr {
			if ctx.Value(requestKey{}) == nil {
				return nil
			}
			return []slog.Attr{slog.String("account", "acc_1234567890")}
		}),
	}, context.WithValue(context.Background(), requestKey{}, "req-1"))

	if strings.Contains(got, "1234567890") {
		t.Fatalf("leaked: %s", got)
	}
}

// LogValuer precedence holds for pulled values too.
func TestContextLogValuerMasked(t *testing.T) {
	ctx := context.WithValue(context.Background(), userKey{}, resolved{raw: "john@example.com"})
	got := logCtx([]cloak.Options{
		cloak.WithDefaultPIIValues(),
		cloak.WithCompositeScan(),
		cloak.WithContextAttrs(userAttrs),
	}, ctx)

	if strings.Contains(got, "john@example.com") {
		t.Fatalf("leaked: %s", got)
	}
}

// WithSkipValueScan applies to pulled values, so a payload you keep verbatim can be
// pulled without being rewritten.
func TestContextSkipValueScan(t *testing.T) {
	ctx := context.WithValue(context.Background(), requestKey{}, "john@example.com")
	got := logCtx([]cloak.Options{
		cloak.WithDefaultPIIValues(),
		cloak.WithSkipValueScan("request_id"),
		cloak.WithContextAttrs(requestAttrs),
	}, ctx)

	if !strings.Contains(got, "john@example.com") {
		t.Fatalf("skip should have been honoured: %s", got)
	}
}

func BenchmarkContextAttrs(b *testing.B) {
	ctx := context.WithValue(context.Background(), requestKey{}, "req-abc-123")
	var buf bytes.Buffer
	logger := slog.New(cloak.New(slog.NewJSONHandler(&buf, nil),
		cloak.WithDefaultPII(), cloak.WithContextAttrs(requestAttrs)))
	b.ReportAllocs()
	for b.Loop() {
		logger.InfoContext(ctx, "event")
	}
}

func BenchmarkContextAttrsDisabled(b *testing.B) {
	var buf bytes.Buffer
	logger := slog.New(cloak.New(slog.NewJSONHandler(&buf, nil), cloak.WithDefaultPII()))
	b.ReportAllocs()
	for b.Loop() {
		logger.InfoContext(context.Background(), "event")
	}
}

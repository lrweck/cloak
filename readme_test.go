package cloak_test

import (
	"bytes"
	"context"
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

// The README shows a LogValuer keeping its own identity and still being masked.
type readmeEmail string

func (readmeEmail) LogValue() slog.Value { return slog.StringValue("john@example.com") }

func TestReadmeLogValuerPrecedence(t *testing.T) {
	var b bytes.Buffer
	logger := slog.New(cloak.New(slog.NewTextHandler(&b, nil),
		cloak.WithDefaultPIIValues(), cloak.WithCompositeScan()))
	logger.Info("m", "mail", readmeEmail("x"))

	got := b.String()
	if strings.Contains(got, "john@example.com") {
		t.Fatalf("LogValue output leaked: %s", got)
	}
	if !strings.Contains(got, "j***@example.com") {
		t.Fatalf("expected the LogValue output to be masked: %s", got)
	}
}

// The README claims reflection never runs without a composite option.
func TestReadmeCompositeOptionsAreOptIn(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts []cloak.Option
		val  any
	}{
		{"struct", []cloak.Option{cloak.WithStructScan()}, readmeAccount{Email: "john@example.com"}},
		{"map", []cloak.Option{cloak.WithMapScan()}, map[string]any{"contact": "john@example.com"}},
		{"slice", []cloak.Option{cloak.WithSliceScan()}, []string{"john@example.com"}},
		{"composite", []cloak.Option{cloak.WithCompositeScan()}, readmeAccount{Email: "john@example.com"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var b bytes.Buffer
			logger := slog.New(cloak.New(slog.NewTextHandler(&b, nil),
				append([]cloak.Option{cloak.WithDefaultPII()}, tc.opts...)...))
			logger.Info("m", "v", tc.val)
			if strings.Contains(b.String(), "john@example.com") {
				t.Fatalf("%s should have masked its shape: %s", tc.name, b.String())
			}
		})
	}
}

type readmeAccount struct {
	ID    int
	Email string
}

func TestReadmeCompositeScopeIsIndependent(t *testing.T) {
	// WithStructScan alone must not touch a slice.
	var b bytes.Buffer
	logger := slog.New(cloak.New(slog.NewTextHandler(&b, nil),
		cloak.WithDefaultPII(), cloak.WithStructScan()))
	logger.Info("m", "emails", []string{"john@example.com"})
	if !strings.Contains(b.String(), "john@example.com") {
		t.Fatal("slice should be out of scope for WithStructScan")
	}
}

// The README claims a context-declared value is masked at every call site.
type readmeUserKey struct{}

type readmePrincipal struct {
	ID    int
	Email string
}

// The README's pull function, defined where the unexported key is reachable.
func readmeUserAttrs(ctx context.Context) []slog.Attr {
	u, ok := ctx.Value(readmeUserKey{}).(readmePrincipal)
	if !ok {
		return nil
	}
	return []slog.Attr{slog.Any("user", u)}
}

func TestReadmeContextAttrs(t *testing.T) {
	ctx := context.WithValue(context.Background(), readmeUserKey{},
		readmePrincipal{ID: 7, Email: "john@example.com"})

	var b bytes.Buffer
	logger := slog.New(cloak.New(slog.NewJSONHandler(&b, nil),
		cloak.WithDefaultPII(),
		cloak.WithStructScan(),
		cloak.WithContextAttrs(readmeUserAttrs),
	))
	logger.InfoContext(ctx, "checkout started")

	got := b.String()
	if strings.Contains(got, "john@example.com") {
		t.Fatalf("context value leaked: %s", got)
	}
	if !strings.Contains(got, "[REDACTED]") {
		t.Fatalf("expected masking: %s", got)
	}
	if !strings.Contains(got, `"ID":7`) {
		t.Fatalf("expected the harmless field to survive: %s", got)
	}
}

func TestReadmeMainExampleCompiles(t *testing.T) {
	// Matches the README "Usage" block, writing to a buffer instead of stdout.
	var out bytes.Buffer
	handler := cloak.New(
		slog.NewJSONHandler(&out, nil),
		cloak.WithDefaultPII(),
		cloak.WithMessageScan(),
		cloak.WithCompositeScan(),
	)
	slog.New(handler).Info("user john@example.com logged in", "customer", struct{ Email string }{Email: "a@b.com"})
	t.Logf("full preset: %s", strings.TrimSpace(out.String()))
	if strings.Contains(out.String(), "john@example.com") || strings.Contains(out.String(), "a@b.com") {
		t.Fatalf("leak under the full preset: %s", out.String())
	}
}

// The README claims a type rule masks a value wherever it appears.
func TestReadmeWithType(t *testing.T) {
	type Password string
	type Login struct {
		User     string
		Password Password
	}
	var b bytes.Buffer
	logger := slog.New(cloak.New(slog.NewJSONHandler(&b, nil),
		cloak.WithType[Password]()))
	logger.Info("login", slog.String("user", "jane"), slog.Any("password", Password("hunter2")))

	got := b.String()
	if strings.Contains(got, "hunter2") {
		t.Fatalf("typed value leaked: %s", got)
	}
	if !strings.Contains(got, "jane") {
		t.Fatalf("sibling must survive: %s", got)
	}
}

// The README claims WithTag masks by struct tag.
func TestReadmeWithTag(t *testing.T) {
	type Account struct {
		ID       int
		Password string `cloak:"secret"`
	}
	var b bytes.Buffer
	logger := slog.New(cloak.New(slog.NewTextHandler(&b, nil),
		cloak.WithStructScan(), cloak.WithTag("cloak", "secret", cloak.Redact)))
	logger.Info("m", "a", Account{ID: 7, Password: "hunter2"})

	got := b.String()
	if strings.Contains(got, "hunter2") {
		t.Fatalf("tagged field leaked: %s", got)
	}
}

// The README claims WithContain masks a known secret anywhere, including a URL.
func TestReadmeWithContain(t *testing.T) {
	var b bytes.Buffer
	logger := slog.New(cloak.New(slog.NewTextHandler(&b, nil),
		cloak.WithContain("sk_live_51H8xQ2")))
	logger.Info("m", "request_url", "https://api.example.com/v1/sk_live_51H8xQ2/charge")

	if strings.Contains(b.String(), "sk_live_51H8xQ2") {
		t.Fatalf("secret leaked: %s", b.String())
	}
}

// The README claims unexported fields do not reach a TextHandler.
func TestReadmeUnexportedDropped(t *testing.T) {
	type acct struct {
		ID       int
		password string
	}
	var b bytes.Buffer
	logger := slog.New(cloak.New(slog.NewTextHandler(&b, nil), cloak.WithStructScan()))
	logger.Info("m", "a", acct{ID: 7, password: "hunter2"})

	got := b.String()
	if strings.Contains(got, "hunter2") {
		t.Fatalf("unexported field leaked: %s", got)
	}
	if !strings.Contains(got, "ID:7") {
		t.Fatalf("exported field must survive: %s", got)
	}
}

// The README claims each compliance preset does what it says, and no more.
func TestReadmeCompliancePresets(t *testing.T) {
	var b bytes.Buffer
	pci := slog.New(cloak.New(slog.NewTextHandler(&b, nil), cloak.WithPCI()))
	pci.Info("m", "pan", "4111111111111111", "amount", 1299)
	got := b.String()
	if strings.Contains(got, "4111111111111111") {
		t.Errorf("PCI preset leaked a PAN: %s", got)
	}
	if !strings.Contains(got, "1299") {
		t.Errorf("PCI preset must keep non-cardholder data: %s", got)
	}

	b.Reset()
	gdpr := slog.New(cloak.New(slog.NewTextHandler(&b, nil), cloak.WithLGPD()))
	gdpr.Info("m", "email", "john@example.com", "country", "Brazil")
	got = b.String()
	if strings.Contains(got, "john@example.com") {
		t.Errorf("LGPD preset leaked an email: %s", got)
	}
	if !strings.Contains(got, "Brazil") {
		t.Errorf("LGPD preset must keep country: %s", got)
	}
}

// The README claims an anchor works, which a substring match cannot express.
func TestReadmeKeyRegex(t *testing.T) {
	var b bytes.Buffer
	logger := slog.New(cloak.New(slog.NewTextHandler(&b, nil),
		cloak.WithKeyRegex(`_key$`, cloak.Redact),
		cloak.WithKeyRegex(`^x-.*-token$`, cloak.Redact)))
	logger.Info("m",
		"api_key", "sk-123",
		"x-auth-token", "t-1",
		"key_id", "k-1",
		"x-api-key", "k-2",
	)

	got := b.String()
	if strings.Contains(got, "sk-123") || strings.Contains(got, "t-1") {
		t.Fatalf("pattern did not match: %s", got)
	}
	for _, want := range []string{"k-1", "k-2"} {
		if !strings.Contains(got, want) {
			t.Errorf("expected %q to survive: %s", want, got)
		}
	}
}

// The README claims each constructor is usable on its own.
func TestReadmeConstructors(t *testing.T) {
	cases := []struct {
		name   string
		build  func(slog.Handler, ...cloak.Option) slog.Handler
		attr   slog.Attr
		leaked string
	}{
		{"PCI", cloak.NewPCI, slog.String("pan", "4111111111111111"), "4111111111111111"},
		{"GDPR", cloak.NewGDPR, slog.String("email", "a@b.com"), "a@b.com"},
		{"LGPD", cloak.NewLGPD, slog.String("email", "a@b.com"), "a@b.com"},
		{"DefaultPII", cloak.NewDefaultPII, slog.String("email", "a@b.com"), "a@b.com"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var b bytes.Buffer
			slog.New(tc.build(slog.NewTextHandler(&b, nil))).Info("m", tc.attr)
			if strings.Contains(b.String(), tc.leaked) {
				t.Fatalf("%s constructor leaked: %s", tc.name, b.String())
			}
		})
	}
}

// The README claims a value rule reaches kinds the detectors cannot see.
func TestReadmeValueRule(t *testing.T) {
	var b bytes.Buffer
	logger := slog.New(cloak.New(slog.NewTextHandler(&b, nil),
		cloak.WithValuePredicate(
			func(v slog.Value) bool {
				return v.Kind() == slog.KindInt64 && v.Int64() > 1_000_000_000_000
			},
			cloak.Redact,
		),
	))
	logger.Info("m", "latency_ns", int64(5_000_000_000_000), "amount", 1299)

	got := b.String()
	if strings.Contains(got, "5000000000000") {
		t.Fatalf("large int leaked: %s", got)
	}
	if !strings.Contains(got, "1299") {
		t.Fatalf("small int must survive: %s", got)
	}
}

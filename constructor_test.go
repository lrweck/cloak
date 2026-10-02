package cloak_test

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/lrweck/cloak"
)

// A constructor must be exactly its option followed by nothing, so that a caller can
// override any part of the preset.

// stripTime drops the record timestamp. It exists because the timestamp is the one part
// of a log record that is different every call, so any test comparing records byte for
// byte, or asserting that a short numeric string is absent, is at the mercy of the clock.
// The nanoseconds a JSONHandler writes are nine digits, which is long enough to contain
// an accidental needle; this fired about once in twenty-five runs on "cvv" being masked
// and the timestamp happening to read .123.
//
// Both handler formats are handled, since a test may use either.
func stripTime(out string) string {
	if _, rest, ok := strings.Cut(out, "level="); ok {
		return rest
	}
	if _, rest, ok := strings.Cut(out, `,"level":`); ok {
		return rest
	}
	return out
}

func TestConstructorsMatchTheirOptions(t *testing.T) {
	cases := []struct {
		name string
		new  func(slog.Handler, ...cloak.Options) slog.Handler
		opt  cloak.Options
		attr slog.Attr
	}{
		{"PCI", cloak.NewPCI, cloak.WithPCI(), slog.Any("v", map[string]string{"cvv": "123"})},
		{"GDPR", cloak.NewGDPR, cloak.WithGDPR(), slog.Any("v", map[string]string{"email": "a@b.com"})},
		{"LGPD", cloak.NewLGPD, cloak.WithLGPD(), slog.Any("v", map[string]string{"cpf": "529.982.247-25"})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var b slog.Handler
			var viaCtor bytes.Buffer
			var viaOpt bytes.Buffer

			base := slog.NewTextHandler(&viaCtor, nil)
			b = tc.new(base, cloak.WithMapScan())
			slog.New(b).Info("m", tc.attr)

			base2 := slog.NewTextHandler(&viaOpt, nil)
			slog.New(cloak.New(base2, tc.opt, cloak.WithMapScan())).Info("m", tc.attr)

			if got, want := stripTime(viaCtor.String()), stripTime(viaOpt.String()); got != want {
				t.Errorf("constructor differs from the option:\n ctor: %s\n opt:  %s", got, want)
			}
		})
	}
}

func TestNewDefaultPII(t *testing.T) {
	var b bytes.Buffer
	logger := slog.New(cloak.NewDefaultPII(slog.NewTextHandler(&b, nil)))
	logger.Info("m", "email", "a@b.com", "card", "4111111111111111")

	got := b.String()
	for _, leaked := range []string{"a@b.com", "4111111111111111"} {
		if strings.Contains(got, leaked) {
			t.Errorf("leaked %q: %s", leaked, got)
		}
	}
}

// The preset goes in first, so a caller option overrides it. This is the last-wins
// rule the rest of the library follows, and it is what makes the constructors usable
// as a starting point rather than a fixed decision.
func TestCallerOptionOverridesPreset(t *testing.T) {
	var b bytes.Buffer
	logger := slog.New(cloak.NewPCI(slog.NewTextHandler(&b, nil),
		cloak.WithKeys(cloak.KeepLast(4), "card_number")))
	logger.Info("m", "card_number", "4111111111111111")

	got := b.String()
	if !strings.Contains(got, "************1111") {
		t.Fatalf("the caller's rule should win over the preset: %s", got)
	}
}

// A key the preset does not mention is untouched by the override.
func TestCallerOptionAddsToPreset(t *testing.T) {
	var b bytes.Buffer
	logger := slog.New(cloak.NewPCI(slog.NewTextHandler(&b, nil),
		cloak.WithKeys(cloak.KeepLast(4), "card_number")))
	logger.Info("m", "card_number", "4111111111111111", "cvv", "123", "amount", 1299)

	got := stripTime(b.String())
	if !strings.Contains(got, "************1111") {
		t.Errorf("caller rule missing: %s", got)
	}
	if strings.Contains(got, "123") {
		t.Errorf("the preset should still mask cvv: %s", got)
	}
	if !strings.Contains(got, "1299") {
		t.Errorf("the preset should still keep amounts: %s", got)
	}
}

// The constructors must compose with the other opt-in features, not replace them.
func TestConstructorWithCompositeScan(t *testing.T) {
	var b bytes.Buffer
	logger := slog.New(cloak.NewLGPD(slog.NewTextHandler(&b, nil), cloak.WithStructScan()))
	logger.Info("m", "u", struct {
		Email string
		Order string
	}{Email: "john@example.com", Order: "ord_9"})

	got := b.String()
	if strings.Contains(got, "john@example.com") {
		t.Errorf("leaked: %s", got)
	}
	if !strings.Contains(got, "ord_9") {
		t.Errorf("non-personal field must survive: %s", got)
	}
}

func TestConstructorsPassNilThrough(t *testing.T) {
	// A nil handler is the documented way to discard everything.
	slog.New(cloak.NewPCI(nil)).Info("m", "pan", "4111111111111111")
	slog.New(cloak.NewGDPR(nil)).Info("m", "email", "a@b.com")
	slog.New(cloak.NewLGPD(nil)).Info("m", "email", "a@b.com")
	slog.New(cloak.NewDefaultPII(nil)).Info("m", "email", "a@b.com")
}

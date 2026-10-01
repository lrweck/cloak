package cloak_test

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/lrweck/cloak"
)

func logPreset(opts []cloak.Option, args ...any) string {
	var b bytes.Buffer
	logger := slog.New(cloak.New(slog.NewTextHandler(&b, nil), opts...))
	logger.Info("m", args...)
	return b.String()
}

func TestPCIMasksCardholderData(t *testing.T) {
	got := logPreset([]cloak.Option{cloak.WithPCI()},
		"pan", "4111111111111111",
		"cvv", "123",
		"cardholder_name", "Jane Doe",
		"exp_month", "12",
		"track2", "4111111111111111=25121010000000000000",
	)
	for _, leaked := range []string{"4111111111111111", "Jane Doe", "25121010000000000000"} {
		if strings.Contains(got, leaked) {
			t.Errorf("PCI field leaked %q: %s", leaked, got)
		}
	}
}

// A card number under an unexpected field name is still caught, by the detector.
func TestPCIUsesPANDetector(t *testing.T) {
	got := logPreset([]cloak.Option{cloak.WithPCI()},
		"whatever", "4111111111111111")
	if strings.Contains(got, "4111111111111111") {
		t.Errorf("PAN detector did not fire: %s", got)
	}
}

// Fields that describe a transaction but are not cardholder data must survive, or the
// log stops being worth reading.
func TestPCIKeepsNonCardholderData(t *testing.T) {
	got := logPreset([]cloak.Option{cloak.WithPCI()},
		"amount", 1299, "currency", "BRL", "merchant", "ACME", "order_id", "ord_9")
	for _, want := range []string{"1299", "BRL", "ACME", "ord_9"} {
		if !strings.Contains(got, want) {
			t.Errorf("expected %q to survive: %s", want, got)
		}
	}
}

func TestGDPRMasksPersonalData(t *testing.T) {
	got := logPreset([]cloak.Option{cloak.WithGDPR()},
		"email", "john@example.com",
		"date_of_birth", "1985-04-12",
		"passport", "X1234567",
		"iban", "GB82WEST12345698765432",
		"medical_record", "diagnosis-A",
	)
	for _, leaked := range []string{"john@example.com", "1985-04-12", "X1234567", "GB82WEST", "diagnosis-A"} {
		if strings.Contains(got, leaked) {
			t.Errorf("GDPR field leaked %q: %s", leaked, got)
		}
	}
}

// "name" is left out on purpose: masking every name makes logs useless.
func TestGDPRDoesNotMaskNames(t *testing.T) {
	got := logPreset([]cloak.Option{cloak.WithGDPR()},
		"country", "Brazil", "user_id", "u-77")
	for _, want := range []string{"Brazil", "u-77"} {
		if !strings.Contains(got, want) {
			t.Errorf("expected %q to survive: %s", want, got)
		}
	}
}

func TestGDPRUsesValueDetectors(t *testing.T) {
	got := logPreset([]cloak.Option{cloak.WithGDPR()},
		"note", "contact john@example.com about 192.168.1.42")
	if strings.Contains(got, "john@example.com") || strings.Contains(got, "192.168.1.42") {
		t.Errorf("detectors did not fire: %s", got)
	}
}

// The presets compose with the rest of the library rather than replacing it.
func TestPresetComposesWithTypeRules(t *testing.T) {
	type secret string
	got := logPreset([]cloak.Option{
		cloak.WithPCI(), cloak.WithType[secret](),
	}, "m", "k", secret("s3cr3t"), "pan", "4111111111111111")

	for _, leaked := range []string{"s3cr3t", "4111111111111111"} {
		if strings.Contains(got, leaked) {
			t.Errorf("leaked %q: %s", leaked, got)
		}
	}
}

// LGPD is the Brazilian name for the same regulation, so it must behave identically
// rather than drifting into a second list.
func TestLGPDMatchesGDPR(t *testing.T) {
	if len(cloak.LGPDKeys) != len(cloak.GDPRKeys) {
		t.Fatalf("LGPDKeys has %d entries, GDPRKeys has %d", len(cloak.LGPDKeys), len(cloak.GDPRKeys))
	}
	got := logPreset([]cloak.Option{cloak.WithLGPD()},
		"email", "john@example.com", "cpf", "529.982.247-25", "order_id", "ord_9")
	for _, leaked := range []string{"john@example.com", "529.982.247"} {
		if strings.Contains(got, leaked) {
			t.Errorf("LGPD field leaked %q: %s", leaked, got)
		}
	}
	if !strings.Contains(got, "ord_9") {
		t.Errorf("non-personal field must survive: %s", got)
	}
}

// A dotted-quad is nine digits and passes SSN's shape check, so the detectors must run
// IPv4 first or the IP is swallowed. Pinning it per preset, since a hand-written
// detector order reintroduces the bug.
func TestPresetIPv4NotSwallowedBySSN(t *testing.T) {
	for name, opt := range map[string]cloak.Option{
		"PCI": cloak.WithPCI(), "GDPR": cloak.WithGDPR(), "LGPD": cloak.WithLGPD(),
	} {
		t.Run(name, func(t *testing.T) {
			got := logPreset([]cloak.Option{opt}, "note", "from 192.168.1.42")
			if strings.Contains(got, "***-**-") {
				t.Errorf("IP masked as an SSN: %s", got)
			}
		})
	}
}

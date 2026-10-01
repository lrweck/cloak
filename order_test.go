package cloak

import "testing"

var detectors = map[string]ValueFunc{
	"PAN": MaskPAN, "CPF": MaskCPF, "CNPJ": MaskCNPJ, "SSN": MaskSSN,
	"IBAN": MaskIBAN, "Email": MaskEmail, "IPv4": MaskIPv4,
	"UUID": MaskUUID, "Phone": MaskPhone,
}

var samples = map[string]string{
	"PAN":   "4111111111111111",
	"CPF":   "529.982.247-25",
	"CNPJ":  "11.222.333/0001-81",
	"SSN":   "078-05-1120",
	"IBAN":  "GB82WEST12345698765432",
	"Email": "john@example.com",
	"IPv4":  "192.168.1.42",
	"UUID":  "550e8400-e29b-41d4-a716-446655440000",
	"Phone": "+55 11 91234-5678",
}

// Every detector must still claim its own sample after any reordering.
func TestEachDetectorStillFires(t *testing.T) {
	h := New(nil, WithDefaultPIIValues()).(*Handler)
	for name, sample := range samples {
		out, ok := h.maskString(sample)
		if !ok {
			t.Errorf("%s: detector did not fire on %q", name, sample)
			continue
		}
		if out == sample {
			t.Errorf("%s: %q unchanged", name, sample)
		}
		t.Logf("%-6s %-38s -> %s", name, sample, out)
	}
}

// The chain must not turn one format into another: a document must keep its document
// shape, an IP its IP shape.
func TestChainDoesNotCrossFormats(t *testing.T) {
	h := New(nil, WithDefaultPIIValues()).(*Handler)
	cases := []struct{ in, want string }{
		{"192.168.1.42", "192.*.*.*"},
		{"172.16.254.1", "172.*.*.*"},
		{"529.982.247-25", "***.***.***-**"},
		{"11.222.333/0001-81", "**.***.***/****-**"},
		{"078-05-1120", "***-**-****"},
		{"card 4111 1111 1111 1111", "card ****1111"},
	}
	for _, tc := range cases {
		out, _ := h.maskString(tc.in)
		if out != tc.want {
			t.Errorf("maskString(%q) = %q, want %q", tc.in, out, tc.want)
		}
	}
}

// Typical log lines carry no PII; this is the case the ordering optimizes for.
var typical = []string{
	"payment settled",
	"handler took 42ms",
	"cache miss for key user:42",
	"GET /v1/accounts/1089 200",
	"retrying upstream request",
	"connection pool size is 20",
}

func BenchmarkDetectorsTypicalText(b *testing.B) {
	for i, fn := range DefaultPIIValueFuncs() {
		b.Run(nameOf(i), func(b *testing.B) {
			for b.Loop() {
				for _, s := range typical {
					fn(s)
				}
			}
		})
	}
}

func BenchmarkMaskStringTypicalText(b *testing.B) {
	h := New(nil, WithDefaultPIIValues()).(*Handler)
	for b.Loop() {
		for _, s := range typical {
			h.maskString(s)
		}
	}
}

// The detector order is fixed, so index it rather than comparing funcs.
var detectorNames = []string{"UUID", "Email", "IPv4", "IBAN", "CPF", "CNPJ", "SSN", "PAN", "Phone"}

func nameOf(i int) string { return detectorNames[i] }

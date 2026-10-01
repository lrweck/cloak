package redact

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestMaskers(t *testing.T) {
	v := slog.StringValue("abcdef")
	if got := KeepLast(2)(v).String(); got != "****ef" { t.Fatalf("KeepLast: %q", got) }
	if got := KeepFirst(2)(v).String(); got != "ab****" { t.Fatalf("KeepFirst: %q", got) }
	if got := KeepEnds(2, 2)(v).String(); got != "ab**ef" { t.Fatalf("KeepEnds: %q", got) }
	if got := Fixed("X")(v).String(); got != "X" { t.Fatalf("Fixed: %q", got) }
}

func TestDetectors(t *testing.T) {
	cases := []struct {
		name, in, want string
		fn ValueFunc
	}{
		{"pan", "card 4111 1111 1111 1111", "card ****1111", MaskPAN},
		{"cpf", "cpf 529.982.247-25", "cpf ***.***.***-**", MaskCPF},
		{"cnpj", "cnpj 11.222.333/0001-81", "cnpj **.***.***/****-**", MaskCNPJ},
		{"ssn", "ssn 078-05-1120", "ssn ***-**-****", MaskSSN},
		{"email", "mail john.doe@example.com", "mail j***@example.com", MaskEmail},
		{"ipv4", "from 192.168.1.42", "from 192.*.*.*", MaskIPv4},
		{"uuid", "id 550e8400-e29b-41d4-a716-446655440000", "id 550e8400-****-****-****-446655440000", MaskUUID},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := tc.fn(tc.in)
			if !ok || got != tc.want { t.Fatalf("got %q, %v; want %q", got, ok, tc.want) }
		})
	}
	if got, ok := MaskCPF("not a cpf 529.982.247-26"); ok || got != "not a cpf 529.982.247-26" {
		t.Fatalf("invalid CPF matched: %q", got)
	}
}

func TestIBAN(t *testing.T) {
	got, ok := MaskIBAN("IBAN GB82 WEST 1234 5698 7654 32")
	if !ok || !strings.HasPrefix(got, "IBAN GB") { t.Fatalf("IBAN: %q, %v", got, ok) }
	if _, ok := MaskIBAN("GB82WEST12345698765431"); ok { t.Fatal("invalid IBAN matched") }
}

func TestDefaultPII(t *testing.T) {
	var b bytes.Buffer
	logger := slog.New(New(slog.NewTextHandler(&b, nil), WithDefaultPII()))
	logger.Info("test",
		"email", "john@example.com",
		"password", "secret",
		"ACCESS_TOKEN", "token-secret",
		"message", "cpf 529.982.247-25 card 4111 1111 1111 1111",
	)
	got := b.String()
	for _, leaked := range []string{"john@example.com", "secret", "token-secret", "529.982.247-25", "4111 1111 1111 1111"} {
		if strings.Contains(got, leaked) { t.Fatalf("PII leaked %q in %q", leaked, got) }
	}
}

func TestKeyNormalization(t *testing.T) {
	var b bytes.Buffer
	logger := slog.New(New(slog.NewTextHandler(&b, nil), WithKey(Redact, "accessToken")))
	logger.Info("test", "ACCESS_TOKEN", "one", "access-token", "two", "Access Token", "three")
	got := b.String()
	for _, leaked := range []string{"one", "two", "three"} {
		if strings.Contains(got, leaked) { t.Fatalf("normalized key leaked %q in %q", leaked, got) }
	}
}

func TestSkipValueScan(t *testing.T) {
	var b bytes.Buffer
	logger := slog.New(New(slog.NewTextHandler(&b, nil),
		WithValueFunc(MaskEmail),
		WithSkipValueScan("raw_message"),
	))
	logger.Info("test", "raw_message", "john@example.com", "message", "john@example.com")
	got := b.String()
	if !strings.Contains(got, "raw_message=john@example.com") { t.Fatalf("skip failed: %q", got) }
	if !strings.Contains(got, "message=j***@example.com") { t.Fatalf("mask failed: %q", got) }
}

type testLogValue struct{}
func (testLogValue) LogValue() slog.Value { return slog.StringValue("john@example.com") }

func TestLogValuerResolvedOnce(t *testing.T) {
	var b bytes.Buffer
	logger := slog.New(New(slog.NewTextHandler(&b, nil), WithValueFunc(MaskEmail)))
	logger.Info("test", "email", testLogValue{})
	got := b.String()
	if strings.Contains(got, "john@example.com") { t.Fatalf("email leaked: %q", got) }
}

func TestGroup(t *testing.T) {
	var b bytes.Buffer
	logger := slog.New(New(slog.NewTextHandler(&b, nil), WithDefaultPII()))
	logger.Info("test", slog.Group("user", slog.String("email", "john@example.com"), slog.String("id", "123")))
	got := b.String()
	if strings.Contains(got, "john@example.com") || !strings.Contains(got, "id=123") { t.Fatalf("group handling: %q", got) }
}

package cloak_test

import (
	"bytes"
	"log/slog"
	"strconv"
	"strings"
	"testing"

	"github.com/lrweck/cloak"
)

func logContain(opts []cloak.Option, msg string, args ...any) string {
	var b bytes.Buffer
	logger := slog.New(cloak.New(slog.NewTextHandler(&b, nil), opts...))
	logger.Info(msg, args...)
	return b.String()
}

const testSecret = "sk_live_51H8xQ2"

// The case the rule exists for: the secret is known but the field is not. The whole
// value goes, not just the secret, because the rest of a URL or a message may carry
// more of it.
func TestContainMasksUnknownField(t *testing.T) {
	got := logContain([]cloak.Option{cloak.WithContain(testSecret)},
		"m", "request_url", "https://api.example.com/v1/"+testSecret+"/charge")

	if strings.Contains(got, testSecret) {
		t.Errorf("secret leaked: %s", got)
	}
	if !strings.Contains(got, cloak.Placeholder) {
		t.Errorf("expected %s: %s", cloak.Placeholder, got)
	}
	if strings.Contains(got, "api.example.com") {
		t.Errorf("the whole value should be replaced: %s", got)
	}
}

func TestContainMatchesAnySecret(t *testing.T) {
	got := logContain([]cloak.Option{cloak.WithContain("aaa111", "bbb222")},
		"m", "note", "value bbb222 here")

	if strings.Contains(got, "bbb222") {
		t.Errorf("second secret leaked: %s", got)
	}
}

func TestContainLeavesOtherValuesAlone(t *testing.T) {
	got := logContain([]cloak.Option{cloak.WithContain(testSecret)},
		"m", "note", "nothing sensitive here")
	if !strings.Contains(got, "nothing sensitive here") {
		t.Errorf("unrelated value must survive: %s", got)
	}
}

// It is a value rule, so it also covers the message.
func TestContainMasksMessage(t *testing.T) {
	got := logContain([]cloak.Option{cloak.WithContain(testSecret), cloak.WithMessageScan()},
		"failed to authenticate with "+testSecret)
	if strings.Contains(got, testSecret) {
		t.Errorf("secret in message leaked: %s", got)
	}
}

func TestContainMasksInsideStruct(t *testing.T) {
	type req struct {
		URL string
	}
	got := logContain([]cloak.Option{
		cloak.WithStructScan(), cloak.WithDefaultPIIKeys(), cloak.WithContain(testSecret),
	}, "m", "req", req{URL: "https://x/" + testSecret})

	if strings.Contains(got, testSecret) {
		t.Errorf("secret inside a struct leaked: %s", got)
	}
}

func TestContainMasksMapAndSlice(t *testing.T) {
	got := logContain([]cloak.Option{
		cloak.WithCompositeScan(), cloak.WithContain(testSecret),
	}, "m", "m", map[string]string{"k": testSecret}, "s", []string{testSecret})

	if strings.Contains(got, testSecret) {
		t.Errorf("secret in a container leaked: %s", got)
	}
}

// An empty needle matches every string, which would silence every log line.
func TestContainIgnoresEmptySecret(t *testing.T) {
	got := logContain([]cloak.Option{cloak.WithContain("")},
		"m", "note", "ordinary value")

	if !strings.Contains(got, "ordinary value") {
		t.Errorf("an empty secret must not mask everything: %s", got)
	}
}

func TestContainAllEmptyIsInert(t *testing.T) {
	got := logContain([]cloak.Option{cloak.WithContain("", "")},
		"m", "note", "ordinary value")
	if !strings.Contains(got, "ordinary value") {
		t.Errorf("expected no rule to be installed: %s", got)
	}
}

// Matching is case sensitive: a secret is a specific byte sequence.
func TestContainIsCaseSensitive(t *testing.T) {
	got := logContain([]cloak.Option{cloak.WithContain("Secret123")},
		"m", "note", "secret123")
	if !strings.Contains(got, "secret123") {
		t.Errorf("matching must stay case sensitive: %s", got)
	}
}

func TestContainRespectsSkipValueScan(t *testing.T) {
	got := logContain([]cloak.Option{
		cloak.WithContain(testSecret), cloak.WithSkipValueScan("raw"),
	}, "m", "raw", "body "+testSecret)

	if !strings.Contains(got, testSecret) {
		t.Errorf("skip should have been honoured: %s", got)
	}
}

func BenchmarkContain(b *testing.B) {
	for _, n := range []int{1, 4} {
		b.Run(strconv.Itoa(n), func(b *testing.B) {
			secrets := make([]string, n)
			for i := range secrets {
				secrets[i] = "sk_live_secret_value_00000000000" + string(rune('a'+i))
			}
			var buf bytes.Buffer
			logger := slog.New(cloak.New(slog.NewTextHandler(&buf, nil), cloak.WithContain(secrets...)))
			b.ReportAllocs()
			for b.Loop() {
				logger.Info("payment settled", "id", 42, "ok", true)
			}
		})
	}
}

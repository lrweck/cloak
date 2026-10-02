package cloak_test

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/lrweck/cloak"
)

// The README's "Getting started" block, with its stated JSON output.
func TestReadmeGettingStartedOutput(t *testing.T) {
	var out bytes.Buffer
	slog.New(cloak.New(slog.NewJSONHandler(&out, nil), cloak.WithDefaultPII())).
		Info("payment", "email", "john@example.com", "amount", 1299)

	got := out.String()
	if !strings.Contains(got, `"email":"[REDACTED]"`) {
		t.Errorf(`README shows "email":"[REDACTED]": %s`, got)
	}
	if !strings.Contains(got, `"amount":1299`) {
		t.Errorf("a non-personal field must survive: %s", got)
	}
}

// A key rule outranks the detector that would otherwise have produced a partial mask.
func TestReadmeKeyRuleBeatsDetector(t *testing.T) {
	var out bytes.Buffer
	slog.New(cloak.New(slog.NewJSONHandler(&out, nil),
		cloak.WithDefaultPII(),
		cloak.WithKey(cloak.KeepLast(4), "card_number"),
	)).Info("m", "card_number", "4111111111111111")

	got := out.String()
	if !strings.Contains(got, "************1111") {
		t.Errorf("the key rule should have won over the preset: %s", got)
	}
}

// Patterns match the name as written, not the normalized form that strips the anchors
// a pattern usually relies on.
func TestReadmeRegexMatchesAsWritten(t *testing.T) {
	var out bytes.Buffer
	slog.New(cloak.New(slog.NewTextHandler(&out, nil),
		cloak.WithKeyRegex(`_key$`, cloak.Redact))).Info("m", "api_key", "sk-1")

	if !strings.Contains(out.String(), "api_key=[REDACTED]") {
		t.Errorf(`README says "_key$" matches api_key: %s`, out.String())
	}
}

// A named string type is stored as KindAny, so the string detectors never see it and
// only WithType can mask it.
func TestReadmeTypeReachesWhatDetectorsCannot(t *testing.T) {
	type EmailAddr string
	var out bytes.Buffer
	slog.New(cloak.New(slog.NewTextHandler(&out, nil),
		cloak.WithDefaultPIIValues(),
		cloak.WithType[EmailAddr](),
	)).Info("m", "to", EmailAddr("john@example.com"))

	got := out.String()
	if strings.Contains(got, "john@example.com") {
		t.Errorf("a typed email leaked past the detectors: %s", got)
	}
}

// A walked value keeps its type, so the record stays structured.
func TestReadmeCompositeKeepsType(t *testing.T) {
	var out bytes.Buffer
	slog.New(cloak.New(slog.NewJSONHandler(&out, nil),
		cloak.WithStructScan())).Info("m", "user", readmeAccount{ID: 7, Email: "a@b.com"})

	got := out.String()
	if !strings.Contains(got, `"Email":"a@b.com"`) {
		t.Errorf("the struct should have stayed a struct: %s", got)
	}
	if !strings.Contains(got, `"ID":7`) {
		t.Errorf("an untouched field must survive: %s", got)
	}
}

// []byte is data, not a container of things to log.
func TestReadmeByteSliceIsSkipped(t *testing.T) {
	var out bytes.Buffer
	slog.New(cloak.New(slog.NewTextHandler(&out, nil),
		cloak.WithDefaultPII(), cloak.WithSliceScan())).
		Info("m", "blob", []byte("john@example.com"))

	if strings.Contains(out.String(), "106,111,104,110") {
		t.Errorf("the payload was rewritten into digits: %s", out.String())
	}
}

// WithContain replaces the whole value, not just the substring.
func TestReadmeContainReplacesWholeValue(t *testing.T) {
	var out bytes.Buffer
	slog.New(cloak.New(slog.NewTextHandler(&out, nil),
		cloak.WithContain("s3cr3t"))).
		Info("m", "note", "before s3cr3t after")

	got := out.String()
	if !strings.Contains(got, "note=[REDACTED]") {
		t.Errorf("the whole value should be replaced: %s", got)
	}
}

// The message is untouched unless asked for.
func TestReadmeMessageScanIsOffByDefault(t *testing.T) {
	var out bytes.Buffer
	slog.New(cloak.New(slog.NewTextHandler(&out, nil), cloak.WithDefaultPII())).
		Info("user john@example.com logged in")

	if !strings.Contains(out.String(), "john@example.com") {
		t.Errorf("README says the message is left alone by default: %s", out.String())
	}
}

// Each composite option is scoped to its own shape.
func TestReadmeCompositeScanIsAllThree(t *testing.T) {
	var out bytes.Buffer
	logger := slog.New(cloak.New(slog.NewTextHandler(&out, nil),
		cloak.WithDefaultPII(), cloak.WithCompositeScan()))

	logger.Info("m", "s", readmeAccount{Email: "a@b.com"})
	logger.Info("m", "mp", map[string]string{"email": "a@b.com"})
	logger.Info("m", "sl", []string{"a@b.com"})

	if strings.Contains(out.String(), "a@b.com") {
		t.Errorf("WithCompositeScan should cover all three shapes: %s", out.String())
	}
}

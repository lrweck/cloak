package cloak_test

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/lrweck/cloak"
)

type tagged struct {
	ID       int
	Password string `cloak:"secret"`
	Note     string `cloak:"pii"`
	Plain    string
	Other    string `json:"other"`
}

func logTagged(opts []cloak.Options, v any) string {
	var b bytes.Buffer
	logger := slog.New(cloak.New(slog.NewTextHandler(&b, nil), opts...))
	logger.Info("m", "v", v)
	return b.String()
}

func withTags(extra ...cloak.Options) []cloak.Options {
	return append([]cloak.Options{
		cloak.WithStructScan(),
		cloak.WithTag(cloak.Redact, "cloak", "secret"),
		cloak.WithTag(cloak.KeepFirst(1), "cloak", "pii"),
	}, extra...)
}

func TestTagMasksField(t *testing.T) {
	got := logTagged(withTags(), tagged{Password: "hunter2", Note: "abcd", Plain: "p"})
	if strings.Contains(got, "hunter2") {
		t.Errorf("tagged field leaked: %s", got)
	}
	if !strings.Contains(got, "[REDACTED]") {
		t.Errorf("expected full redaction: %s", got)
	}
}

// One tag value can carry a different masker than another.
func TestTagUsesItsOwnMasker(t *testing.T) {
	got := logTagged(withTags(), tagged{Password: "hunter2", Note: "abcd"})
	if strings.Contains(got, "abcd") {
		t.Errorf("pii tag should have been masked too: %s", got)
	}
	if !strings.Contains(got, "a***") {
		t.Errorf("expected KeepFirst(1) on the pii tag: %s", got)
	}
}

// A tag only applies to struct fields, and only under a composite option.
func TestTagIgnoresUntaggedFields(t *testing.T) {
	got := logTagged(withTags(), tagged{ID: 7, Plain: "visible"})
	if !strings.Contains(got, "visible") {
		t.Errorf("untagged field must survive: %s", got)
	}
	if !strings.Contains(got, "ID:7") {
		t.Errorf("sibling must survive: %s", got)
	}
}

// Rules for different tag keys coexist, and the key is not matched by value alone.
func TestTagKeyIsHonoured(t *testing.T) {
	type doc struct {
		Secret string `json:"secret"`
	}
	got := logTagged([]cloak.Options{
		cloak.WithStructScan(),
		cloak.WithTag(cloak.Redact, "json", "secret"),
	}, doc{Secret: "hunter2"})
	if strings.Contains(got, "hunter2") {
		t.Errorf("json tag key should have matched: %s", got)
	}

	// The same value under a key nobody watches stays.
	got = logTagged([]cloak.Options{cloak.WithStructScan()}, doc{Secret: "hunter2"})
	if !strings.Contains(got, "hunter2") {
		t.Errorf("without a rule the field must survive: %s", got)
	}
}

// A tag the walk never watches is inert.
func TestTagUnrelatedKeyIgnored(t *testing.T) {
	got := logTagged([]cloak.Options{
		cloak.WithStructScan(),
		cloak.WithTag(cloak.Redact, "cloak", "secret"),
	}, tagged{Other: "visible"})
	if !strings.Contains(got, "visible") {
		t.Errorf("json:\"other\" is not cloak:\"secret\": %s", got)
	}
}

// A tag beats the value detectors but loses to an explicit key rule.
func TestTagPrecedenceAgainstKeyRule(t *testing.T) {
	type both struct {
		Password string `cloak:"secret"`
	}
	got := logTagged([]cloak.Options{
		cloak.WithStructScan(),
		cloak.WithTag(cloak.Redact, "cloak", "secret"),
		cloak.WithKeys(cloak.KeepLast(3), "Password"),
	}, both{Password: "hunter2"})

	if !strings.Contains(got, "****er2") {
		t.Errorf("an explicit key rule must win over a tag: %s", got)
	}
}

// A tag reaches nested structs too.
func TestTagOnNestedStruct(t *testing.T) {
	type inner struct {
		Secret string `cloak:"secret"`
	}
	type outer struct {
		In inner
	}
	got := logTagged(withTags(), outer{In: inner{Secret: "hunter2"}})
	if strings.Contains(got, "hunter2") {
		t.Errorf("nested tagged field leaked: %s", got)
	}
}

func TestTagOnUnexportedFieldIsRedundant(t *testing.T) {
	// Unexported fields are dropped outright, so a tag there has nothing to act on.
	type hidden struct {
		secret string `cloak:"secret"`
	}
	got := logTagged(withTags(), hidden{secret: "hunter2"})
	if strings.Contains(got, "hunter2") {
		t.Errorf("leaked: %s", got)
	}
}

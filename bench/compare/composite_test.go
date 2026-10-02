package compare

import (
	"bytes"
	"log/slog"
	"testing"

	"github.com/lrweck/cloak"
	"github.com/m-mizutani/masq"
)

type probeUser struct {
	ID       int
	Password string
}

// The benchmark compares key rules only, and with that configuration none of the
// libraries reaches inside a struct — cloak included, because walking composites is
// opt-in. Without this, the table would look like a like-for-like comparison of a
// capability it deliberately leaves out.
func TestKeyOnlyConfigReachesInsideNothing(t *testing.T) {
	var b bytes.Buffer
	slog.New(cloak.New(slog.NewJSONHandler(&b, nil),
		cloak.WithKeys(cloak.Redact, sensitiveKeys...),
	)).Info("m", slog.Any("user", probeUser{ID: 7, Password: "hunter2"}))

	if !bytes.Contains(b.Bytes(), []byte("hunter2")) {
		t.Fatalf("the key-only configuration walked a struct, so the table is not "+
			"comparing like with like: %s", b.String())
	}
}

// Both cloak and masq can be configured to reach inside. That capability is not what
// the benchmark measures, and it is not a difference in the integration shape: masq
// hooks ReplaceAttr and still walks, because it clones what it is handed.
func TestBothHandlersCanReachInsideWhenConfigured(t *testing.T) {
	var cloaked bytes.Buffer
	slog.New(cloak.New(slog.NewJSONHandler(&cloaked, nil),
		cloak.WithKeys(cloak.Redact, sensitiveKeys...),
		cloak.WithStructScan(),
	)).Info("m", slog.Any("user", probeUser{ID: 7, Password: "hunter2"}))

	if bytes.Contains(cloaked.Bytes(), []byte("hunter2")) {
		t.Errorf("cloak with WithStructScan should have masked the field: %s", cloaked.String())
	}

	// masq matches the Go field name exactly, so the spelling has to be the field's.
	var masked bytes.Buffer
	slog.New(slog.NewJSONHandler(&masked, &slog.HandlerOptions{
		ReplaceAttr: masq.New(masq.WithFieldName("Password")),
	})).Info("m", slog.Any("user", probeUser{ID: 7, Password: "hunter2"}))

	if bytes.Contains(masked.Bytes(), []byte("hunter2")) {
		t.Errorf("masq with the field named should have masked it: %s", masked.String())
	}
}

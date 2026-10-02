package cloak_test

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/lrweck/cloak"
)

// A key rule names the field, so it has to reach the value stored under that name
// wherever the field lives. This is the regression: map[string]string{"password": …}
// used to reach the sink untouched, because only type rules and detectors ran inside
// the walk.
func TestKeyRuleReachesEveryContainer(t *testing.T) {
	cases := []struct {
		name string
		attr slog.Attr
		opts []cloak.Options
	}{
		{"attribute", slog.String("password", "hunter2"), nil},
		{"group", slog.Group("g", slog.String("password", "hunter2")), nil},
		{"struct field", slog.Any("a", struct{ Password string }{Password: "hunter2"}),
			[]cloak.Options{cloak.WithStructScan()}},
		{"map key", slog.Any("m", map[string]string{"password": "hunter2"}),
			[]cloak.Options{cloak.WithMapScan()}},
		{"map key, any value", slog.Any("m", map[string]any{"password": "hunter2"}),
			[]cloak.Options{cloak.WithMapScan()}},
		{"map key, nested map", slog.Any("m", map[string]any{"auth": map[string]string{"password": "hunter2"}}),
			[]cloak.Options{cloak.WithMapScan()}},
		{"slice of maps", slog.Any("s", []map[string]string{{"password": "hunter2"}}),
			[]cloak.Options{cloak.WithSliceScan(), cloak.WithMapScan()}},
		{"map key, slice value", slog.Any("m", map[string][]string{"password": {"hunter2"}}),
			[]cloak.Options{cloak.WithMapScan(), cloak.WithSliceScan()}},
		{"struct field holding a map", slog.Any("a", struct {
			Auth map[string]string `json:"auth"`
		}{Auth: map[string]string{"password": "hunter2"}}),
			[]cloak.Options{cloak.WithStructScan(), cloak.WithMapScan()}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts := append([]cloak.Options{cloak.WithKey(cloak.Redact, "password")}, tc.opts...)
			var b bytes.Buffer
			logger := slog.New(cloak.New(slog.NewTextHandler(&b, nil), opts...))
			logger.Info("m", tc.attr)

			if strings.Contains(b.String(), "hunter2") {
				t.Fatalf("key rule did not reach the value: %s", b.String())
			}
		})
	}
}

// The key itself must survive: it is the field name, not the secret, and losing it
// makes the entry unrecognisable.
func TestKeyRuleKeepsTheMapKey(t *testing.T) {
	got := logWith(compositeOpts(cloak.WithMapScan(), cloak.WithKey(cloak.Redact, "password")),
		func(l *slog.Logger) {
			l.Info("m", "m", map[string]string{"password": "hunter2", "user": "jane"})
		})
	if !strings.Contains(got, "password") {
		t.Errorf("the key name should survive: %s", got)
	}
	if !strings.Contains(got, "jane") {
		t.Errorf("an unmatched entry must survive: %s", got)
	}
	if strings.Contains(got, "hunter2") {
		t.Errorf("leaked: %s", got)
	}
}

// The default preset reaches map keys too, which is what masked the CPF by key
// before the value detector happened to agree.
func TestDefaultPresetReachesMapKeys(t *testing.T) {
	got := logWith(compositeOpts(cloak.WithMapScan()), func(l *slog.Logger) {
		l.Info("m", "m", map[string]string{"password": "hunter2", "cvv": "999"})
	})
	if strings.Contains(got, "hunter2") || strings.Contains(got, "999") {
		t.Errorf("default preset did not reach map keys: %s", got)
	}
}

// A key rule wins over the value detectors, as everywhere else.
func TestKeyRuleBeatsDetectorOnMapValue(t *testing.T) {
	got := logWith(compositeOpts(cloak.WithMapScan(), cloak.WithKey(cloak.KeepFirst(1), "email")),
		func(l *slog.Logger) {
			l.Info("m", "m", map[string]string{"email": "john@example.com"})
		})
	if !strings.Contains(got, "j***@example.com") {
		t.Errorf("the key rule should have masked the whole value: %s", got)
	}
}

// A map keyed by something other than a string has no name for a rule to match, and
// must not panic trying.
func TestNonStringMapKeyIsUntouched(t *testing.T) {
	got := logWith(compositeOpts(cloak.WithMapScan(), cloak.WithKey(cloak.Redact, "password")),
		func(l *slog.Logger) {
			l.Info("m", "m", map[int]string{7: "harmless"})
		})
	if !strings.Contains(got, "harmless") {
		t.Errorf("unexpected: %s", got)
	}
}

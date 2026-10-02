package cloak

import (
	"log/slog"
	"strings"
	"testing"
)

// normalizeKey's fast path returns the input untouched, which is what keeps the path
// where nothing matched from allocating. Identity is the assertion: an equal string
// built by the builder would pass a value comparison and still cost the allocation.
func TestNormalizeKeyFastPathReturnsInput(t *testing.T) {
	for _, s := range []string{"", "status", "amount", "userid", "a", "cpf123"} {
		if got := normalizeKey(s); got != s {
			t.Errorf("normalizeKey(%q) = %q, want the input back", s, got)
		}
	}
}

func TestNormalizeKeyStillFoldsWhenItMust(t *testing.T) {
	cases := map[string]string{
		"card_number": "cardnumber",
		"cardNumber":  "cardnumber",
		"CARD-NUMBER": "cardnumber",
		"Card Number": "cardnumber",
		"a\tb":        "ab",
		"_-":          "",
	}
	for in, want := range cases {
		if got := normalizeKey(in); got != want {
			t.Errorf("normalizeKey(%q) = %q, want %q", in, got, want)
		}
	}
}

// An already-normalized key costs nothing, on the path that runs for every attribute
// of every record.
func BenchmarkNormalizeKey(b *testing.B) {
	b.Run("already_normalized", func(b *testing.B) {
		for b.Loop() {
			_ = normalizeKey("duration")
		}
	})
	b.Run("needs_folding", func(b *testing.B) {
		for b.Loop() {
			_ = normalizeKey("duration_ms")
		}
	})
}

// A record wider than the stack buffer must still come through whole: the array is an
// optimization, not a limit, and silently dropping attributes would be a leak-shaped
// bug rather than a slow one.
func TestHandleWideRecordKeepsEveryAttribute(t *testing.T) {
	const n = 40 // past the 16-slot stack buffer

	for _, tc := range []struct {
		name    string
		opts    []Options
		masked  string // field name expected to be redacted rather than passed through
		leakage string // value that must not appear anywhere
	}{
		{"no rule matched", nil, "", ""},
		{"a rule fired", []Options{WithKeys(Redact, "field_ba")}, "field_ba", ""},
		{
			"a detector fired", []Options{WithValueFunc(MaskEmail)},
			"", "john@example.com",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := newConfigForBench()
			for _, o := range tc.opts {
				o.apply(cfg)
			}
			cfg.finalize()

			var b strings.Builder
			logger := slog.New(&Handler{next: slog.NewTextHandler(&b, nil), cfg: cfg})

			args := make([]any, 0, 2*n)
			for i := range n {
				args = append(args, slog.Int(fieldName(i), i))
			}
			if tc.leakage != "" {
				args = append(args, "contact", tc.leakage)
			}
			logger.Info("wide", args...)

			out := b.String()
			// Every field name present is the assertion: a dropped attribute is the
			// failure mode the stack buffer could have introduced.
			for i := range n {
				if !strings.Contains(out, fieldName(i)+"=") {
					t.Fatalf("attribute %d lost: %s", i, out)
				}
			}
			if tc.masked != "" && !strings.Contains(out, tc.masked+"="+Placeholder) {
				t.Errorf("expected %s to be redacted: %s", tc.masked, out)
			}
			if tc.leakage != "" && strings.Contains(out, tc.leakage) {
				t.Errorf("value leaked: %s", out)
			}
		})
	}
}

func fieldName(i int) string {
	return "field_" + string(rune('a'+i%26)) + string(rune('a'+i/26))
}

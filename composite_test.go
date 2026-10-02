package cloak_test

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/lrweck/cloak"
)

type account struct {
	ID      int
	Email   string
	CPF     string
	Tags    []string
	Inner   *account
	Skip    string `slog:"-"`
	Contact string
}

func logWith(opts []cloak.Options, fn func(*slog.Logger)) string {
	var b bytes.Buffer
	logger := slog.New(cloak.New(slog.NewTextHandler(&b, nil), opts...))
	fn(logger)
	return b.String()
}

func compositeOpts(extra ...cloak.Options) []cloak.Options {
	return append([]cloak.Options{
		cloak.WithDefaultPIIKeys(),
		cloak.WithDefaultPIIValues(),
	}, extra...)
}

func TestWithStructScan(t *testing.T) {
	got := logWith(compositeOpts(cloak.WithStructScan()), func(l *slog.Logger) {
		l.Info("m", "acct", account{ID: 7, Email: "john@example.com", CPF: "529.982.247-25"})
	})
	for _, leaked := range []string{"john@example.com", "529.982.247"} {
		if strings.Contains(got, leaked) {
			t.Errorf("leaked %q: %s", leaked, got)
		}
	}
	// TextHandler renders a struct with %+v, so the sibling field is "ID:7".
	if !strings.Contains(got, "ID:7") {
		t.Errorf("struct must keep its other fields: %s", got)
	}
}

func TestPointerToStructAtTopLevel(t *testing.T) {
	// Passing a struct by pointer is the common case, and compositePtr is set by
	// every option so it must be walked too.
	got := logWith(compositeOpts(cloak.WithStructScan()), func(l *slog.Logger) {
		l.Info("m", "acct", &account{ID: 7, Email: "john@example.com"})
	})
	if strings.Contains(got, "john@example.com") {
		t.Errorf("leaked: %s", got)
	}
	if !strings.Contains(got, "[REDACTED]") {
		t.Errorf("expected masking: %s", got)
	}
}

func TestStructScanKeepsType(t *testing.T) {
	var b bytes.Buffer
	logger := slog.New(cloak.New(slog.NewJSONHandler(&b, nil),
		cloak.WithDefaultPIIValues(), cloak.WithStructScan()))
	logger.Info("m", "acct", account{ID: 7, Email: "john@example.com"})

	// A masked struct is still an object in JSON, not a stringified blob.
	if !strings.Contains(b.String(), `"acct":{"ID":7,"Email":"j***@example.com"`) {
		t.Fatalf("struct should keep its shape: %s", b.String())
	}
}

func TestWithMapScan(t *testing.T) {
	got := logWith(compositeOpts(cloak.WithMapScan()), func(l *slog.Logger) {
		l.Info("m", "ctx", map[string]any{
			"email": "john@example.com",
			"role":  "admin",
			"cpf":   "529.982.247-25",
		})
	})
	for _, leaked := range []string{"john@example.com", "529.982.247"} {
		if strings.Contains(got, leaked) {
			t.Errorf("leaked %q: %s", leaked, got)
		}
	}
	if !strings.Contains(got, "role") || !strings.Contains(got, "admin") {
		t.Errorf("map must keep unrelated entries: %s", got)
	}
}

func TestWithSliceScan(t *testing.T) {
	got := logWith(compositeOpts(cloak.WithSliceScan()), func(l *slog.Logger) {
		l.Info("m", "emails", []string{"a@example.com", "b@example.com"})
	})
	if strings.Contains(got, "@example.com\"") || strings.Contains(got, "a@example.com,") {
		t.Errorf("leaked: %s", got)
	}
	if !strings.Contains(got, "a***@example.com") {
		t.Errorf("expected masking: %s", got)
	}
}

func TestSliceOfPointers(t *testing.T) {
	// slog renders a pointer slice as [0x...] addresses, so the leak check needs
	// the JSON handler, which dereferences.
	var b bytes.Buffer
	logger := slog.New(cloak.New(slog.NewJSONHandler(&b, nil), compositeOpts(cloak.WithSliceScan())...))
	logger.Info("m", "users", []*account{{ID: 1, Email: "john@example.com"}})

	got := b.String()
	if strings.Contains(got, "john@example.com") {
		t.Errorf("leaked through pointer slice: %s", got)
	}
	if !strings.Contains(got, `"ID":1`) {
		t.Errorf("expected the element to survive: %s", got)
	}
}

func TestNestedStructs(t *testing.T) {
	got := logWith(compositeOpts(cloak.WithStructScan()), func(l *slog.Logger) {
		l.Info("m", "acct", account{Inner: &account{ID: 2, Email: "inner@example.com"}})
	})
	if strings.Contains(got, "inner@example.com") {
		t.Errorf("leaked from nested pointer: %s", got)
	}
}

func TestByteSliceUntouched(t *testing.T) {
	// Walking []byte would rewrite a payload into decimal digits.
	payload := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9}
	got := logWith(compositeOpts(cloak.WithCompositeScan()), func(l *slog.Logger) {
		l.Info("m", "raw", payload)
	})
	if strings.Contains(got, "*") {
		t.Errorf("[]byte must not be walked: %s", got)
	}
}

// TextHandler renders a struct with %+v, which prints unexported fields that
// encoding/json would ignore. Copying them through hands the value to the sink.
func TestUnexportedFieldsAreDropped(t *testing.T) {
	type withUnexported struct {
		Public string
		secret string
	}
	for _, h := range []struct {
		name  string
		build func(*bytes.Buffer) slog.Handler
	}{
		{"TextHandler", func(b *bytes.Buffer) slog.Handler { return slog.NewTextHandler(b, nil) }},
		{"JSONHandler", func(b *bytes.Buffer) slog.Handler { return slog.NewJSONHandler(b, nil) }},
	} {
		t.Run(h.name, func(t *testing.T) {
			var b bytes.Buffer
			logger := slog.New(cloak.New(h.build(&b), compositeOpts(cloak.WithStructScan())...))
			logger.Info("m", "v", withUnexported{Public: "public-value", secret: "hunter2"})

			got := b.String()
			if strings.Contains(got, "hunter2") {
				t.Errorf("unexported field leaked: %s", got)
			}
			if !strings.Contains(got, "public-value") {
				t.Errorf("exported field must survive: %s", got)
			}
		})
	}
}

// A struct carrying an unexported field rebuilds even when no rule matched, because
// dropping the field is the change.
func TestUnexportedFieldForcesRebuild(t *testing.T) {
	type quiet struct{ secret string }
	var b bytes.Buffer
	logger := slog.New(cloak.New(slog.NewTextHandler(&b, nil), cloak.WithStructScan()))
	logger.Info("m", "v", quiet{secret: "hunter2"})

	if strings.Contains(b.String(), "hunter2") {
		t.Fatalf("leaked: %s", b.String())
	}
}

// A struct with no unexported fields and no match is passed through untouched.
func TestCleanStructPassesThrough(t *testing.T) {
	type clean struct{ A, B int }
	got := logWith(compositeOpts(cloak.WithStructScan()), func(l *slog.Logger) {
		l.Info("m", "v", clean{A: 1, B: 2})
	})
	if !strings.Contains(got, "A:1") || !strings.Contains(got, "B:2") {
		t.Fatalf("unexpected: %s", got)
	}
}

// A field tagged slog:"-" is omitted from the output rather than copied.
func TestSlogDashTagDropped(t *testing.T) {
	got := logWith(compositeOpts(cloak.WithStructScan()), func(l *slog.Logger) {
		l.Info("m", "acct", account{ID: 7, Skip: "hunter2"})
	})
	if strings.Contains(got, "hunter2") {
		t.Errorf(`slog:"-" must not be emitted: %s`, got)
	}
	if !strings.Contains(got, "ID:7") {
		t.Errorf("siblings must survive: %s", got)
	}
}

func TestOptionsAreIndependent(t *testing.T) {
	cases := []struct {
		name   string
		opts   []cloak.Options
		attr   slog.Attr
		leaked string
		masked string
	}{
		{
			name:   "struct only does not touch slices",
			opts:   compositeOpts(cloak.WithStructScan()),
			attr:   slog.Any("v", []string{"a@example.com"}),
			leaked: "a@example.com",
		},
		{
			name:   "slice only does not touch structs",
			opts:   compositeOpts(cloak.WithSliceScan()),
			attr:   slog.Any("v", account{Email: "a@example.com"}),
			leaked: "a@example.com",
		},
		{
			name:   "map only does not touch slices",
			opts:   compositeOpts(cloak.WithMapScan()),
			attr:   slog.Any("v", []string{"a@example.com"}),
			leaked: "a@example.com",
		},
		{
			name:   "composite covers slices",
			opts:   compositeOpts(cloak.WithCompositeScan()),
			attr:   slog.Any("v", []string{"a@example.com"}),
			masked: "a***@example.com",
		},
		{
			name:   "composite covers structs",
			opts:   compositeOpts(cloak.WithCompositeScan()),
			attr:   slog.Any("v", account{Contact: "a@example.com"}),
			masked: "a***@example.com",
		},
		{
			name:   "composite covers maps",
			opts:   compositeOpts(cloak.WithCompositeScan()),
			attr:   slog.Any("v", map[string]any{"mail": "a@example.com"}),
			masked: "a***@example.com",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := logWith(tc.opts, func(l *slog.Logger) { l.Info("m", tc.attr) })
			if tc.leaked != "" && !strings.Contains(got, tc.leaked) {
				t.Fatalf("expected %q to survive: %s", tc.leaked, got)
			}
			if tc.masked != "" && !strings.Contains(got, tc.masked) {
				t.Fatalf("expected %q to be masked: %s", tc.masked, got)
			}
		})
	}
}

// slog.LogValuer takes precedence over masking: it decides what the value exposes,
// and that output is then masked.
type resolved struct{ raw string }

func (r resolved) LogValue() slog.Value { return slog.StringValue(r.raw) }

func TestLogValuerTakesPrecedenceThenMasked(t *testing.T) {
	cases := []struct {
		name   string
		opts   []cloak.Options
		attr   slog.Attr
		masked string
		leaked string
	}{
		{
			name:   "top level",
			opts:   compositeOpts(cloak.WithCompositeScan()),
			attr:   slog.Any("v", resolved{raw: "john@example.com"}),
			masked: "j***@example.com",
		},
		{
			name:   "struct field",
			opts:   compositeOpts(cloak.WithStructScan()),
			attr:   slog.Any("v", struct{ Contact resolved }{Contact: resolved{raw: "john@example.com"}}),
			masked: "j***@example.com",
		},
		{
			// "email" is a default key, so the key rule wins over the detector.
			name:   "struct field, key rule beats value detector",
			opts:   compositeOpts(cloak.WithStructScan()),
			attr:   slog.Any("v", struct{ Email resolved }{Email: resolved{raw: "john@example.com"}}),
			masked: "[REDACTED]",
		},
		{
			name:   "map value",
			opts:   compositeOpts(cloak.WithMapScan()),
			attr:   slog.Any("v", map[string]any{"mail": resolved{raw: "john@example.com"}}),
			masked: "j***@example.com",
		},
		{
			name:   "slice element",
			opts:   compositeOpts(cloak.WithSliceScan()),
			attr:   slog.Any("v", []resolved{{raw: "john@example.com"}}),
			masked: "j***@example.com",
		},
		{
			name:   "LogValue returning a group",
			opts:   compositeOpts(cloak.WithCompositeScan()),
			attr:   slog.Any("v", groupValuer{}),
			masked: "[REDACTED]",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := logWith(tc.opts, func(l *slog.Logger) { l.Info("m", tc.attr) })
			if tc.leaked != "" && strings.Contains(got, tc.leaked) {
				t.Fatalf("leaked %q: %s", tc.leaked, got)
			}
			if !strings.Contains(got, tc.masked) {
				t.Fatalf("expected %q: %s", tc.masked, got)
			}
			if strings.Contains(got, "john@example.com") {
				t.Fatalf("LogValue output was not masked: %s", got)
			}
		})
	}
}

type groupValuer struct{}

func (groupValuer) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("mail", "john@example.com"),
		slog.Int("id", 7),
	)
}

func TestLogValuerGroupKeepsOtherFields(t *testing.T) {
	got := logWith(compositeOpts(cloak.WithCompositeScan()), func(l *slog.Logger) {
		l.Info("m", "v", groupValuer{})
	})
	if !strings.Contains(got, "id=7") && !strings.Contains(got, "id:7") {
		t.Errorf("group siblings must survive: %s", got)
	}
}

func TestCompositeScanOffByDefault(t *testing.T) {
	for _, attr := range []slog.Attr{
		slog.Any("v", account{Email: "john@example.com"}),
		slog.Any("v", map[string]any{"mail": "john@example.com"}),
		slog.Any("v", []string{"john@example.com"}),
	} {
		got := logWith(compositeOpts(), func(l *slog.Logger) { l.Info("m", attr) })
		if !strings.Contains(got, "john@example.com") {
			t.Errorf("default must not walk composites: %s", got)
		}
	}
}

// A struct that cannot keep its shape widens to a group, and the group must carry
// every field: one skipped after the shape broke would vanish from the record.
// Here N is masked to a string that does not fit int64, and B follows the break.
func TestGroupKeepsFieldsAfterShapeBreak(t *testing.T) {
	type mixed struct {
		A int
		N int64
		B int
	}
	got := logWith([]cloak.Options{
		cloak.WithStructScan(),
		cloak.WithValuePredicate(cloak.Fixed("X"), func(v slog.Value) bool {
			return v.Kind() == slog.KindInt64 && v.Int64() == 2
		}),
	}, func(l *slog.Logger) {
		l.Info("m", slog.Any("s", mixed{A: 1, N: 2, B: 3}))
	})

	for _, want := range []string{"s.A=1", "s.N=X", "s.B=3"} {
		if !strings.Contains(got, want) {
			t.Errorf("expected %q in the widened group: %s", want, got)
		}
	}
}

// A changed pointer field widens to the group as well. The masking behind it is
// correct either way, but fmt renders a nested pointer as an address, so a struct
// keeping one reaches a TextHandler as 0x... with nothing showing a rule fired.
func TestChangedPointerFieldIsReadableOnText(t *testing.T) {
	type addr struct {
		Street string
		CEP    string
	}
	type user struct {
		ID     int
		ShipTo *addr
		Tags   []string
	}
	got := logWith(compositeOpts(cloak.WithStructScan()), func(l *slog.Logger) {
		l.Info("m", slog.Any("user", user{
			ID:     7,
			ShipTo: &addr{Street: "Rua X", CEP: "01310-100"},
			Tags:   []string{"admin"},
		}))
	})

	if strings.Contains(got, "01310-100") {
		t.Errorf("masked value leaked: %s", got)
	}
	if strings.Contains(got, "0x") {
		t.Errorf("a pointer address reached the text sink: %s", got)
	}
	if !strings.Contains(got, "[REDACTED]") {
		t.Errorf("expected the mask to show: %s", got)
	}
	// The widening must not lose the siblings, in either direction.
	for _, want := range []string{"user.ID=7", "admin"} {
		if !strings.Contains(got, want) {
			t.Errorf("expected sibling %q to survive: %s", want, got)
		}
	}
}

// The widening is a text rendering concern: on JSON the value stays a nested
// object, identical in shape to the struct.
func TestChangedPointerFieldKeepsObjectOnJSON(t *testing.T) {
	type addr struct {
		Street string
		CEP    string
	}
	type user struct {
		ID     int
		ShipTo *addr
	}
	var b bytes.Buffer
	slog.New(cloak.New(slog.NewJSONHandler(&b, nil),
		cloak.WithStructScan(), cloak.WithDefaultPII(),
	)).Info("m", slog.Any("user", user{ID: 7, ShipTo: &addr{Street: "Rua X", CEP: "01310-100"}}))

	got := b.String()
	if !strings.Contains(got, `"ShipTo":{"Street":"Rua X","CEP":"[REDACTED]"}`) {
		t.Errorf("expected a nested object: %s", got)
	}
}

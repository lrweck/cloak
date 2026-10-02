package cloak_test

import (
	"bytes"
	"log/slog"
	"reflect"
	"strings"
	"testing"

	"github.com/lrweck/cloak"
)

// A name has to mean the same thing wherever it lives. Struct fields and map keys
// walk through different code — walkField and walkMap — and they drifted: the map
// ran the value detectors before the key rule, so a map value got the detector's
// partial mask while the equivalent struct field got the preset's full redaction.
// The skip list was ignored in maps for the same reason.
//
// This compares the two paths for the same name and the same rules, so a future
// change to one that is not made to the other fails here instead of shipping.
func TestMapAndStructAgreeOnEveryRule(t *testing.T) {
	cases := []struct {
		name       string
		key        string
		val        string
		extra      []cloak.Options
		wantMasked bool // the value must not survive in the clear
	}{
		{"detector only", "contact", "john@example.com", nil, true},
		{"preset key", "email", "john@example.com", nil, true},
		// "apikey" is a preset key, so the regex case below is not the only
		// thing masking it.
		{"preset key via normalization", "api_key", "abcdef", nil, true},
		{"no rule matches", "nickname", "hunter2", nil, false},
		{"explicit key rule", "tok", "abcdef",
			[]cloak.Options{cloak.WithKeys(cloak.KeepFirst(2), "tok")}, true},
		{"key rule beats detector", "email", "john@example.com",
			[]cloak.Options{cloak.WithKeys(cloak.KeepFirst(1), "email")}, true},
		{"skip list", "payload", "john@example.com",
			[]cloak.Options{cloak.WithSkipValueScan("payload")}, false},
		{"skip loses to an explicit rule", "payload", "abcdef",
			[]cloak.Options{cloak.WithSkipValueScan("payload"), cloak.WithKeys(cloak.KeepFirst(2), "payload")}, true},
		{"contains rule", "db_password", "abcdef",
			[]cloak.Options{cloak.WithKeysContaining(cloak.KeepLast(2), "password")}, true},
		{"regex rule", "swift_key", "abcdef",
			[]cloak.Options{cloak.WithKeyRegex(cloak.KeepLast(2), `(?i)key$`)}, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			structValue := maskedStructField(t, tc.key, tc.val, tc.extra...)
			mapValue := maskedMapEntry(t, tc.key, tc.val, tc.extra...)

			if structValue != mapValue {
				t.Fatalf("the same rule over %q answered two ways:\n struct: %q\n map:    %q",
					tc.key, structValue, mapValue)
			}
			if leaked := strings.Contains(structValue, tc.val); leaked == tc.wantMasked {
				t.Fatalf("value %q in %q, wantMasked=%v", tc.val, structValue, tc.wantMasked)
			}
		})
	}
}

// maskedStructField logs the value as a struct field named after the key, so the
// struct reaches the same rule the map key would.
func maskedStructField(t *testing.T, key, val string, extra ...cloak.Options) string {
	t.Helper()
	opts := append([]cloak.Options{cloak.WithDefaultPII(), cloak.WithStructScan()}, extra...)
	var b bytes.Buffer
	slog.New(cloak.New(slog.NewTextHandler(&b, nil), opts...)).
		Info("m", "v", oneFieldStruct(key, val))
	return structFieldValue(b.String())
}

func maskedMapEntry(t *testing.T, key, val string, extra ...cloak.Options) string {
	t.Helper()
	opts := append([]cloak.Options{cloak.WithDefaultPII(), cloak.WithMapScan()}, extra...)
	var b bytes.Buffer
	slog.New(cloak.New(slog.NewTextHandler(&b, nil), opts...)).
		Info("m", "v", map[string]string{key: val})
	return mapFieldValue(b.String())
}

// oneFieldStruct builds a struct whose single exported field is the Go spelling of
// key. Exported is required: walkStruct drops an unexported field rather than
// copying it, which would compare the wrong thing.
func oneFieldStruct(key, val string) any {
	t := reflect.StructOf([]reflect.StructField{{
		Name: goFieldName(key),
		Type: reflect.TypeFor[string](),
	}})
	v := reflect.New(t).Elem()
	v.Field(0).SetString(val)
	return v.Interface()
}

// goFieldName turns a key into an exported Go identifier whose normalized form is
// the key's, so both sides reach the same rule.
func goFieldName(key string) string {
	var b strings.Builder
	upper := true
	for _, r := range key {
		switch {
		case r == '_' || r == '-':
			upper = true
		case upper:
			b.WriteString(strings.ToUpper(string(r)))
			upper = false
		default:
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		// reflect.StructOf rejects an empty field name.
		return "F"
	}
	return b.String()
}

// structFieldValue pulls the value out of the `v={Name:Value}` a TextHandler writes.
func structFieldValue(line string) string {
	const prefix = "v={"
	i := strings.Index(line, prefix)
	if i < 0 {
		return "<no field>"
	}
	rest := strings.TrimRight(line[i+len(prefix):], "\n")
	return valueAfterColon(strings.TrimSuffix(rest, "}"))
}

// mapFieldValue pulls the single entry's value out of the `v=map[Name:Value]` a
// TextHandler writes. The trailing bracket trimmed is the map wrapper's, so the
// suffix of a masked value like [REDACTED] inside it survives.
func mapFieldValue(line string) string {
	const prefix = "v=map["
	i := strings.Index(line, prefix)
	if i < 0 {
		return "<no field>"
	}
	rest := strings.TrimRight(line[i+len(prefix):], "\n")
	return valueAfterColon(strings.TrimSuffix(rest, "]"))
}

// valueAfterColon drops the field name, since the struct side is spelled in Go and
// the map side in the caller's key.
func valueAfterColon(s string) string {
	if _, v, ok := strings.Cut(s, ":"); ok {
		return v
	}
	return s
}

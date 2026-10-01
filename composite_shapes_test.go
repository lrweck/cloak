package cloak_test

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/lrweck/cloak"
)

// Composite shapes nest in ways that are easy to get wrong. Every case here asserts the
// one property that matters: the value does not reach the sink.

func logComposite(t *testing.T, attr slog.Attr) string {
	t.Helper()
	var b bytes.Buffer
	logger := slog.New(cloak.New(slog.NewJSONHandler(&b, nil),
		cloak.WithDefaultPII(), cloak.WithCompositeScan()))
	logger.Info("m", attr)
	return b.String()
}

func logCompositeText(t *testing.T, attr slog.Attr) string {
	t.Helper()
	var b bytes.Buffer
	logger := slog.New(cloak.New(slog.NewTextHandler(&b, nil),
		cloak.WithDefaultPII(), cloak.WithCompositeScan()))
	logger.Info("m", attr)
	return b.String()
}

func assertNoLeak(t *testing.T, got string, leaked ...string) {
	t.Helper()
	for _, s := range leaked {
		if strings.Contains(got, s) {
			t.Errorf("leaked %q: %s", s, got)
		}
	}
}

func TestMapWithStructKey(t *testing.T) {
	// TextHandler, because slog's JSONHandler rejects a struct map key outright,
	// with or without cloak.
	got := logCompositeText(t, slog.Any("m", map[keyStruct]any{
		{Email: "john@example.com"}: "v",
	}))
	assertNoLeak(t, got, "john@example.com")
	if !strings.Contains(got, ":v") {
		t.Errorf("value dropped: %s", got)
	}
}

// A LogValuer key masks to a different type than the key holds. Reusing the original
// key would leak; stringifying it in place used to panic.
func TestMapKeyThatCannotBeRepresented(t *testing.T) {
	got := logComposite(t, slog.Any("m", map[lvKey]any{
		{Contact: resolved{raw: "john@example.com"}}: "v",
	}))
	assertNoLeak(t, got, "john@example.com")
	if !strings.Contains(got, `"v"`) {
		t.Errorf("entry dropped: %s", got)
	}
}

// Masking a key can make two distinct keys equal, so entries may merge. That is the
// price of masking keys; nothing may leak.
func TestMapKeyCollision(t *testing.T) {
	got := logComposite(t, slog.Any("m", map[resolved]string{
		{raw: "john@example.com"}: "first",
		{raw: "jane@example.com"}: "second",
	}))
	assertNoLeak(t, got, "john@example.com", "jane@example.com")
}

func TestSliceOfStructs(t *testing.T) {
	got := logComposite(t, slog.Any("s", []account{{ID: 1, Email: "john@example.com"}}))
	assertNoLeak(t, got, "john@example.com")
	if !strings.Contains(got, `"ID":1`) {
		t.Errorf("element lost its fields: %s", got)
	}
}

func TestNestedMaps(t *testing.T) {
	got := logComposite(t, slog.Any("m", map[string]map[string]account{
		"outer": {"inner": {ID: 1, Email: "john@example.com"}},
	}))
	assertNoLeak(t, got, "john@example.com")
}

func TestSliceOfSlices(t *testing.T) {
	got := logComposite(t, slog.Any("s", [][]string{{"a@b.com"}, {"c@d.com"}}))
	assertNoLeak(t, got, "a@b.com", "c@d.com")
}

func TestMapOfSlices(t *testing.T) {
	got := logComposite(t, slog.Any("m", map[string][]string{"k": {"a@b.com"}}))
	assertNoLeak(t, got, "a@b.com")
}

func TestSliceOfMaps(t *testing.T) {
	got := logComposite(t, slog.Any("s", []map[string]any{{"contact": "a@b.com"}}))
	assertNoLeak(t, got, "a@b.com")
}

func TestMapWithAnyKey(t *testing.T) {
	got := logComposite(t, slog.Any("m", map[any]any{42: "a@b.com"}))
	assertNoLeak(t, got, "a@b.com")
}

func TestDeepMixedNesting(t *testing.T) {
	type deep struct {
		Rows []map[string][]account
	}
	got := logComposite(t, slog.Any("d", deep{
		Rows: []map[string][]account{{"k": {{ID: 1, Email: "a@b.com"}}}},
	}))
	assertNoLeak(t, got, "a@b.com")
}

// A cycle must not hang the logger. The depth ceiling stops the walk; the email is
// masked at the first level it is reached.
func TestSelfReferentialStruct(t *testing.T) {
	type node struct {
		Name  string
		Email string
		Next  *node
	}
	n := &node{Name: "a", Email: "john@example.com"}
	n.Next = n

	got := logComposite(t, slog.Any("n", n))
	assertNoLeak(t, got, "john@example.com")
}

func TestPointerToStructKey(t *testing.T) {
	got := logComposite(t, slog.Any("m", map[*account]any{
		{ID: 1, Email: "a@b.com"}: "v",
	}))
	assertNoLeak(t, got, "a@b.com")
}

type keyStruct struct {
	Email string
}

type lvKey struct {
	Contact resolved
}

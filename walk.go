package cloak

import (
	"fmt"
	"log/slog"
	"reflect"
)

// Walk depth ceiling. A self-referential structure (a linked list, a tree holding a
// parent pointer) is walked at most this deep, so a cyclic value cannot hang the
// logger. Past the limit the value is replaced by its fmt form and left unmasked.
//
// ponytail: no cycle detection, because depth is cheaper and bounds the damage for
// the pathological case. Raise it if you legitimately nest deeper than 32 levels.
const maxWalkDepth = 32

// walkCalls counts walk entries. Tests use it to assert that a handler with no
// composite option never reaches reflection.
var walkCalls int

// composite is a set of Go kinds that can carry nested data.
type composite uint8

const (
	compositeStruct composite = 1 << iota
	compositeMap
	compositeSlice
	compositePtr
)

// classify reports which kinds x belongs to, so each option is scoped to the shape it
// was asked about.
func classify(x any) composite {
	var c composite
	switch v := reflect.ValueOf(x); v.Kind() {
	case reflect.Struct:
		c |= compositeStruct
	case reflect.Map:
		c |= compositeMap
	case reflect.Slice:
		// []byte is data, not a container of things to log. Walking it would
		// rewrite a payload into decimal digits.
		if v.Type().Elem().Kind() != reflect.Uint8 {
			c |= compositeSlice
		}
	case reflect.Pointer:
		c |= compositePtr
	}
	return c
}

// scans reports whether a value of this shape should be walked. Callers must check
// c.scan != 0 first: this is what touches reflect.
func (c *config) scans(x any) bool { return classify(x)&c.scan != 0 }

// walk masks PII anywhere inside a composite value.
//
// slog.LogValuer is resolved first, because a value that knows how to log itself has
// already decided what it exposes. Masking the raw struct instead would ignore the
// author's intent and, worse, miss the string they actually meant to emit.
//
// A copy is built only when something changes, so an untouched value keeps its
// original type and is handed on by identity.
func (h *Handler) walk(x any, depth int) (any, bool) {
	walkCalls++
	if depth > maxWalkDepth {
		return fmt.Sprintf("%+v", x), false
	}
	if lv, ok := x.(slog.LogValuer); ok {
		return h.walkValue(lv.LogValue().Resolve(), depth+1)
	}
	// A value rule before the reflect switch, so it sees the value rather than the
	// container around it. Skip list is not consulted here: the walk has already
	// descended past a key the caller asked to leave alone.
	if len(h.cfg.rules) > 0 {
		if out, ok := h.valueRule(slog.AnyValue(x)); ok {
			return out, true
		}
	}
	// A type rule before the reflect switch, so a named type is caught wherever it
	// sits: a slice element, a map value, anything reach() descends into.
	if len(h.cfg.typeMasks) > 0 {
		if m, ok := h.cfg.typeMasks[reflect.TypeOf(x)]; ok {
			return m(slog.AnyValue(x)), true
		}
	}

	v := reflect.ValueOf(x)
	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() {
			return x, false
		}
		out, changed := h.walk(v.Elem().Interface(), depth+1)
		if !changed {
			return x, false
		}
		cv := convert(out, v.Type().Elem())
		if !cv.IsValid() {
			return x, false
		}
		// A new pointer: the walked element may no longer fit the old one's
		// address, and reusing it would alias the caller's data.
		p := reflect.New(v.Type().Elem())
		p.Elem().Set(cv)
		return p.Interface(), true

	case reflect.Struct:
		return h.walkStruct(v, depth)

	case reflect.Map:
		return h.walkMap(v, depth)

	case reflect.Slice:
		return h.walkSlice(v, depth)

	case reflect.String:
		if s, ok := h.maskString(v.String()); ok {
			return s, true
		}
	}
	return x, false
}

// walkValue handles an already-resolved [slog.Value], so a LogValuer result is masked
// by the same path as a literal.
func (h *Handler) walkValue(v slog.Value, depth int) (any, bool) {
	switch v.Kind() {
	case slog.KindGroup:
		src := v.Group()
		// Prefix copy, as in attr: an untouched group keeps its backing array,
		// so walking one that matches nothing allocates nothing.
		var dst []slog.Attr
		changed := false
		for i, ga := range src {
			out, c := h.walkField(ga.Key, "", ga.Value, depth+1)
			if c && !changed {
				dst = append(make([]slog.Attr, 0, len(src)), src[:i]...)
				changed = true
			}
			if changed {
				dst = append(dst, slog.Attr{Key: ga.Key, Value: out})
			}
		}
		if !changed {
			return v, false
		}
		return slog.GroupValue(dst...), true

	case slog.KindString:
		if s, ok := h.maskString(v.String()); ok {
			return slog.StringValue(s), true
		}

	case slog.KindLogValuer:
		// A LogValuer is resolved before anything else is decided: a value that
		// knows how to log itself has already chosen what it exposes, and
		// masking the struct behind it would miss the string it emits.
		return h.walkValue(v.Resolve(), depth+1)

	case slog.KindAny:
		// Resolve would hand back the same KindAny forever, so unwrap it.
		return h.walk(v.Any(), depth+1)
	}
	return v, false
}

// walkField applies key rules before walking, so a field named "password" is masked
// as a whole instead of scanned for values it happens to contain.
//
// tag is the field's struct tag value under the configured tag key, empty when the
// field carries none.
func (h *Handler) walkField(name, tag string, v slog.Value, depth int) (slog.Value, bool) {
	if m, ok := h.cfg.maskerForKey(name); ok {
		return m(v.Resolve()), true
	}
	if m, ok := h.cfg.maskerForTag(tag); ok {
		return m(v.Resolve()), true
	}
	if m, ok := h.cfg.maskerForType(v); ok {
		return m(v.Resolve()), true
	}
	if h.cfg.skipKey(name) {
		return v, false
	}
	// A value rule here as well as in walk, because a struct field reaches this path
	// rather than the reflect switch walk uses. A rule that declines runs twice,
	// which costs a call and changes nothing: the first to offer a replacement ends
	// it.
	if len(h.cfg.rules) > 0 && v.Kind() != slog.KindGroup {
		if out, ok := h.valueRule(v); ok {
			return out, true
		}
	}
	out, changed := h.walkValue(v, depth+1)
	if !changed {
		return v, false
	}
	sv, ok := out.(slog.Value)
	if !ok {
		return slog.AnyValue(out), true
	}
	return sv, true
}

// walkStruct returns a masked copy of a struct, or the original when nothing matched.
//
// Fields that cannot be represented in the output are dropped rather than copied:
// unexported fields, and fields tagged slog:"-". Unexported fields are the important
// case. encoding/json ignores them, but slog's TextHandler renders a struct with "%+v",
// which prints them, so copying one through would hand the value straight to the sink:
//
//	slog.Info("m", "a", struct{ pw string }{pw: "hunter2"})
//	// TextHandler: a="{pw:hunter2}"   <- the leak this avoids
//
// reflect cannot write an unexported field either, so leaving it zero is the only
// option that does not copy it — and it is what encoding/json would have produced
// anyway. A struct carrying one of these fields therefore always rebuilds, even when no
// rule matched, because the rebuild is the point.
//
// When a masked field no longer fits its declared type — which is what happens to a
// [slog.LogValuer] field, since its LogValue returns a different type than the field
// holds — the struct cannot be rebuilt in place. In that case the result is a
// [slog.Value] group carrying the same fields, which logs identically.
func (h *Handler) walkStruct(v reflect.Value, depth int) (any, bool) {
	t := v.Type()
	dst := reflect.New(t).Elem()

	// dirty records that dst no longer equals v, which is not only about masking:
	// a zeroed field is a change too.
	dirty := false
	shaped := true
	attrs := make([]slog.Attr, 0, t.NumField())
	for i := range t.NumField() {
		f := t.Field(i)
		if !dst.Field(i).CanSet() || f.Tag.Get("slog") == "-" {
			dirty = true
			continue
		}
		out, c := h.walkField(f.Name, h.cfg.tagValue(f), slog.AnyValue(v.Field(i).Interface()), depth+1)
		if !c {
			dst.Field(i).Set(v.Field(i))
			// Unconditional: attrs is the group when the struct cannot keep its
			// shape, and a field skipped after the shape broke would vanish from
			// the record. The boxing costs one allocation per field on a path
			// that already rebuilds; dropping a field costs data.
			attrs = append(attrs, slog.Any(f.Name, v.Field(i).Interface()))
			continue
		}
		dirty = true
		attrs = append(attrs, slog.Any(f.Name, out))
		if cv := convert(out, f.Type); cv.IsValid() {
			dst.Field(i).Set(cv)
		} else {
			shaped = false
		}
		// A changed pointer field widens to the group too. The masking behind it
		// is correct either way, but fmt renders a nested pointer as an address,
		// so a struct keeping one would reach a TextHandler as 0x... with nothing
		// showing a rule fired. A group renders the pointed-to value instead.
		// Untouched pointers stay untouched: rebuilding for readability alone
		// would break the passthrough the quiet path promises.
		if f.Type.Kind() == reflect.Pointer {
			shaped = false
		}
	}
	if !dirty {
		return v.Interface(), false
	}
	if !shaped {
		return slog.GroupValue(attrs...), true
	}
	return dst.Interface(), true
}

// walkMap masks both keys and values, so "email" -> "john@example.com" is caught by
// key and a bare address used as a value is caught by the detectors.
//
// When a masked key cannot be represented in the map's key type the whole map widens
// to map[string]any. The alternative — keeping the original key — would leak, and
// stringifying the key in place is not an option either: a map panics on a
// non-assignable key, and two masked keys that print alike would collide and silently
// drop an entry.
func (h *Handler) walkMap(v reflect.Value, depth int) (any, bool) {
	if v.IsNil() {
		return v.Interface(), false
	}
	dst := reflect.MakeMapWithSize(v.Type(), v.Len())
	wide := make(map[string]any, v.Len())
	changed, shaped := false, true
	// reflect.Value.Seq2, so map entries arrive through the range-over-func
	// protocol rather than a manual MapRange loop.
	for key, value := range v.Seq2() {
		maskedKey, kc := h.walk(key.Interface(), depth+1)

		// The key rule first, exactly as walkField does for a struct field, and
		// for the same reason: the name is the most specific statement of intent,
		// so it must not depend on whether a detector also happened to match.
		// Running the value first made map{"email": "a@b.com"} log a partially
		// masked address while struct{Email: "a@b.com"} logged the redaction the
		// preset asked for — the same rule over the same name, two answers.
		//
		// A key rule masks the value stored under the name, never the name:
		// masking the key would leave the value in the clear, which is the same
		// leak wearing a hat — map[[REDACTED]:hunter2] protects nothing.
		var maskedValue any
		vc := false
		switch m, named := h.mapKeyMasker(key); {
		case named:
			maskedValue, vc = m(slog.AnyValue(value.Interface())), true
		case key.Kind() == reflect.String && h.cfg.skipKey(key.String()):
			// The name was excluded from the value scan, as in walkField. The
			// order matches too: an explicit rule beats the skip list, so only an
			// entry no rule claimed is left alone here.
			maskedValue = value.Interface()
		default:
			// No name for the entry, so the value detectors and rules decide.
			maskedValue, vc = h.walk(value.Interface(), depth+1)
		}

		kv := key
		if kc {
			changed = true
			cv := convert(maskedKey, v.Type().Key())
			if cv.IsValid() {
				kv = cv
			} else {
				shaped = false
			}
		}
		vv := value
		if vc {
			changed = true
			if cv := convert(maskedValue, v.Type().Elem()); cv.IsValid() {
				vv = cv
			} else {
				shaped = false
			}
		}
		// A key that could not be represented keeps the original only where the
		// map is already widening; there it is rendered rather than leaked.
		if shaped || !kc {
			dst.SetMapIndex(kv, vv)
		}
		if kc {
			wide[fmt.Sprint(maskedKey)] = loose(maskedValue, vc, vv.Interface())
		} else {
			wide[key.String()] = loose(maskedValue, vc, vv.Interface())
		}
	}
	if !changed {
		return v.Interface(), false
	}
	if !shaped {
		return wide, true
	}
	return dst.Interface(), true
}

// mapKeyMasker returns the rule matching a map key. Only a string key can be named
// by a rule; a struct or pointer key has no name to match.
func (h *Handler) mapKeyMasker(key reflect.Value) (Masker, bool) {
	if key.Kind() != reflect.String {
		return nil, false
	}
	return h.cfg.maskerForKey(key.String())
}

// loose returns the masked value when there is one, and the original otherwise.
func loose(masked any, wasChanged bool, original any) any {
	if wasChanged {
		return masked
	}
	return original
}

// walkSlice masks each element, recursing so nested slices and slices of pointers
// work too.
func (h *Handler) walkSlice(v reflect.Value, depth int) (any, bool) {
	if v.IsNil() {
		return v.Interface(), false
	}
	dst := reflect.MakeSlice(v.Type(), v.Len(), v.Len())
	wide := make([]any, v.Len())
	changed, shaped := false, true
	// The integer range, since Seq yields elements without their index and dst.Index
	// needs one.
	for i := range v.Len() {
		elem := v.Index(i)
		// Boxed once: wide reuses the same any walk consumed.
		ei := elem.Interface()
		out, c := h.walk(ei, depth+1)
		wide[i] = loose(out, c, ei)

		if !c {
			dst.Index(i).Set(elem)
			continue
		}
		changed = true
		if cv := convert(out, v.Type().Elem()); cv.IsValid() {
			dst.Index(i).Set(cv)
			continue
		}
		// The element type cannot hold what masking produced — a []LogValuer,
		// for instance. Keeping the original would leak, so widen the slice
		// instead and let the field type follow.
		shaped = false
		dst.Index(i).Set(elem)
	}
	if !changed {
		return v.Interface(), false
	}
	if !shaped {
		return wide, true
	}
	return dst.Interface(), true
}

// convert turns a walked value back into the type the container requires, so a struct
// field or slice element keeps its declared type after masking.
func convert(x any, t reflect.Type) reflect.Value {
	// A walked value comes back as a slog.Value; unwrap it to the Go value the
	// container expects, so a named string field stays that named string type.
	if sv, ok := x.(slog.Value); ok {
		x = sv.Any()
	}
	v := reflect.ValueOf(x)
	if !v.IsValid() || !v.Type().AssignableTo(t) {
		return reflect.Value{}
	}
	return v
}

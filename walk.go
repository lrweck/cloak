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
		dst := make([]slog.Attr, len(src))
		changed := false
		for i, ga := range src {
			out, c := h.walkField(ga.Key, ga.Value, depth+1)
			dst[i] = slog.Attr{Key: ga.Key, Value: out}
			changed = changed || c
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
func (h *Handler) walkField(name string, v slog.Value, depth int) (slog.Value, bool) {
	if m, ok := h.cfg.maskerFor(normalizeKey(name)); ok {
		return m(v.Resolve()), true
	}
	if _, skip := h.cfg.skip[normalizeKey(name)]; skip {
		return v, false
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
// When a masked field no longer fits its declared type — which is what happens to a
// [slog.LogValuer] field, since its LogValue returns a different type than the field
// holds — the struct cannot be rebuilt in place. In that case the result is a
// [slog.Value] group carrying the same fields, which logs identically.
func (h *Handler) walkStruct(v reflect.Value, depth int) (any, bool) {
	t := v.Type()
	dst := reflect.New(t).Elem()
	// Copy first, then overwrite only what changed. Unexported fields cannot be
	// Set at all, and this way they keep their original value for free.
	dst.Set(v)

	changed := false
	shaped := true
	attrs := make([]slog.Attr, 0, t.NumField())
	for i := range t.NumField() {
		f := t.Field(i)
		// Unexported fields cannot be read through reflection, so they keep the
		// value copied in above and are neither walked nor re-emitted.
		if f.Tag.Get("slog") == "-" || !v.Field(i).CanInterface() {
			continue
		}
		out, c := h.walkField(f.Name, slog.AnyValue(v.Field(i).Interface()), depth+1)
		if !c {
			if shaped {
				attrs = append(attrs, slog.Any(f.Name, v.Field(i).Interface()))
			}
			continue
		}
		changed = true
		attrs = append(attrs, slog.Any(f.Name, out))
		if !dst.Field(i).CanSet() {
			shaped = false
			continue
		}
		if cv := convert(out, f.Type); cv.IsValid() && cv.Type() == f.Type {
			dst.Field(i).Set(cv)
		} else {
			shaped = false
		}
	}
	if !changed {
		return v.Interface(), false
	}
	if !shaped {
		return slog.GroupValue(attrs...), true
	}
	return dst.Interface(), true
}

// walkMap masks both keys and values, so "email" -> "john@example.com" is caught by
// key and a bare address used as a value is caught by the detectors.
func (h *Handler) walkMap(v reflect.Value, depth int) (any, bool) {
	if v.IsNil() {
		return v.Interface(), false
	}
	dst := reflect.MakeMapWithSize(v.Type(), v.Len())
	wide := make(map[string]any, v.Len())
	changed, shaped := false, true
	for iter := v.MapRange(); iter.Next(); {
		key, value := iter.Key(), iter.Value()

		maskedKey, kc := h.walk(key.Interface(), depth+1)
		maskedValue, vc := h.walk(value.Interface(), depth+1)

		kv := key
		if kc {
			changed = true
			if cv := convert(maskedKey, v.Type().Key()); cv.IsValid() {
				kv = cv
			} else {
				shaped = false
				kv = reflect.ValueOf(fmt.Sprint(maskedKey))
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
		dst.SetMapIndex(kv, vv)
		wide[fmt.Sprint(kv.Interface())] = loose(maskedValue, vc, vv.Interface())
	}
	if !changed {
		return v.Interface(), false
	}
	if !shaped {
		return wide, true
	}
	return dst.Interface(), true
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
	for i := range v.Len() {
		out, c := h.walk(v.Index(i).Interface(), depth+1)
		wide[i] = loose(out, c, v.Index(i).Interface())

		if !c {
			dst.Index(i).Set(v.Index(i))
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
		dst.Index(i).Set(v.Index(i))
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

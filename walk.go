package cloak

import (
	"fmt"
	"log/slog"
	"reflect"
	"time"
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
		// Nothing masked means the LogValuer keeps its own identity and resolves
		// downstream, so the original is returned rather than the resolution. Only
		// a change has to be boxed back into an any.
		out, changed := h.walkValue(lv.LogValue().Resolve(), depth+1)
		if !changed {
			return x, false
		}
		return out, true
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
//
// It returns a [slog.Value] rather than an any: the unchanged result is the value
// itself, and boxing a 32-byte slog.Value into an any costs an allocation on every
// field of every struct walked, including the ones nothing matched. The any is
// rebuilt only where a Go value genuinely came back from reflection.
func (h *Handler) walkValue(v slog.Value, depth int) (slog.Value, bool) {
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
		out, changed := h.walk(v.Any(), depth+1)
		if !changed {
			return v, false
		}
		// A walk may hand back a slog.Value (a group) or a rebuilt Go value.
		if sv, ok := out.(slog.Value); ok {
			return sv, true
		}
		return slog.AnyValue(out), true
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
	return out, true
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

	// dst is the copy being rebuilt, allocated at the first change rather than up
	// front, and attrs is the group fallback, built only once the struct cannot
	// keep its shape. A struct where nothing matched — the common case — must not
	// pay for a copy or a slice it discards.
	var dst reflect.Value
	var attrs []slog.Attr
	// groupFrom is the first index that has to appear in the group, or -1 while
	// the struct still has its shape.
	groupFrom := -1
	dirty := false
	shaped := true

	for i := range t.NumField() {
		f := t.Field(i)
		if f.PkgPath != "" || f.Tag.Get("slog") == "-" {
			// Unexported, or opted out: dropped rather than copied, because
			// TextHandler renders a struct with %+v and would print it.
			dirty = true
			if !dst.IsValid() {
				dst = structCopy(v, t, i)
			}
			if groupFrom < 0 {
				groupFrom, attrs = i, groupPrefix(dst, t, i)
			}
			continue
		}
		fv := v.Field(i)
		out, c := h.walkField(f.Name, h.cfg.tagValue(f), slog.AnyValue(fv.Interface()), depth+1)
		if !c {
			// Unchanged. dst carries the copy only if it was allocated before this
			// field; structCopy filled in whatever came earlier.
			if dst.IsValid() {
				dst.Field(i).Set(fv)
			}
			if groupFrom >= 0 {
				attrs = append(attrs, slog.Any(f.Name, fv.Interface()))
			}
			continue
		}
		dirty = true
		if !dst.IsValid() {
			// Every field below i is unchanged, or dst would already exist, so
			// copying them from v loses nothing masked.
			dst = structCopy(v, t, i)
		}
		if !maskInto(dst.Field(i), out, f.Type) {
			// The mask does not fit the declared type, so the struct cannot keep
			// its shape and the record becomes a group.
			if groupFrom < 0 {
				groupFrom, attrs = i, groupPrefix(dst, t, i)
			}
			shaped = false
		}
		// A changed pointer field widens to the group too. The masking behind it
		// is correct either way, but fmt renders a nested pointer as an address,
		// so a struct keeping one would reach a TextHandler as 0x... with nothing
		// showing a rule fired. A group renders the pointed-to value instead.
		// Untouched pointers stay untouched: rebuilding for readability alone
		// would break the passthrough the quiet path promises.
		if f.Type.Kind() == reflect.Pointer {
			if groupFrom < 0 {
				groupFrom, attrs = i, groupPrefix(dst, t, i)
			}
			shaped = false
		}
		// Appended last, so it lands after the prefix groupPrefix may just have
		// built, and only while the group is in play at all.
		if groupFrom >= 0 {
			attrs = append(attrs, slog.Any(f.Name, out))
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

// structCopy returns an addressable struct of t with v's fields [0,i) copied, so a
// rebuild that starts at i inherits the fields it has not rewritten. No index below i
// can be unexported: the walk stops at the first one, so the copies all succeed.
func structCopy(v reflect.Value, t reflect.Type, i int) reflect.Value {
	dst := reflect.New(t).Elem()
	for j := range i {
		dst.Field(j).Set(v.Field(j))
	}
	return dst
}

// groupPrefix boxes the fields a struct has already decided, for the moment it loses
// its shape. dst holds the right value for every index below i — the shape cannot
// have survived past the first unrepresentable field — so the prefix is rebuilt from
// the copy rather than from a second walk.
func groupPrefix(dst reflect.Value, t reflect.Type, i int) []slog.Attr {
	attrs := make([]slog.Attr, 0, t.NumField())
	for j := range i {
		attrs = append(attrs, slog.Any(t.Field(j).Name, dst.Field(j).Interface()))
	}
	return attrs
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

// maskInto stores a masked value into a field of the declared type, reporting whether
// it fit. It is convert plus the Set, with the kinds slog can hold written straight
// from the kind: convert would box the value into an any and read it back out, two
// allocations the common scalar cases never need.
//
// Only the predeclared types take the direct path. Anything else — a named string
// type, an interface — falls through to convert, which decides by assignability, so
// the two cannot disagree about what fits.
func maskInto(field reflect.Value, sv slog.Value, t reflect.Type) bool {
	if setScalar(field, sv, t) {
		return true
	}
	cv := convert(sv, t)
	if !cv.IsValid() {
		return false
	}
	field.Set(cv)
	return true
}

// setScalar writes a [slog.Value] into a field of exactly the type slog.Value.Any
// would have returned for that kind. Named types and interfaces return false.
func setScalar(field reflect.Value, sv slog.Value, t reflect.Type) bool {
	switch sv.Kind() {
	case slog.KindString:
		if t == reflect.TypeFor[string]() {
			field.SetString(sv.String())
			return true
		}
	case slog.KindInt64:
		if t == reflect.TypeFor[int64]() {
			field.SetInt(sv.Int64())
			return true
		}
	case slog.KindUint64:
		if t == reflect.TypeFor[uint64]() {
			field.SetUint(sv.Uint64())
			return true
		}
	case slog.KindFloat64:
		if t == reflect.TypeFor[float64]() {
			field.SetFloat(sv.Float64())
			return true
		}
	case slog.KindBool:
		if t == reflect.TypeFor[bool]() {
			field.SetBool(sv.Bool())
			return true
		}
	case slog.KindDuration:
		if t == reflect.TypeFor[time.Duration]() {
			field.SetInt(int64(sv.Duration()))
			return true
		}
	case slog.KindTime:
		if t == reflect.TypeFor[time.Time]() {
			field.Set(reflect.ValueOf(sv.Time()))
			return true
		}
	}
	return false
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

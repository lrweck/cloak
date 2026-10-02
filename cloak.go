// Package cloak provides a slog.Handler wrapper that masks sensitive values.
//
// Key-based masking is exact and cheap. Optional value detectors use a two-stage
// strategy: a small structural pre-filter first, followed by the exact
// validation required by the detector (for example, Luhn for PAN or check
// digits for CPF/CNPJ/SSN). This keeps the common logging path inexpensive and
// reduces false positives from arbitrary strings.
//
// # Naming
//
// Every option that takes a [Masker] takes it first:
//
//	cloak.WithKeys(cloak.KeepLast(4), "card_number")
//	cloak.WithKeysContaining(cloak.Redact, "password")
//	cloak.WithKeyRegex(cloak.Redact, `^x-.*-token$`)
//	cloak.WithTag(cloak.Redact, "cloak", "secret")
//	cloak.WithValuePredicate(cloak.Redact, pred)
//
// The reason is Go, not taste: the subject of a key rule is a variadic list, and a
// variadic parameter has to come last. A Masker in the last position is therefore
// impossible for exactly the options people reach for most. Putting it first gives
// one rule with no exceptions to remember.
//
// An option that takes several subjects says so in its name — [WithKeys],
// [WithKeysContaining]. One that takes a single pattern or a single tag does not.
package cloak

import (
	"context"
	"log/slog"
	"reflect"
	"slices"
	"strings"
	"unicode/utf8"
)

// Placeholder is the replacement a [Handler] uses for a fully redacted value unless
// [WithRedactedValue] says otherwise.
const Placeholder = "[REDACTED]"

type Masker func(slog.Value) slog.Value

// Redact replaces a value entirely. It is the request for a full redaction rather than
// a message of its own: inside a handler the replacement is that handler's redacted
// value, which [WithRedactedValue] sets. Called outside one, it falls back to
// [Placeholder].
//
// Partial maskers like [KeepLast] are unaffected, since they state their own output.
func Redact(v slog.Value) slog.Value { return slog.StringValue(Placeholder) }

// redactPtr identifies Redact so a handler can recognise the request and answer it with
// its own message. Sound only because Redact is a package-level function with no
// captures, so two references to it are the same function. The reasoning does not hold
// for a masker built from a literal: two closures from one literal share a code pointer
// while behaving differently, which is why maskers are never compared this way.
var redactPtr = reflect.ValueOf(Redact).Pointer()

func isRedact(m Masker) bool { return reflect.ValueOf(m).Pointer() == redactPtr }

// WithRedactedValue sets what a fully redacted value is replaced with.
//
//	cloak.NewPCI(next, cloak.WithRedactedValue("***"))
//
// It is a property of the handler rather than of any rule: every request for a full
// redaction answers with this string, whatever asked for it — a key rule, a tag, a
// type, a pattern, or one of the presets. Partial maskers keep their own output, since
// [KeepLast] and friends state exactly what they produce.
func WithRedactedValue(msg string) Options {
	return option(func(c *config) { c.redacted = msg })
}

func Fixed(marker string) Masker {
	return func(slog.Value) slog.Value { return slog.StringValue(marker) }
}

func KeepLast(n int) Masker {
	if n < 0 {
		n = 0
	}
	return func(v slog.Value) slog.Value {
		r := []rune(v.String())
		if len(r) <= n {
			return slog.StringValue(strings.Repeat("*", len(r)))
		}
		return slog.StringValue(strings.Repeat("*", len(r)-n) + string(r[len(r)-n:]))
	}
}

func KeepFirst(n int) Masker {
	if n < 0 {
		n = 0
	}
	return func(v slog.Value) slog.Value {
		r := []rune(v.String())
		if len(r) <= n {
			return slog.StringValue(strings.Repeat("*", len(r)))
		}
		return slog.StringValue(string(r[:n]) + strings.Repeat("*", len(r)-n))
	}
}

func KeepEnds(first, last int) Masker {
	if first < 0 {
		first = 0
	}
	if last < 0 {
		last = 0
	}
	return func(v slog.Value) slog.Value {
		r := []rune(v.String())
		if first+last >= len(r) {
			return slog.StringValue(strings.Repeat("*", len(r)))
		}
		return slog.StringValue(string(r[:first]) + strings.Repeat("*", len(r)-first-last) + string(r[len(r)-last:]))
	}
}

func MaskMiddle(first, last int) Masker { return KeepEnds(first, last) }

type ValueFunc func(string) (string, bool)

type rule struct {
	part   string
	masker Masker
}

type config struct {
	keys map[string]Masker
	skip map[string]struct{}
	// redacted is the instance's replacement for a full redaction, resolved by
	// finalize once the options have all been applied.
	redacted string
	// rules are value rules, which see a value of any kind.
	rules    []ValueRule
	values   []ValueFunc
	contains []rule
	// scanMessage runs the value detectors over the log message itself, which is
	// where unstructured text usually leaks.
	scanMessage bool
	// scan is the set of composite kinds to walk by reflection. Zero means no
	// reflection happens at all, which keeps reflect off the default path.
	scan composite
	// ctxPulls produce attributes from the context, masked like any others.
	ctxPulls []func(context.Context) []slog.Attr
	// tagMasks match a struct field by tag, which survives a rename in a way a
	// field name does not.
	tagMasks []tagMask
	// typeMasks match a value by its Go type, which is decided at compile time by
	// the type itself rather than by a name someone has to remember.
	typeMasks map[reflect.Type]Masker
	// regexKeys are key patterns, resolved at configuration time.
	regexKeys []regexKey
	// Indexes so a rule declared twice replaces rather than accumulates. Each holds
	// the position in its slice: that keeps the first matching rule winning between
	// distinct patterns, while the newest masker wins for the same one.
	containsIdx map[string]int
	tagIdx      map[tagID]int
	regexIdx    map[string]int
	// keyHash is the foldHash of every exact name the config can match: registered
	// keys and skip entries, which are all stored normalized. A name needing a fold
	// whose hash is absent cannot match either, so the miss path never materializes
	// the folded form. Nil before finalize runs, which only internal tests observe.
	keyHash map[uint64]struct{}
	// builtins tracks which of the library's own detectors are installed, so a
	// preset composed twice does not scan twice.
	builtins uint32
}

type tagID struct{ key, value string }

type tagMask struct {
	key, value string
	masker     Masker
}

// WithType masks every value whose Go type is exactly T.
//
//	type EmailAddr string
//	type Password string
//
//	cloak.WithType[EmailAddr](), cloak.WithType[Password](cloak.KeepLast(0))
//
// This is the strongest rule available and the cheapest to use correctly. The
// compiler refuses to pass a type that does not exist, the value cannot be logged
// under a name you forgot to add to a preset, and there are no false positives: a
// Password is masked wherever it is, and nothing else is.
//
// It applies wherever the value appears: as an attribute, a struct field, a map
// value or a slice element. Values of a named type are not KindString to slog, so
// this also reaches types the value detectors cannot see.
//
// With no masker, the value is fully redacted.
//
// Precedence: an explicit key rule wins over a type rule, and a type rule wins over
// the value detectors.
func WithType[T any](maskers ...Masker) Options {
	m := Redact
	if len(maskers) > 0 && maskers[0] != nil {
		m = maskers[0]
	}
	t := reflect.TypeFor[T]()
	return option(func(c *config) {
		if c.typeMasks == nil {
			c.typeMasks = make(map[reflect.Type]Masker)
		}
		c.typeMasks[t] = m
	})
}

// maskerForType returns the rule matching a value's exact Go type, if any.
func (c *config) maskerForType(v slog.Value) (Masker, bool) {
	if len(c.typeMasks) == 0 {
		return nil, false
	}
	// A LogValuer must be resolved first: its type is not what gets logged.
	if v.Kind() == slog.KindLogValuer {
		v = v.Resolve()
	}
	if v.Kind() != slog.KindAny {
		return nil, false
	}
	m, ok := c.typeMasks[reflect.TypeOf(v.Any())]
	return m, ok
}

// WithContain masks any value that contains one of the given strings, wherever it
// appears.
//
//	cloak.WithContain("s3cr3t-token")
//
// It solves the problem the other rules cannot: you know the secret but not where it
// will be logged. A token spliced into a URL, an error message quoting a response
// body, an auth header assembled by a client — none of those carry a field name worth
// matching, and the value detectors have no idea what your token looks like.
//
// It is a value rule, so it applies to the message, to attribute values, and
// everywhere the composite walk descends. Matching is case sensitive, since a secret
// is a specific byte sequence. The whole value is replaced rather than the substring,
// because the rest of the value may be sensitive too.
//
// Empty secrets are ignored: an empty needle matches everything, which would silence
// every log line.
func WithContain(secrets ...string) Options {
	return option(func(c *config) {
		needles := make([]string, 0, len(secrets))
		for _, s := range secrets {
			if s != "" {
				needles = append(needles, s)
			}
		}
		if len(needles) == 0 {
			return
		}
		// Ahead of the format detectors: a known secret is a more certain match than
		// anything inferred from the shape of the value.
		c.values = slices.Insert(c.values, 0, func(s string) (string, bool) {
			for _, needle := range needles {
				if strings.Contains(s, needle) {
					return c.redacted, true
				}
			}
			return s, false
		})
	})
}

// WithTag masks a struct field carrying the given struct tag.
//
//	type Account struct {
//	    ID       int
//	    Password string `cloak:"secret"`
//	}
//
//	cloak.WithTag(cloak.Redact, "cloak", "secret")
//
// A tag is the most durable way to mark a field: renaming the field does not lose the
// rule, and the intent sits on the field rather than in the logger's configuration.
//
// Rules for different tag keys can coexist, since the key is part of each rule. A field
// matching no rule is walked normally.
func WithTag(m Masker, key, value string) Options {
	return option(func(c *config) { c.addTag(tagID{key, value}, m) })
}

// addTag registers a tag rule, replacing one already registered for the same tag key
// and value.
func (c *config) addTag(id tagID, m Masker) {
	if i, ok := c.tagIdx[id]; ok {
		c.tagMasks[i].masker = m
		return
	}
	if c.tagIdx == nil {
		c.tagIdx = make(map[tagID]int)
	}
	c.tagIdx[id] = len(c.tagMasks)
	c.tagMasks = append(c.tagMasks, tagMask{key: id.key, value: id.value, masker: m})
}

// maskerForTag returns the rule matching a field's tag value, if any.
func (c *config) maskerForTag(tag string) (Masker, bool) {
	if tag == "" {
		return nil, false
	}
	for _, t := range c.tagMasks {
		if t.value == tag {
			return t.masker, true
		}
	}
	return nil, false
}

// tagValue reads the tag on a struct field that any rule is watching. It scans the
// configured keys in order and returns the first hit, so a field carrying several of
// them resolves predictably.
func (c *config) tagValue(f reflect.StructField) string {
	for _, t := range c.tagMasks {
		if v := f.Tag.Get(t.key); v != "" {
			return v
		}
	}
	return ""
}

// WithContextAttrs registers functions that pull values out of the context and copy
// them onto every record, masked by the same rules as attributes you logged yourself.
//
// It exists because a value carried in the context is attached once, usually far from
// the log call that will expose it:
//
//	ctx = context.WithValue(ctx, userKey, user)     // middleware, no logging in sight
//	slog.InfoContext(ctx, "loaded")                // somewhere else, entirely
//
// A pull function rather than a key, because the idiomatic context key is a private
// type: naming it from outside the package that owns it does not compile, and
// exporting it just to configure a logger gives up the collision safety that makes the
// private type worth having. The closure lives where the key is reachable, so the key
// never leaves its package:
//
//	// package auth
//	func LogAttrs(ctx context.Context) []slog.Attr {
//	    u, ok := userFrom(ctx)          // uses the unexported key
//	    if !ok {
//	        return nil
//	    }
//	    return []slog.Attr{slog.Any("user", u)}
//	}
//
//	// package main
//	cloak.WithContextAttrs(auth.LogAttrs)
//
// Masking is not special-cased: a key rule, a detector, a composite walk and
// LogValuer precedence all apply exactly as they would to an attribute you logged
// yourself. Return nil for anything absent, so a missing value is skipped rather than
// logged as null.
//
// It also suits sources that are not context values at all, such as request-scoped
// state kept by a web framework.
func WithContextAttrs(pulls ...func(context.Context) []slog.Attr) Options {
	return option(func(c *config) { c.ctxPulls = append(c.ctxPulls, pulls...) })
}

// normalizeKey folds case and drops the separators, so card_number, cardNumber,
// CARD-NUMBER and "Card Number" are one key.
//
// Most keys in a real log are already normalized, and a builder allocated for every
// attribute on every record is the largest single cost on the path where nothing
// matched. The fast path scans first and returns the input untouched, allocating
// nothing. An empty key has nothing to fold and returns as it came.
// isPlain reports whether s needs no folding: no separators, no uppercase. It is
// the scan normalizeKey would do anyway, exposed so the key lookup can decide
// whether folding is needed before paying for it.
func isPlain(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '_' || c == '-' || c == ' ' || c == '\t' ||
			(c >= 'A' && c <= 'Z') {
			return false
		}
	}
	return true
}

// foldHash is FNV-1a over the folded form, computed without materializing it. It is
// only a pre-filter for the exact-key lookup: a hit is always verified against the
// real key, so a collision costs one wasted fold, never a wrong rule.
func foldHash(s string) uint64 {
	const (
		offset = 14695981039346656037
		prime  = 1099511628211
	)
	h := uint64(offset)
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '_', '-', ' ', '\t':
			continue
		}
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		h ^= uint64(c)
		h *= prime
	}
	return h
}

func normalizeKey(s string) string {
	if isPlain(s) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '_', '-', ' ', '\t':
			continue
		}
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b.WriteByte(c)
	}
	return b.String()
}

// Options configures a Handler. One Options value carries either a single option or a
// set of them, following the shape encoding/json/v2 uses: opaque, composable, and
// impossible to construct from outside the package.
//
//	opt := cloak.WithDefaultPII()                  // one option
//	policy := cloak.JoinOptions(opt, opt2, opt3)    // a set, storable as a value
//
// Individual constructors return a single option; [JoinOptions] coalesces any number into
// one value that can be named, stored and passed around, which a slice of options cannot
// be. Properties set later override earlier ones, as everywhere else here.
type Options interface {
	apply(*config)
}

type option func(*config)

func (f option) apply(c *config) { f(c) }

// options is the combined form, so a joined value is one option rather than many.
type options []option

func (o options) apply(c *config) {
	for _, f := range o {
		f(c)
	}
}

// JoinOptions coalesces options into a single [Options] value, applied in order.
func JoinOptions(opts ...Options) Options {
	merged := make(options, 0, len(opts))
	for _, o := range opts {
		switch v := o.(type) {
		case nil:
			continue
		case options:
			merged = append(merged, v...)
		case *options:
			merged = append(merged, *v...)
		default:
			merged = append(merged, option(o.apply))
		}
	}
	return merged
}

// WithKeys masks attributes whose normalized key exactly matches one of keys.
//
//	cloak.WithKeys(cloak.Redact, "password", "cpf")
//	cloak.WithKeys(cloak.KeepLast(4), "card_number")
//
// Matching is on the normalized key, so card_number, cardNumber, CARD-NUMBER and
// "Card Number" are all the same rule from one entry.
func WithKeys(m Masker, keys ...string) Options {
	return option(func(c *config) {
		for _, k := range keys {
			c.keys[normalizeKey(k)] = m
		}
	})
}

// WithKeysContaining masks attributes whose normalized key contains one of keys as a
// substring. It catches the qualified names that exact matching misses, such as
// "db.password" or "headers.Authorization".
//
//	cloak.WithKeysContaining(cloak.Redact, "password")
//
// It is looser than [WithKeys]: "token" also matches "tokens_used". Keys holding
// unrelated data ("id", "name") make it a poor choice, so prefer [WithKeys] and reach
// for this only where the prefixes are known.
func WithKeysContaining(m Masker, keys ...string) Options {
	return option(func(c *config) {
		for _, k := range keys {
			c.addContains(normalizeKey(k), m)
		}
	})
}

// addContains registers a substring rule, replacing one already registered for the
// same part. Replacing rather than appending means the rule cannot be scanned twice,
// and the newest masker is the one that applies — the same last-wins behaviour
// WithKeys already has, since it is a map.
func (c *config) addContains(part string, m Masker) {
	if i, ok := c.containsIdx[part]; ok {
		c.contains[i].masker = m
		return
	}
	if c.containsIdx == nil {
		c.containsIdx = make(map[string]int)
	}
	c.containsIdx[part] = len(c.contains)
	c.contains = append(c.contains, rule{part: part, masker: m})
}

func WithValueFunc(f ValueFunc) Options {
	return option(func(c *config) {
		// A built-in handed over by name is the same function the presets install,
		// so mark it. Nothing else is compared, for the closure reason above.
		if b, ok := builtinByPtr[reflect.ValueOf(f).Pointer()]; ok {
			c.addBuiltins(b)
			return
		}
		c.values = append(c.values, f)
	})
}

// ValueRule inspects a value of any kind and returns its replacement, or reports that
// it has nothing to say. It mirrors [ValueFunc] exactly — same shape, same
// direction — so the two are one idea rather than two.
//
// Use it where a string detector cannot reach: an int, a duration, a time, a bool, or
// any value at all, including a struct reached through [slog.Any].
//
//	cloak.WithValueRule(func(v slog.Value) (slog.Value, bool) {
//	    if v.Kind() != slog.KindInt64 {
//	        return v, false
//	    }
//	    n := v.Int64()
//	    if n < 1_000_000_000_000 {
//	        return v, false
//	    }
//	    return slog.StringValue("[large]"), true
//	})
type ValueRule func(slog.Value) (slog.Value, bool)

// WithValueRule registers a rule over values of any kind.
//
// A rule runs after key, tag and type rules and before the format detectors, because
// a rule is a deliberate statement while a detector infers from the shape of a string.
// It is not applied to a group, since replacing one would discard its structure.
//
// [WithSkipValueScan] governs value rules as it does the detectors.
func WithValueRule(r ValueRule) Options {
	return option(func(c *config) { c.rules = append(c.rules, r) })
}

// WithValuePredicate masks a value of any kind when pred accepts it. It is
// [WithValueRule] for the common case where deciding and replacing are separate.
//
//	cloak.WithValuePredicate(cloak.Redact, func(v slog.Value) bool {
//	    return v.Kind() == slog.KindInt64 && v.Int64() > 1_000_000_000_000
//	})
func WithValuePredicate(m Masker, pred func(slog.Value) bool) Options {
	return WithValueRule(func(v slog.Value) (slog.Value, bool) {
		if !pred(v) {
			return v, false
		}
		return m(v), true
	})
}

// valueRule runs the rules in order and returns the first replacement offered.
func (h *Handler) valueRule(v slog.Value) (slog.Value, bool) {
	for _, r := range h.cfg.rules {
		if out, ok := r(v); ok {
			return out, true
		}
	}
	return v, false
}

// DefaultPIIValueFuncs returns the built-in detectors, in the order they must run.
//
// Two rules decide the order. Cheapest structural gate first, so a string that cannot
// possibly match costs one comparison. Most specific before least specific, because
// maskString chains: each detector sees the previous one's output.
//
// That chaining is why IPv4 must precede SSN. An IPv4 address like "192.168.1.42" is
// exactly nine digits and passes the SSN shape check, so SSN first turns the most
// common private address into "***-**-****" and leaves IPv4 nothing to match. Phone
// is last because it claims almost any number, documents included.
func DefaultPIIValueFuncs() []ValueFunc {
	out := make([]ValueFunc, 0, biCount)
	for _, f := range builtinFuncs {
		out = append(out, f)
	}
	return out
}

// builtin identifies one of the library's own detectors. The set is closed, and each
// member is a package-level function with no captures, which is what makes a bitmask
// an exact record of what is installed and makes pointer equality meaningful here.
type builtin uint8

const (
	biUUID builtin = iota
	biEmail
	biIPv4
	biIBAN
	biCPF
	biCNPJ
	biSSN
	biPAN
	biPhone
	biCount
)

// builtinFuncs is in detector order, which is what DefaultPIIValueFuncs hands back.
var builtinFuncs = [biCount]ValueFunc{MaskUUID, MaskEmail, MaskIPv4, MaskIBAN, MaskCPF, MaskCNPJ, MaskSSN, MaskPAN, MaskPhone}

// builtinByPtr identifies a built-in from a function value. Safe only for this set: two
// closures from the same literal share a code pointer while capturing different values,
// so comparing user detectors this way would treat KeepLast(4) and KeepLast(9) as the
// same rule and silently drop one.
var builtinByPtr = func() map[uintptr]builtin {
	m := make(map[uintptr]builtin, biCount)
	for i, f := range builtinFuncs {
		m[reflect.ValueOf(f).Pointer()] = builtin(i)
	}
	return m
}()

// addBuiltins installs detectors, skipping any already present. Composing two presets
// would otherwise scan every string twice, which is a plausible mistake given that
// WithDefaultPII already includes the detectors.
func (c *config) addBuiltins(bs ...builtin) {
	for _, b := range bs {
		bit := uint32(1) << b
		if c.builtins&bit != 0 {
			continue
		}
		c.builtins |= bit
		c.values = append(c.values, builtinFuncs[b])
	}
}

func WithDefaultPIIValues() Options {
	return option(func(c *config) { c.addBuiltins(biUUID, biEmail, biIPv4, biIBAN, biCPF, biCNPJ, biSSN, biPAN, biPhone) })
}

var DefaultPIIKeys = []string{
	"password", "passwd", "passcode", "passphrase", "pwd", "secret", "sharedsecret", "token",
	"accesstoken", "refreshtoken", "idtoken", "authtoken", "bearertoken", "apikey", "apisecret",
	"clientsecret", "authorization", "auth", "cookie", "setcookie", "session", "sessionid",
	"privatekey", "sshkey", "encryptionkey", "cpf", "cpfnumber", "cnpj", "cnpjnumber", "cpfcnpj",
	"document", "documentnumber", "documentid", "taxid", "taxpayerid", "nationalid",
	"nationalidentifier", "identitynumber", "identificationnumber", "passport", "passportnumber",
	"passportid", "driverlicense", "driverslicense", "licensenumber", "ssn",
	"socialsecuritynumber", "email", "emailaddress", "mail", "useremail", "contactemail", "phone",
	"phonenumber", "telephone", "telephonenumber", "tel", "mobile", "mobilephone", "mobilenumber",
	"cellphone", "cellphonenumber", "homephone", "workphone", "address", "addressline",
	"address1", "address2", "streetaddress", "postaladdress", "zip", "zipcode", "postalcode",
	"postcode", "cep", "complement", "addresscomplement", "dateofbirth", "birthdate", "dob",
	"creditcard", "creditcardnumber", "cardnumber", "pan", "primaryaccountnumber", "ccnumber",
	"cc", "cardno", "cvv", "cvc", "cid", "securitycode", "cardsecuritycode", "verificationcode",
	"bankaccount", "bankaccountnumber", "accountnumber", "acctnumber", "routingnumber",
	"sortcode", "iban", "bankiban",
}

func WithDefaultPIIKeys() Options { return WithKeys(Redact, DefaultPIIKeys...) }

func WithDefaultPII() Options {
	return option(func(c *config) {
		for _, k := range DefaultPIIKeys {
			c.keys[normalizeKey(k)] = Redact
		}
		c.addBuiltins(biUUID, biEmail, biIPv4, biIBAN, biCPF, biCNPJ, biSSN, biPAN, biPhone)
	})
}

// PCIKeys are the cardholder-data fields named by PCI DSS: the data that must never
// reach a log, as distinct from the many fields that merely describe a transaction.
var PCIKeys = []string{
	"pan", "primaryaccountnumber", "cardnumber", "creditcardnumber",
	"ccnumber", "accountnumber", "cardholdername", "expmonth", "expyear", "expirationdate",
	"expiry", "cvv", "cvc", "cid", "csc", "cvv2", "securitycode", "cardsecuritycode",
	"pin", "pinblock", "track1", "track2", "tracks", "servicecode", "cryptogram",
	"emv", "chipdata", "magstripe", "signature",
}

// GDPRKeys are the personal-data categories of the GDPR, as attribute names.
//
// The regulation names categories rather than fields, so this list is necessarily a
// guess about your schema. Treat it as a starting point and add your own: "name" is
// absent on purpose, since masking every name would make the logs useless.
var GDPRKeys = []string{
	// Identity and contact
	"email", "emailaddress", "contactemail", "phone", "phonenumber", "telephone",
	"telephonenumber", "mobile", "mobilenumber", "address", "addressline", "streetaddress",
	"postaladdress", "postcode", "zip", "zipcode", "postalcode", "cep", "geolocation",
	"latitude", "longitude", "gps", "ipaddress", "ip",
	// Government identifiers
	"ssn", "socialsecuritynumber", "cpf", "cnpj", "document", "documentnumber", "taxid",
	"nationalid", "nationalidentifier", "passport", "passportnumber", "driverlicense",
	"driverslicense", "licensenumber", "birthdate", "dateofbirth", "dob",
	// Financial
	"bankaccount", "bankaccountnumber", "accountnumber", "iban", "routingnumber",
	"sortcode", "swift", "creditcard", "cardnumber", "pan", "cvv", "cvc",
	// Special categories, article 9
	"health", "medical", "medicalrecord", "diagnosis", "prescription", "disability",
	"genetic", "biometric", "biometricdata", "political", "politicalopinion",
	"religion", "religious", "sexualorientation", "tradeunion", "unionmembership",
}

// WithPCI enables the cardholder-data fields PCI DSS forbids in logs, plus the PAN
// detector so a card number is caught even under a field name you did not anticipate.
//
// It does not mask every field that mentions money — amounts, currencies and merchant
// descriptors are not cardholder data, and masking them would cost you the transaction
// history that makes a log useful.
func WithPCI() Options {
	return option(func(c *config) {
		for _, k := range PCIKeys {
			c.keys[normalizeKey(k)] = Redact
		}
		// PAN only: the other format detectors are not cardholder data and their
		// false positives would cost more than they protect here.
		c.addBuiltins(biPAN)
	})
}

// LGPDKeys is [GDPRKeys] under its Brazilian name. The two laws name the same
// categories, so this is the same list rather than a parallel one that could drift.
var LGPDKeys = GDPRKeys

// WithLGPD is [WithGDPR] under its Brazilian name, for code that already speaks
// LGPD.
func WithLGPD() Options { return WithGDPR() }

// WithGDPR enables the personal-data categories named by the GDPR.
//
// It is a starting point rather than a compliance claim: the regulation names
// categories, and only your schema says which attribute holds each one. Review it, and
// add whatever your domain calls something else.
func WithGDPR() Options {
	return option(func(c *config) {
		for _, k := range GDPRKeys {
			c.keys[normalizeKey(k)] = Redact
		}
		// In detector order, not a hand-written one: IPv4 before SSN, since a
		// dotted-quad is nine digits and SSN would swallow it. MaskPhone is left
		// out because the key list already covers phone fields and its heuristic
		// would mask IDs and timestamps.
		c.addBuiltins(biEmail, biIPv4, biCPF, biCNPJ, biSSN)
	})
}

func WithSkipValueScan(keys ...string) Options {
	return option(func(c *config) {
		for _, k := range keys {
			c.skip[normalizeKey(k)] = struct{}{}
		}
	})
}

// WithMessageScan also runs the value detectors over the log message.
//
// Attributes are opt-in per key, but the message is free text nobody reviews, and
// `slog.Info("login for "+email)` is a routine way to leak. It is off by default
// because rewriting the message surprises readers and costs a scan per record.
func WithMessageScan() Options {
	return option(func(c *config) { c.scanMessage = true })
}

// WithStructScan walks struct values logged through [slog.Any], masking PII in their
// fields by field name and by value.
//
// The value keeps its type: only the offending fields are replaced, so the record
// still logs a structured object.
//
//	cloak.WithStructScan()   // slog.Any("user", User{Email: ...})
func WithStructScan() Options {
	return option(func(c *config) { c.scan |= compositeStruct | compositePtr })
}

// WithMapScan walks map values logged through [slog.Any], masking both keys and values.
// A key match wins over the value detectors, so map[string]any{"password": "x"} is
// caught by name while a bare address is caught as a value.
//
//	cloak.WithMapScan()   // slog.Any("ctx", map[string]any{"email": ...})
func WithMapScan() Options {
	return option(func(c *config) { c.scan |= compositeMap | compositePtr })
}

// WithSliceScan walks slice values logged through [slog.Any], masking each element and
// recursing into nested containers.
//
// []byte is excluded: it is data, not a container of things to log, and walking it
// would rewrite a payload into decimal digits.
//
//	cloak.WithSliceScan()   // slog.Any("emails", []string{"a@example.com"})
func WithSliceScan() Options {
	return option(func(c *config) { c.scan |= compositeSlice | compositePtr })
}

// WithCompositeScan enables [WithStructScan], [WithMapScan] and [WithSliceScan] at
// once, and is what you want unless you have a reason to scope the walk.
//
// Pointers are always followed, since a pointer is just an address to the value behind
// it.
func WithCompositeScan() Options {
	return option(func(c *config) {
		c.scan |= compositeStruct | compositeMap | compositeSlice | compositePtr
	})
}

type Handler struct {
	next slog.Handler
	cfg  *config
}

func New(next slog.Handler, opts ...Options) slog.Handler {
	c := &config{keys: make(map[string]Masker), skip: make(map[string]struct{})}
	for _, opt := range opts {
		opt.apply(c)
	}
	c.finalize()
	return &Handler{next: next, cfg: c}
}

// NewDefaultPII returns a handler masking the built-in key set and value detectors.
//
// It is New(next, WithDefaultPII()) with the compliance choice visible at the call
// site, which matters more here than for the other options because "what is
// sensitive" is a decision a reader of the code should be able to see:
//
//	slog.SetDefault(slog.New(cloak.NewDefaultPII(os.Stdout)))
//
// For a named regulation prefer [NewPCI], [NewGDPR] or [NewLGPD].
func NewDefaultPII(next slog.Handler, opts ...Options) slog.Handler {
	return New(next, append([]Options{WithDefaultPII()}, opts...)...)
}

// NewPCI returns a handler masking the cardholder data PCI DSS forbids in logs.
//
//	cloak.NewPCI(slog.NewJSONHandler(os.Stdout, nil), cloak.WithStructScan())
func NewPCI(next slog.Handler, opts ...Options) slog.Handler {
	return New(next, append([]Options{WithPCI()}, opts...)...)
}

// NewGDPR returns a handler masking the personal-data categories GDPR names.
//
//	cloak.NewGDPR(slog.NewJSONHandler(os.Stdout, nil))
func NewGDPR(next slog.Handler, opts ...Options) slog.Handler {
	return New(next, append([]Options{WithGDPR()}, opts...)...)
}

// NewLGPD is [NewGDPR] under its Brazilian name, for code that already speaks LGPD.
//
//	cloak.NewLGPD(slog.NewJSONHandler(os.Stdout, nil))
func NewLGPD(next slog.Handler, opts ...Options) slog.Handler {
	return New(next, append([]Options{WithLGPD()}, opts...)...)
}

func (h *Handler) Enabled(ctx context.Context, level slog.Level) bool {
	if h.next == nil {
		return false
	}
	return h.next.Enabled(ctx, level)
}

func (h *Handler) Handle(ctx context.Context, r slog.Record) error {
	if h.next == nil {
		return nil
	}
	// A fixed backing array, so a record that matches nothing never grows a heap
	// slice on the way to being discarded. 16 covers the overwhelming majority of
	// records; a wider one falls back to append and allocates, as it must.
	var stack [16]slog.Attr
	attrs := h.contextAttrs(ctx)
	if len(attrs) > 0 {
		merged := make([]slog.Attr, 0, len(attrs)+16)
		attrs = append(merged, attrs...)
	} else {
		attrs = stack[:0]
	}
	changed := len(attrs) > 0
	r.Attrs(func(a slog.Attr) bool {
		na, c := h.attr(a)
		attrs = append(attrs, na)
		changed = changed || c
		return true
	})
	msg := r.Message
	if h.cfg.scanMessage {
		if masked, c := h.maskString(msg); c {
			msg = masked
			changed = true
		}
	}
	if changed {
		nr := slog.NewRecord(r.Time, r.Level, msg, r.PC)
		nr.AddAttrs(attrs...)
		r = nr
	}
	return h.next.Handle(ctx, r)
}

// contextAttrs masks whatever the registered pulls produce and returns them as
// attributes.
func (h *Handler) contextAttrs(ctx context.Context) []slog.Attr {
	if len(h.cfg.ctxPulls) == 0 {
		return nil
	}
	var attrs []slog.Attr
	for _, pull := range h.cfg.ctxPulls {
		for _, a := range pull(ctx) {
			na, _ := h.attr(a)
			attrs = append(attrs, na)
		}
	}
	return attrs
}

func (h *Handler) WithAttrs(as []slog.Attr) slog.Handler {
	out := make([]slog.Attr, len(as))
	for i, a := range as {
		out[i], _ = h.attr(a)
	}
	if h.next == nil {
		return &Handler{cfg: h.cfg}
	}
	return &Handler{next: h.next.WithAttrs(out), cfg: h.cfg}
}

func (h *Handler) WithGroup(name string) slog.Handler {
	if h.next == nil {
		return &Handler{cfg: h.cfg}
	}
	return &Handler{next: h.next.WithGroup(name), cfg: h.cfg}
}

func (h *Handler) attr(a slog.Attr) (slog.Attr, bool) {
	v := a.Value.Resolve()
	if m, ok := h.cfg.maskerForKey(a.Key); ok {
		return slog.Attr{Key: a.Key, Value: m(v)}, true
	}
	if m, ok := h.cfg.maskerForType(v); ok {
		return slog.Attr{Key: a.Key, Value: m(v)}, true
	}
	switch v.Kind() {
	case slog.KindGroup:
		src := v.Group()
		var dst []slog.Attr
		changed := false
		for i, ga := range src {
			na, c := h.attr(ga)
			if c && !changed {
				// First redaction in this group: copy the untouched prefix, then
				// rewrite from here on. Losing attrs before the first change is
				// how this used to silently drop data.
				dst = append(make([]slog.Attr, 0, len(src)), src[:i]...)
				changed = true
			}
			if changed {
				dst = append(dst, na)
			}
		}
		if changed {
			return slog.Attr{Key: a.Key, Value: slog.GroupValue(dst...)}, true
		}
	default:
		// Everything that is not a group: a value rule may claim it whatever its
		// kind, which is the point of the rule. A group is excluded because
		// replacing one would discard the structure rather than mask it.
		if h.cfg.skipKey(a.Key) {
			break
		}
		if nv, ok := h.valueRule(v); ok {
			return slog.Attr{Key: a.Key, Value: nv}, true
		}
	}
	switch v.Kind() {
	case slog.KindString:
		if h.cfg.skipKey(a.Key) {
			return a, false
		}
		if s, changed := h.maskString(v.String()); changed {
			return slog.String(a.Key, s), true
		}
	case slog.KindAny:
		// Check the flag before calling classify, so a handler with no composite
		// option never reaches reflect on this path.
		if h.cfg.scan == 0 {
			break
		}
		if !h.cfg.scans(v.Any()) {
			break
		}
		if h.cfg.skipKey(a.Key) {
			return a, false
		}
		if out, changed := h.walk(v.Any(), 0); changed {
			return slog.Attr{Key: a.Key, Value: slog.AnyValue(out)}, true
		}
	}
	if a.Value.Kind() == slog.KindLogValuer {
		return slog.Attr{Key: a.Key, Value: v}, true
	}
	return a, false
}

func (h *Handler) maskString(s string) (string, bool) {
	changed := false
	for _, f := range h.cfg.values {
		ns, ok := f(s)
		if ok {
			s, changed = ns, true
		}
	}
	return s, changed
}

func isDigit(b byte) bool       { return b >= '0' && b <= '9' }
func isASCIILetter(b byte) bool { return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') }
func isHex(b byte) bool         { return isDigit(b) || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F') }

func luhn(d []byte) bool {
	sum, alt := 0, false
	for i := len(d) - 1; i >= 0; i-- {
		n := int(d[i] - '0')
		if alt {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
		alt = !alt
	}
	return sum%10 == 0
}

func allSameDigits(s string) bool {
	if len(s) < 2 {
		return false
	}
	for i := 1; i < len(s); i++ {
		if s[i] != s[0] {
			return false
		}
	}
	return true
}

func maskDigitsInPlace(s string, pred func([]byte) bool, replacement func(string) string) (string, bool) {
	var out []byte
	last := 0
	for i := 0; i < len(s); {
		if !isDigit(s[i]) {
			i++
			continue
		}
		start, j := i, i
		digits := make([]byte, 0, 19)
		for j < len(s) {
			c := s[j]
			if isDigit(c) {
				if len(digits) < 20 {
					digits = append(digits, c)
				}
				j++
				continue
			}
			if (c == ' ' || c == '-' || c == '.' || c == '/') && j+1 < len(s) && isDigit(s[j+1]) {
				j++
				continue
			}
			break
		}
		if pred(digits) {
			if out == nil {
				out = make([]byte, 0, len(s))
			}
			out = append(out, s[last:start]...)
			out = append(out, replacement(string(digits))...)
			last, i = j, j
		} else {
			i = j
		}
	}
	if out == nil {
		return s, false
	}
	out = append(out, s[last:]...)
	return string(out), true
}

func MaskPAN(s string) (string, bool) {
	d := 0
	for i := 0; i < len(s); i++ {
		if isDigit(s[i]) {
			d++
			if d >= 13 {
				break
			}
		}
	}
	if d < 13 {
		return s, false
	}
	return maskDigitsInPlace(s,
		func(d []byte) bool { return len(d) >= 13 && len(d) <= 19 && luhn(d) },
		func(d string) string { return "****" + d[len(d)-4:] })
}

func MaskCPF(s string) (string, bool) {
	if !hasAtLeastDigits(s, 11) {
		return s, false
	}
	return maskDigitsInPlace(s, validCPF, func(string) string { return "***.***.***-**" })
}

func validCPF(d []byte) bool {
	if len(d) != 11 || allSameDigits(string(d)) {
		return false
	}
	sum := 0
	for i := 0; i < 9; i++ {
		sum += int(d[i]-'0') * (10 - i)
	}
	check1 := (sum * 10) % 11
	if check1 == 10 {
		check1 = 0
	}
	if check1 != int(d[9]-'0') {
		return false
	}
	sum = 0
	for i := 0; i < 10; i++ {
		sum += int(d[i]-'0') * (11 - i)
	}
	check2 := (sum * 10) % 11
	if check2 == 10 {
		check2 = 0
	}
	return check2 == int(d[10]-'0')
}

func MaskCNPJ(s string) (string, bool) {
	if !hasAtLeastDigits(s, 14) {
		return s, false
	}
	return maskDigitsInPlace(s, validCNPJ, func(string) string { return "**.***.***/****-**" })
}

func validCNPJ(d []byte) bool {
	if len(d) != 14 || allSameDigits(string(d)) {
		return false
	}
	w1 := []int{5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2}
	w2 := []int{6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2}
	check := func(n int, w []int) int {
		sum := 0
		for i := 0; i < n; i++ {
			sum += int(d[i]-'0') * w[i]
		}
		r := sum % 11
		if r < 2 {
			return 0
		}
		return 11 - r
	}
	return check(12, w1) == int(d[12]-'0') && check(13, w2) == int(d[13]-'0')
}

func MaskSSN(s string) (string, bool) {
	if !hasAtLeastDigits(s, 9) {
		return s, false
	}
	return maskDigitsInPlace(s, validSSN, func(string) string { return "***-**-****" })
}

func validSSN(d []byte) bool {
	if len(d) != 9 || allSameDigits(string(d)) {
		return false
	}
	return !(d[0] == '0' && d[1] == '0' && d[2] == '0') && !(d[0] == '6' && d[1] == '6' && d[2] == '6') && !(d[0] == '9') &&
		!(d[3] == '0' && d[4] == '0') && !(d[5] == '0' && d[6] == '0' && d[7] == '0' && d[8] == '0')
}

func MaskEmail(s string) (string, bool) {
	if len(s) == 0 || len(s) > 4096 || !strings.Contains(s, "@") {
		return s, false
	}
	var out []byte
	last := 0
	for pos := 0; pos < len(s); {
		rel := strings.IndexByte(s[pos:], '@')
		if rel < 0 {
			break
		}
		at := pos + rel
		if at == 0 || at+1 >= len(s) {
			pos = at + 1
			continue
		}
		start := at - 1
		for start >= 0 && isEmailLocalChar(s[start]) {
			start--
		}
		start++
		end := at + 1
		for end < len(s) && isEmailDomainChar(s[end]) {
			end++
		}
		candidate := s[start:end]
		localLen := at - start
		if strings.Contains(s[at+1:end], ".") && localLen > 0 && localLen <= 64 && len(candidate) <= 254 &&
			validEmailLocal(s[start:at]) && validEmailDomain(s[at+1:end]) {
			local := s[start:at]
			first, _ := utf8.DecodeRuneInString(local)
			maskedLocal := "*"
			if first != utf8.RuneError {
				maskedLocal = string(first) + "***"
			}
			if out == nil {
				out = make([]byte, 0, len(s))
			}
			out = append(out, s[last:start]...)
			out = append(out, maskedLocal+"@"+s[at+1:end]...)
			last, pos = end, end
			continue
		}
		pos = at + 1
	}
	if out == nil {
		return s, false
	}
	out = append(out, s[last:]...)
	return string(out), true
}

func isEmailLocalChar(c byte) bool {
	return isASCIILetter(c) || isDigit(c) || strings.ContainsRune(".!#$%&'*+-/=?^_`{|}~", rune(c))
}
func isEmailDomainChar(c byte) bool { return isASCIILetter(c) || isDigit(c) || c == '-' || c == '.' }

func validEmailLocal(s string) bool {
	if s == "" || strings.HasPrefix(s, ".") || strings.HasSuffix(s, ".") || strings.Contains(s, "..") {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if isASCIILetter(c) || isDigit(c) {
			continue
		}
		if strings.ContainsRune(".!#$%&'*+-/=?^_`{|}~", rune(c)) {
			continue
		}
		return false
	}
	return true
}

func validEmailDomain(s string) bool {
	if len(s) == 0 || strings.HasPrefix(s, ".") || strings.HasSuffix(s, ".") || strings.Contains(s, "..") {
		return false
	}
	// SplitSeq, so no slice is allocated to walk the labels.
	labels, last := 0, 0
	for p := range strings.SplitSeq(s, ".") {
		if p == "" || p[0] == '-' || p[len(p)-1] == '-' {
			return false
		}
		for i := 0; i < len(p); i++ {
			if !(isASCIILetter(p[i]) || isDigit(p[i]) || p[i] == '-') {
				return false
			}
		}
		labels++
		last = len(p)
	}
	return labels >= 2 && last >= 2
}

func hasAtLeastDigits(s string, n int) bool {
	count := 0
	for i := 0; i < len(s); i++ {
		if isDigit(s[i]) {
			count++
			if count >= n {
				return true
			}
		}
	}
	return false
}

func MaskPhone(s string) (string, bool) {
	if !hasAtLeastDigits(s, 7) {
		return s, false
	}
	var out []byte
	last := 0
	for i := 0; i < len(s); {
		if !isDigit(s[i]) {
			i++
			continue
		}
		if i > 0 && isDigit(s[i-1]) {
			i++
			continue
		}
		start, j, nd := i, i, 0
		for j < len(s) {
			c := s[j]
			if isDigit(c) {
				nd++
				if nd > 15 {
					break
				}
				j++
				continue
			}
			if (c == '+' || c == ' ' || c == '(' || c == ')' || c == '-' || c == '.') && j+1 < len(s) {
				j++
				continue
			}
			break
		}
		if nd >= 7 && nd <= 15 {
			if out == nil {
				out = make([]byte, 0, len(s))
			}
			out = append(out, s[last:start]...)
			candidate := s[start:j]
			remaining := nd
			for k := 0; k < len(candidate); k++ {
				if isDigit(candidate[k]) {
					remaining--
					if remaining > 4 {
						out = append(out, '*')
					} else {
						out = append(out, candidate[k])
					}
				} else {
					out = append(out, candidate[k])
				}
			}
			last, i = j, j
		} else {
			i = j
		}
	}
	if out == nil {
		return s, false
	}
	out = append(out, s[last:]...)
	return string(out), true
}

func MaskIPv4(s string) (string, bool) {
	if !strings.Contains(s, ".") {
		return s, false
	}
	var out []byte
	last := 0
	for i := 0; i < len(s); {
		if !isDigit(s[i]) {
			i++
			continue
		}
		if i > 0 && isDigit(s[i-1]) {
			i++
			continue
		}
		j := i
		for j < len(s) && (isDigit(s[j]) || s[j] == '.') {
			j++
		}
		candidate := s[i:j]
		if validIPv4(candidate) {
			if out == nil {
				out = make([]byte, 0, len(s))
			}
			// Cut rather than Split: only the first octet survives, so there is
			// no reason to allocate the rest.
			firstOctet, _, _ := strings.Cut(candidate, ".")
			out = append(out, s[last:i]...)
			out = append(out, firstOctet...)
			out = append(out, ".*.*.*"...)
			last = j
		}
		i = j
	}
	if out == nil {
		return s, false
	}
	out = append(out, s[last:]...)
	return string(out), true
}

func validIPv4(s string) bool {
	// SplitSeq, and the count comes from the loop rather than a slice length.
	octets := 0
	for x := range strings.SplitSeq(s, ".") {
		if octets == 4 {
			return false
		}
		if len(x) == 0 || len(x) > 3 || (len(x) > 1 && x[0] == '0') {
			return false
		}
		n := 0
		for i := 0; i < len(x); i++ {
			if !isDigit(x[i]) {
				return false
			}
			n = n*10 + int(x[i]-'0')
		}
		if n > 255 {
			return false
		}
		octets++
	}
	return octets == 4
}

func MaskUUID(s string) (string, bool) {
	if len(s) < 36 {
		return s, false
	}
	for i := 0; i+36 <= len(s); i++ {
		if i > 0 && isHex(s[i-1]) {
			continue
		}
		if !validUUID(s[i : i+36]) {
			continue
		}
		if i+36 < len(s) && isHex(s[i+36]) {
			continue
		}
		return s[:i] + s[i:i+8] + "-****-****-****-" + s[i+24:i+36] + s[i+36:], true
	}
	return s, false
}
func validUUID(s string) bool {
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return false
	}
	for i := 0; i < 36; i++ {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			continue
		}
		if !isHex(s[i]) {
			return false
		}
	}
	return true
}

func MaskIBAN(s string) (string, bool) {
	if len(s) < 15 || !strings.Contains(s, " ") && !strings.ContainsAny(s, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz") {
		return s, false
	}
	var out []byte
	last := 0
	for i := 0; i+4 <= len(s); i++ {
		if !isASCIILetter(s[i]) || !isASCIILetter(s[i+1]) || !isDigit(s[i+2]) || !isDigit(s[i+3]) {
			continue
		}
		j := i + 4
		for j < len(s) {
			c := s[j]
			if isASCIILetter(c) || isDigit(c) || c == ' ' || c == '-' {
				j++
				continue
			}
			break
		}
		candidate := s[i:j]
		compact := make([]byte, 0, len(candidate))
		for k := 0; k < len(candidate); k++ {
			if candidate[k] != ' ' && candidate[k] != '-' {
				compact = append(compact, candidate[k])
			}
		}
		if len(compact) < 15 || len(compact) > 34 || !validIBAN(compact) {
			continue
		}
		if out == nil {
			out = make([]byte, 0, len(s))
		}
		out = append(out, s[last:i]...)
		out = append(out, compact[:2]...)
		out = append(out, strings.Repeat("*", len(compact)-2)...)
		last, i = j, j-1
	}
	if out == nil {
		return s, false
	}
	out = append(out, s[last:]...)
	return string(out), true
}

func validIBAN(compact []byte) bool {
	if len(compact) < 15 || len(compact) > 34 || !isASCIILetter(compact[0]) || !isASCIILetter(compact[1]) || !isDigit(compact[2]) || !isDigit(compact[3]) {
		return false
	}
	for _, c := range compact[4:] {
		if !(isASCIILetter(c) || isDigit(c)) {
			return false
		}
	}
	rot := append(append([]byte{}, compact[4:]...), compact[:4]...)
	rem := 0
	for _, c := range rot {
		if isDigit(c) {
			rem = (rem*10 + int(c-'0')) % 97
		} else {
			rem = (rem*100 + int(c-'A') + 10) % 97
		}
	}
	return rem == 1
}

// Package cloak provides a slog.Handler wrapper that masks sensitive values.
//
// Key-based masking is exact and cheap. Optional value detectors use a two-stage
// strategy: a small structural pre-filter first, followed by the exact
// validation required by the detector (for example, Luhn for PAN or check
// digits for CPF/CNPJ/SSN). This keeps the common logging path inexpensive and
// reduces false positives from arbitrary strings.
package cloak

import (
	"context"
	"log/slog"
	"reflect"
	"strings"
	"unicode/utf8"
)

type Masker func(slog.Value) slog.Value

func Redact(slog.Value) slog.Value { return slog.StringValue("[REDACTED]") }

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
	keys     map[string]Masker
	skip     map[string]struct{}
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
}

type tagMask struct {
	key, value string
	masker     Masker
}

// WithTag masks a struct field carrying the given struct tag.
//
//	type Account struct {
//	    ID       int
//	    Password string `cloak:"secret"`
//	}
//
//	cloak.WithTag("cloak", "secret", cloak.Redact)
//
// A tag is the most durable way to mark a field: renaming the field does not lose the
// rule, and the intent sits on the field rather than in the logger's configuration.
//
// Rules for different tag keys can coexist, since the key is part of each rule. A field
// matching no rule is walked normally.
func WithTag(key, value string, m Masker) Option {
	return func(c *config) {
		c.tagMasks = append(c.tagMasks, tagMask{key: key, value: value, masker: m})
	}
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
func WithContextAttrs(pulls ...func(context.Context) []slog.Attr) Option {
	return func(c *config) { c.ctxPulls = append(c.ctxPulls, pulls...) }
}

// maskerFor returns the rule matching a normalized key, if any.
func (c *config) maskerFor(key string) (Masker, bool) {
	if m, ok := c.keys[key]; ok {
		return m, true
	}
	for _, r := range c.contains {
		if strings.Contains(key, r.part) {
			return r.masker, true
		}
	}
	return nil, false
}

func normalizeKey(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '_', '-', ' ', '	':
			continue
		}
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b.WriteByte(c)
	}
	return b.String()
}

type Option func(*config)

// WithKey redacts attributes whose normalized key exactly matches one of keys.
func WithKey(m Masker, keys ...string) Option {
	return func(c *config) {
		for _, k := range keys {
			c.keys[normalizeKey(k)] = m
		}
	}
}

// WithKeyContains redacts attributes whose normalized key contains one of keys as a
// substring. It catches the qualified names that exact matching misses, such as
// "db.password" or "headers.Authorization".
//
// It is looser than [WithKey]: "token" also matches "tokens_used". Keys holding
// unrelated data ("id", "name") make it a poor choice, so prefer [WithKey] and reach
// for this only where the prefixes are known.
func WithKeyContains(m Masker, keys ...string) Option {
	return func(c *config) {
		for _, k := range keys {
			c.contains = append(c.contains, rule{part: normalizeKey(k), masker: m})
		}
	}
}

func WithValueFunc(f ValueFunc) Option {
	return func(c *config) { c.values = append(c.values, f) }
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
	return []ValueFunc{MaskUUID, MaskEmail, MaskIPv4, MaskIBAN, MaskCPF, MaskCNPJ, MaskSSN, MaskPAN, MaskPhone}
}

func WithDefaultPIIValues() Option {
	return func(c *config) { c.values = append(c.values, DefaultPIIValueFuncs()...) }
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

func WithDefaultPIIKeys() Option { return WithKey(Redact, DefaultPIIKeys...) }

func WithDefaultPII() Option {
	return func(c *config) {
		for _, k := range DefaultPIIKeys {
			c.keys[normalizeKey(k)] = Redact
		}
		c.values = append(c.values, DefaultPIIValueFuncs()...)
	}
}

func WithSkipValueScan(keys ...string) Option {
	return func(c *config) {
		for _, k := range keys {
			c.skip[normalizeKey(k)] = struct{}{}
		}
	}
}

// WithMessageScan also runs the value detectors over the log message.
//
// Attributes are opt-in per key, but the message is free text nobody reviews, and
// `slog.Info("login for "+email)` is a routine way to leak. It is off by default
// because rewriting the message surprises readers and costs a scan per record.
func WithMessageScan() Option {
	return func(c *config) { c.scanMessage = true }
}

// WithStructScan walks struct values logged through [slog.Any], masking PII in their
// fields by field name and by value.
//
// The value keeps its type: only the offending fields are replaced, so the record
// still logs a structured object.
//
//	cloak.WithStructScan()   // slog.Any("user", User{Email: ...})
func WithStructScan() Option {
	return func(c *config) { c.scan |= compositeStruct | compositePtr }
}

// WithMapScan walks map values logged through [slog.Any], masking both keys and values.
// A key match wins over the value detectors, so map[string]any{"password": "x"} is
// caught by name while a bare address is caught as a value.
//
//	cloak.WithMapScan()   // slog.Any("ctx", map[string]any{"email": ...})
func WithMapScan() Option {
	return func(c *config) { c.scan |= compositeMap | compositePtr }
}

// WithSliceScan walks slice values logged through [slog.Any], masking each element and
// recursing into nested containers.
//
// []byte is excluded: it is data, not a container of things to log, and walking it
// would rewrite a payload into decimal digits.
//
//	cloak.WithSliceScan()   // slog.Any("emails", []string{"a@example.com"})
func WithSliceScan() Option {
	return func(c *config) { c.scan |= compositeSlice | compositePtr }
}

// WithCompositeScan enables [WithStructScan], [WithMapScan] and [WithSliceScan] at
// once, and is what you want unless you have a reason to scope the walk.
//
// Pointers are always followed, since a pointer is just an address to the value behind
// it.
func WithCompositeScan() Option {
	return func(c *config) {
		c.scan |= compositeStruct | compositeMap | compositeSlice | compositePtr
	}
}

type Handler struct {
	next slog.Handler
	cfg  *config
}

func New(next slog.Handler, opts ...Option) slog.Handler {
	c := &config{keys: make(map[string]Masker), skip: make(map[string]struct{})}
	for _, opt := range opts {
		opt(c)
	}
	return &Handler{next: next, cfg: c}
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
	attrs := h.contextAttrs(ctx)
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
	key := normalizeKey(a.Key)
	if m, ok := h.cfg.maskerFor(key); ok {
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
	case slog.KindString:
		if _, ok := h.cfg.skip[key]; ok {
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
		if _, ok := h.cfg.skip[key]; ok {
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
	parts := strings.Split(s, ".")
	if len(parts) < 2 {
		return false
	}
	for _, p := range parts {
		if p == "" || p[0] == '-' || p[len(p)-1] == '-' {
			return false
		}
		for i := 0; i < len(p); i++ {
			if !(isASCIILetter(p[i]) || isDigit(p[i]) || p[i] == '-') {
				return false
			}
		}
	}
	return len(parts[len(parts)-1]) >= 2
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
			parts := strings.Split(candidate, ".")
			out = append(out, s[last:i]...)
			out = append(out, parts[0]...)
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
	p := strings.Split(s, ".")
	if len(p) != 4 {
		return false
	}
	for _, x := range p {
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
	}
	return true
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

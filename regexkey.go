package cloak

import (
	"regexp"
	"regexp/syntax"
	"slices"
	"strings"
)

// regexKey is a key pattern resolved at configuration time.
//
// A pattern that is nothing but literals — `secret`, or an alternation such as
// `(?i)pass|secret|token` — is turned into substring tests, because running the regexp
// on every attribute costs 450ns where three strings.Contains cost 21ns. Anything with
// real structure stays a compiled regexp.
//
// The split matters less than it looks: a bare literal is exactly what
// [WithKeysContaining] does, so the fast path adds no new semantics. It exists to make
// the natural spelling of a case-insensitive alternation cheap.
type regexKey struct {
	// lits are the literal alternatives, already folded and normalized. A pattern
	// with no literals leaves this empty and is matched with re instead.
	lits []string
	// fold is true when the pattern used (?i), which syntax has already applied to
	// the literal runes. Folding happens on both sides at match time.
	fold bool
	// re is nil for a literal pattern.
	re     *regexp.Regexp
	masker Masker
}

// matches reports whether the key is covered by the pattern.
//
// raw is the attribute name as written, normalized its lowercased separator-stripped
// form. A case-sensitive literal matches the raw name, so `Secret` does not hide
// `secret`; a folded one matches the normalized name, which is what makes (?i) work
// across the casing and separators the library folds everywhere else.
//
// A folded literal can therefore match slightly more than its regexp would —
// `(?i)api_key` matches `apiKey` — because it goes through the same normalization as
// WithKeysContaining. That direction is the safe one: cloak masks more than asked rather
// than less, and the two never disagree about a key that needs masking.
func (r *regexKey) matches(raw, normalized string) bool {
	if r.re != nil {
		return r.re.MatchString(raw)
	}
	haystack := raw
	if r.fold {
		haystack = normalized
	}
	for _, lit := range r.lits {
		if strings.Contains(haystack, lit) {
			return true
		}
	}
	return false
}

// newRegexKey resolves a pattern to literals when it can, at configuration time.
func newRegexKey(re *regexp.Regexp, m Masker) regexKey {
	r := regexKey{re: re, masker: m}
	words, fold, ok := patternLiterals(re.String())
	if !ok {
		return r
	}
	// An unanchored literal is a substring match; normalize it the way
	// WithKeysContaining does so both rules behave alike. Folding is already in the
	// runes syntax produced, and normalizeKey lowercases, so a folded literal
	// ends up lowercase and matches the normalized key.
	for _, w := range words {
		// A folded literal is compared against the normalized key, so it is
		// normalized too. A case-sensitive one is compared against the raw name
		// and keeps its case, or `Secret` would start matching `secret`.
		n := w
		if fold {
			n = normalizeKey(w)
		}
		if !slices.Contains(r.lits, n) {
			r.lits = append(r.lits, n)
		}
	}
	r.fold = fold
	r.re = nil
	return r
}

// patternLiterals reports the literal alternatives of a pattern, and whether it folds
// case. It refuses anything with real structure, which keeps the fast path honest: a
// pattern it cannot fully account for stays a regexp.
func patternLiterals(pattern string) (words []string, fold, ok bool) {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return nil, false, false
	}
	add := func(n *syntax.Regexp) bool {
		if n.Op != syntax.OpLiteral || len(n.Sub) != 0 {
			return false
		}
		words = append(words, string(n.Rune))
		fold = fold || n.Flags&syntax.FoldCase != 0
		return true
	}
	switch re.Op {
	case syntax.OpLiteral:
		ok = add(re)
	case syntax.OpAlternate:
		for _, sub := range re.Sub {
			if !add(sub) {
				return nil, false, false
			}
		}
		ok = len(words) > 0
	default:
		return nil, false, false
	}
	if !ok {
		return nil, false, false
	}
	return words, fold, true
}

// WithKeyRegex masks attributes whose key matches the pattern, compiled with
// [regexp.MustCompile].
//
// It panics on an invalid pattern, which is the point: a typo would otherwise become a
// rule that silently matches nothing, and PII would leave the program with no signal.
// Failing at construction time means it fails at startup, where it is loud. Use
// [WithKeyRegexp] if you would rather handle the compile error yourself.
//
// The pattern matches the attribute name **as written**, not the normalized key, so
// `_key$` and `^x-.*-token$` mean what they look like. normalizeKey strips the
// underscores and hyphens a pattern usually wants to anchor on.
//
//	cloak.WithKeyRegex(cloak.Redact, `_key$`)
//	cloak.WithKeyRegex(cloak.Redact, `^x-.*-token$`)
//
// Precedence is key rule, then this, then [WithKeysContaining]: an exact key is the most
// specific statement of intent, a pattern is deliberate, and a substring is the loosest.
func WithKeyRegex(m Masker, pattern string) Options {
	return WithKeyRegexp(m, regexp.MustCompile(pattern))
}

// WithKeyRegexp is [WithKeyRegex] for a pattern you compiled yourself, so a bad
// pattern is your error to handle rather than a panic.
//
//	pattern, err := regexp.Compile(os.Getenv("REDACT_PATTERN"))
//	if err != nil {
//	    return err
//	}
//	cloak.WithKeyRegexp(cloak.Redact, pattern)
func WithKeyRegexp(m Masker, re *regexp.Regexp) Options {
	// A nil regexp is the shape of a discarded compile error, and it would
	// otherwise surface as a nil dereference inside Handle — during a log call,
	// with no stack pointing at the mistake. Fail here instead, where the message
	// can name the cause.
	if re == nil {
		panic("cloak: WithKeyRegexp requires a compiled pattern; check the error from regexp.Compile")
	}
	// Resolved here rather than when the option is applied, so the pattern is
	// parsed and classified exactly once, whichever constructor is used.
	key := newRegexKey(re, m)
	return option(func(c *config) { c.addRegexKey(re.String(), key) })
}

// addRegexKey registers a pattern rule, replacing one already registered for the same
// pattern. Only the masker changes: the pattern is identical, so its resolved literals
// and fold flag are still correct.
func (c *config) addRegexKey(pattern string, key regexKey) {
	if i, ok := c.regexIdx[pattern]; ok {
		c.regexKeys[i].masker = key.masker
		return
	}
	if c.regexIdx == nil {
		c.regexIdx = make(map[string]int)
	}
	c.regexIdx[pattern] = len(c.regexKeys)
	c.regexKeys = append(c.regexKeys, key)
}

// finalize answers every outstanding request for a full redaction with the handler's
// own message. It runs once, in [New], after the options are applied, so the hot path
// pays nothing for the indirection.
//
// Doing it here rather than at registration is what makes the message a property of the
// instance: an option may set it before or after the rule that asks for redaction, and
// both orders have to end up the same.
func (c *config) finalize() {
	if c.redacted == "" {
		c.redacted = Placeholder
	}
	fill := func(m Masker) Masker {
		if isRedact(m) {
			return Fixed(c.redacted)
		}
		return m
	}
	for k, m := range c.keys {
		c.keys[k] = fill(m)
	}
	for k, m := range c.typeMasks {
		c.typeMasks[k] = fill(m)
	}
	for i := range c.contains {
		c.contains[i].masker = fill(c.contains[i].masker)
	}
	for i := range c.tagMasks {
		c.tagMasks[i].masker = fill(c.tagMasks[i].masker)
	}
	for i := range c.regexKeys {
		c.regexKeys[i].masker = fill(c.regexKeys[i].masker)
	}
}

// maskerForKey returns the rule covering a key, given the name as written and its
// normalized form.
//
// The order is fixed rather than the order the options were given: an exact key is the
// most specific statement of intent, a pattern is deliberate, and a substring is the
// loosest of the three. Without a fixed order the same configuration would behave
// differently depending on argument order.
func (c *config) maskerForKey(raw, normalized string) (Masker, bool) {
	if m, ok := c.keys[normalized]; ok {
		return m, true
	}
	for i := range c.regexKeys {
		if c.regexKeys[i].matches(raw, normalized) {
			return c.regexKeys[i].masker, true
		}
	}
	for _, r := range c.contains {
		if strings.Contains(normalized, r.part) {
			return r.masker, true
		}
	}
	return nil, false
}

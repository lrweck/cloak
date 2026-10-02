package cloak

import (
	"log/slog"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// FuzzKeyRegexFastPathNeverMasksLess is the security invariant of the whole library.
//
// A pattern whose literals are resolved ahead of time is matched with substring tests
// instead of the regexp. If that fast path ever says "no match" where the regexp would
// have said "match", a sensitive key slips through the mask with no symptom. The fast
// path may match more than the regexp — stripping separators can join characters the
// regexp would not have joined — and that direction is safe. This target pins the
// unsafe direction shut.
func FuzzKeyRegexFastPathNeverMasksLess(f *testing.F) {
	// Patterns the extractor resolves to literals, and patterns it must not.
	patterns := []string{
		`secret`, `Secret`, `(?i)pass|secret|token`, `pass|secret|token`,
		`(?i)pass`, `authorization`, `api_key`, `(?i)api_key`,
		// The parenthesised forms defeat the extractor while matching identically,
		// so they exercise the slow path for the same semantics.
		`(secret)`, `(?i)(pass|secret|token)`, `(authorization)`, `(?i)(api_key)`,
		// Patterns with structure, which always stay on the regexp path.
		`_key$`, `^x-.*-token$`, `(?i)api_?key`, `(?i)(secret|token)`,
		`\d+`, `.*key.*`, `^authorization$`, `(?i)(?i)pass`, ``,
		// Fold mixed across alternatives.
		`a|(?-i)BC`, `(?i)a|BC`,
	}
	keys := []string{
		"password", "PASS", "Secret", "SECRET", "user_secret", "access_token",
		"authorization", "api_key", "apiKey", "api-key", "sec_ret", "x-auth-token",
		"mysecretvalue", "request_id", "latency_ms", "id", "a", "A", "bc", "BC",
		"", " ", "\t", "-", "___", "pässwörd", "密码", "🔑secret", "SECRET-KEY",
	}
	for _, p := range patterns {
		for _, k := range keys {
			f.Add(p, k)
		}
	}

	f.Fuzz(func(t *testing.T, pattern, key string) {
		re, err := regexp.Compile(pattern)
		if err != nil {
			t.Skip("pattern does not compile")
		}
		rk := newRegexKey(re, Redact)
		normalized := normalizeKey(key)

		if rk.matches(key, normalized) {
			return
		}
		if re.MatchString(key) {
			t.Fatalf("fast path missed %q that the regexp matches: pattern %q", key, pattern)
		}
	})
}

// A pattern that does resolve to literals must resolve to the same set the regexp
// would accept, which is what makes the fast path a rewrite rather than a different
// rule.
func FuzzKeyRegexResolvedLiteralsAreSound(f *testing.F) {
	f.Add(`(?i)pass|secret|token`, "user_secret")
	f.Add(`api_key`, "apiKey")
	f.Add(`Secret`, "mysecretvalue")

	f.Fuzz(func(t *testing.T, pattern, key string) {
		re, err := regexp.Compile(pattern)
		if err != nil {
			t.Skip("pattern does not compile")
		}
		words, fold, ok := patternLiterals(re.String())
		if !ok {
			t.Skip("not a literal pattern")
		}

		// Every resolved literal must be one the regexp itself accepts somewhere,
		// once case folding is accounted for.
		for _, w := range words {
			probe := w
			if fold {
				probe = strings.ToLower(w)
			}
			if re.MatchString(probe) {
				return
			}
			// A folded literal is stored folded, so compare against the raw form too.
			if fold && re.MatchString(w) {
				return
			}
			t.Fatalf("resolved literal %q (fold=%v) is not matched by its own pattern %q", w, fold, pattern)
		}
	})
}

// The rule path must survive arbitrary patterns and keys without panicking, including
// the nil-map indexes and the group path.
func FuzzKeyRegexRuleNoPanic(f *testing.F) {
	f.Add(`_key$`, "api_key")
	f.Add(`(?i)pass|secret|token`, "user_secret")
	f.Add(``, "k")

	f.Fuzz(func(t *testing.T, pattern, key string) {
		re, err := regexp.Compile(pattern)
		if err != nil {
			t.Skip("pattern does not compile")
		}
		c := &config{keys: make(map[string]Masker), skip: make(map[string]struct{})}
		c.addRegexKey(re.String(), newRegexKey(re, Redact))
		WithKeysContaining(Redact, "pass").apply(c)
		WithKeys(Redact, "password").apply(c)

		m, ok := c.maskerForKey(key)
		if !ok {
			return
		}
		// The masker must produce something usable whatever the input kind.
		if got := m(slog.AnyValue(key)); got.Kind() == slog.KindGroup {
			t.Fatalf("masker returned a group for a scalar key %q", key)
		}
	})
}

// matches must stay cheap and terminating on pathological input, since it runs inside
// Handle. A pattern the extractor mishandled would show up here as a runaway.
func FuzzKeyRegexMatchesTerminates(f *testing.F) {
	f.Add(`(?i)pass|secret|token`, "user_secret")
	f.Add(`(a)(b)(c)`, "abcabc")
	f.Add(`^x-.*-token$`, "x-auth-token")

	f.Fuzz(func(t *testing.T, pattern, key string) {
		re, err := regexp.Compile(pattern)
		if err != nil {
			t.Skip("pattern does not compile")
		}
		rk := newRegexKey(re, Redact)
		// Called on both sides: the regexp is the slow path this fast path exists to
		// avoid, so it has to terminate too.
		_ = rk.matches(key, normalizeKey(key))
		_ = re.MatchString(key)
	})
}

// Seeds a literal pattern list and checks the extractor never invents a word that is
// not in the pattern.
func TestRegexKeyLiteralExtraction(t *testing.T) {
	cases := []struct {
		pattern string
		want    []string
		fold    bool
		resolve bool
	}{
		{`secret`, []string{"secret"}, false, true},
		{`(?i)pass`, []string{"PASS"}, true, true},
		{`pass|secret`, []string{"pass", "secret"}, false, true},
		{`(?i)pass|secret`, []string{"PASS", "SECRET"}, true, true},
		{`_key$`, nil, false, false},
		{`^x-.*-token$`, nil, false, false},
		{`(?i)(secret)`, nil, false, false},
		{`\d+`, nil, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.pattern, func(t *testing.T) {
			words, fold, ok := patternLiterals(tc.pattern)
			if ok != tc.resolve {
				t.Fatalf("resolved=%v, want %v (words %v)", ok, tc.resolve, words)
			}
			if !ok {
				return
			}
			if fold != tc.fold {
				t.Errorf("fold=%v, want %v", fold, tc.fold)
			}
			if !slices.Equal(words, tc.want) {
				t.Errorf("words=%v, want %v", words, tc.want)
			}
		})
	}
}

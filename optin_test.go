package cloak

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
)

// Every feature below is opt-in, and the promise is not merely that it does nothing
// when unset — it is that its code does not run. A rule that inspects a value it was
// never asked about is a rule the caller cannot reason about, and on a logging path it
// is a cost nobody budgeted for.
//
// Two directions are asserted for every case. Checking only that a disabled option
// leaves the value alone would pass just as well on an option that is broken and does
// nothing, enabled or not; the enabled column is what gives the case meaning.
//
// What this file can and cannot prove, established by removing each gate and re-running
// it. Removing the message gate, both reflect gates, or disabling a caller-supplied
// function is caught here. Removing the gate on typeMasks, value rules, tag rules,
// detectors, contains, regex keys or context pulls is not, and cannot be: their bodies
// are a lookup in a collection that is empty when the option is unset, so a gate that
// does not exist and one that returns early produce identical output. There is no
// observable difference to assert on. What is asserted for those is structural — see
// TestNothingIsArmedWithoutOptions — and, for the ones taking a caller function, the
// call count in TestOptionalFunctionsAreNeverCalledWhenUnset.
//
// Reflect needed both its gates removed at once to show up at all, because there are
// two: the raw `scan == 0` flag is checked before classify(), and classify() is what
// calls reflect. scans() then refines it per shape. Either alone holds.

// optIn is one feature and the record it would change.
type optIn struct {
	name string
	// rules are what make the case meaningful, usually a key rule the value violates.
	rules []Options
	// feature is the option under test. With it absent the secret must survive
	// verbatim; with it present the secret must be gone.
	feature Options
	// msg, when set, is logged as the message instead of args, for the features that
	// only touch the message.
	msg  string
	args []any
	// secret is the substring whose presence proves the feature did not run.
	secret string
}

type optInPassword string

type optInAccount struct {
	ID       int
	Email    string
	Token    string `cloak:"secret"`
	Password optInPassword
}

// optInHidden carries a secret in an unexported field, which is what makes "was this
// struct walked?" observable from outside.
//
// Every other case here asks whether a value was masked, and for those two states are
// required to be indistinguishable: walking a struct that changes nothing returns the
// value untouched, on purpose, because that is what makes the pass-through free. Here
// the two states differ. A TextHandler prints an unexported field through %+v, so
// leaving the struct unwalked leaves the secret in the sink and walking it drops the
// field. Which of the two happened is visible in the output — and it is the only way to
// catch a missing reflect gate, since every other probe here is blind to one by
// construction.
type optInHidden struct {
	ID     int
	secret string
}

func optInCases() []optIn {
	email := "leak@example.com"
	pan := "4111111111111111"
	return []optIn{
		{
			name:    "struct scan",
			rules:   []Options{WithKeys(Redact, "email")},
			feature: WithStructScan(),
			args:    []any{slog.Any("v", optInAccount{ID: 7, Email: email})},
			secret:  email,
		},
		{
			name:    "map scan",
			rules:   []Options{WithKeys(Redact, "email")},
			feature: WithMapScan(),
			args:    []any{slog.Any("v", map[string]any{"email": email})},
			secret:  email,
		},
		{
			// A slice element has no key of its own, so this case needs a detector for
			// there to be anything to reach for. Under a key rule it stays unmasked
			// whether or not the option is set, which would make the case vacuous.
			name:    "slice scan",
			rules:   []Options{WithDefaultPIIValues()},
			feature: WithSliceScan(),
			args:    []any{slog.Any("v", []string{pan})},
			secret:  pan,
		},
		{
			// Not a masking case: the probe is whether the struct was walked at all. See
			// optInHidden. The rule list is empty because the field must fall to the
			// "unexported fields are dropped" rule, not to a key rule.
			name:    "reflect runs at all",
			feature: WithStructScan(),
			args:    []any{slog.Any("v", optInHidden{ID: 7, secret: "abc123"})},
			secret:  "abc123",
		},
		{
			name:    "composite scan",
			rules:   []Options{WithKeys(Redact, "email")},
			feature: WithCompositeScan(),
			args:    []any{slog.Any("v", optInAccount{ID: 7, Email: email})},
			secret:  email,
		},
		{
			// The message is free text with no key, for the same reason the slice is.
			name:    "message scan",
			rules:   []Options{WithDefaultPIIValues()},
			feature: WithMessageScan(),
			msg:     "charge " + pan + " settled",
			secret:  pan,
		},
		{
			name:    "contain",
			feature: WithContain("sk_live_q7Z"),
			args:    []any{"url", "https://api/x?k=sk_live_q7Z"},
			secret:  "sk_live_q7Z",
		},
		{
			name:    "key regex",
			rules:   []Options{},
			feature: WithKeyRegex(Redact, `^x-.*-token$`),
			args:    []any{"x-auth-token", "abc123"},
			secret:  "abc123",
		},
		{
			// A tag rule is consulted while walking a struct, so the walk is the baseline
			// here and the tag is the feature. Without WithStructScan the tag is never
			// read, which is a different case — see the notes on tagMasks below.
			name:    "struct tag",
			rules:   []Options{WithStructScan()},
			feature: WithTag(Redact, "cloak", "secret"),
			args:    []any{slog.Any("v", optInAccount{ID: 7, Token: "abc123"})},
			secret:  "abc123",
		},
		{
			name:    "go type",
			feature: WithType[optInPassword](),
			args:    []any{"password", optInPassword("abc123")},
			secret:  "abc123",
		},
		{
			name:    "detectors",
			feature: WithDefaultPIIValues(),
			args:    []any{"note", pan},
			secret:  pan,
		},
	}
}

// runFeature logs one record through a handler carrying rules and optionally the
// feature, and returns what reached the sink.
func runFeature(t *testing.T, c optIn, feature bool) string {
	t.Helper()

	opts := append([]Options{}, c.rules...)
	if feature {
		opts = append(opts, c.feature)
	}
	var b bytes.Buffer
	logger := slog.New(New(slog.NewTextHandler(&b, nil), opts...))
	if c.msg != "" {
		logger.Info(c.msg)
	} else {
		logger.Info("event", c.args...)
	}
	return b.String()
}

func TestOptionalFeaturesOnlyRunWhenEnabled(t *testing.T) {
	for _, c := range optInCases() {
		t.Run(c.name, func(t *testing.T) {
			off := runFeature(t, c, false)
			if !strings.Contains(off, c.secret) {
				t.Errorf("sem %s o valor deveria passar intacto, mas nao chegou:\n%s", c.name, off)
			}
			on := runFeature(t, c, true)
			if strings.Contains(on, c.secret) {
				t.Errorf("com %s o valor deveria ter sido mascarado:\n%s", c.name, on)
			}
		})
	}
}

// Counting the calls is the part behavioural assertions cannot do. Output that looks
// right is also what a rule that ran and then decided not to mask produces; a counter
// separates the two.
func TestOptionalFunctionsAreNeverCalledWhenUnset(t *testing.T) {
	t.Run("value func", func(t *testing.T) {
		calls := 0
		fn := func(s string) (string, bool) { calls++; return s + "!", true }
		log := func(feature bool) string {
			var opts []Options
			if feature {
				opts = append(opts, WithValueFunc(fn))
			}
			var b bytes.Buffer
			slog.New(New(slog.NewTextHandler(&b, nil), opts...)).Info("m", "note", "clean")
			return b.String()
		}
		if got := log(false); calls != 0 {
			t.Errorf("a funcao de valor rodou %d vez(es) sem WithValueFunc:\n%s", calls, got)
		}
		if got := log(true); calls != 1 {
			t.Errorf("com WithValueFunc a funcao deveria rodar uma vez, rodou %d:\n%s", calls, got)
		}
	})

	t.Run("value rule", func(t *testing.T) {
		calls := 0
		rule := func(v slog.Value) (slog.Value, bool) { calls++; return v, false }
		log := func(feature bool) string {
			var opts []Options
			if feature {
				opts = append(opts, WithValueRule(rule))
			}
			var b bytes.Buffer
			slog.New(New(slog.NewTextHandler(&b, nil), opts...)).Info("m", "note", "clean")
			return b.String()
		}
		if got := log(false); calls != 0 {
			t.Errorf("a regra de valor rodou %d vez(es) sem WithValueRule:\n%s", calls, got)
		}
		if got := log(true); calls != 1 {
			t.Errorf("com WithValueRule a regra deveria rodar uma vez, rodou %d:\n%s", calls, got)
		}
	})

	t.Run("value predicate", func(t *testing.T) {
		calls := 0
		pred := func(slog.Value) bool { calls++; return true }
		log := func(feature bool) string {
			var opts []Options
			if feature {
				opts = append(opts, WithValuePredicate(Redact, pred))
			}
			var b bytes.Buffer
			slog.New(New(slog.NewTextHandler(&b, nil), opts...)).Info("m", "note", "clean")
			return b.String()
		}
		if got := log(false); calls != 0 {
			t.Errorf("o predicado rodou %d vez(es) sem WithValuePredicate:\n%s", calls, got)
		}
		if got := log(true); calls == 0 {
			t.Errorf("com WithValuePredicate o predicado deveria rodar:\n%s", got)
		}
	})

	t.Run("context attrs", func(t *testing.T) {
		calls := 0
		pull := func(context.Context) []slog.Attr {
			calls++
			return []slog.Attr{slog.String("user", "jane")}
		}
		log := func(feature bool) string {
			var opts []Options
			if feature {
				opts = append(opts, WithContextAttrs(pull))
			}
			var b bytes.Buffer
			slog.New(New(slog.NewTextHandler(&b, nil), opts...)).InfoContext(context.Background(), "m")
			return b.String()
		}
		if got := log(false); calls != 0 {
			t.Errorf("o pull rodou %d vez(es) sem WithContextAttrs:\n%s", calls, got)
		}
		if got := log(true); calls != 1 {
			t.Errorf("com WithContextAttrs o pull deveria rodar uma vez, rodou %d:\n%s", calls, got)
		}
	})
}

// The white-box half: with nothing configured, nothing is armed. Every field a
// feature needs is zero, so the gate each feature is consulted through cannot be
// taken. This is what makes the behavioural table above more than an observation.
func TestNothingIsArmedWithoutOptions(t *testing.T) {
	c := &config{keys: map[string]Masker{}, skip: map[string]struct{}{}}
	c.finalize()

	var armed []string
	if len(c.keys) > 0 {
		armed = append(armed, "keys")
	}
	if len(c.skip) > 0 {
		armed = append(armed, "skip")
	}
	if len(c.rules) > 0 {
		armed = append(armed, "rules (value rules)")
	}
	if len(c.values) > 0 {
		armed = append(armed, "values (detectors)")
	}
	if len(c.contains) > 0 {
		armed = append(armed, "contains")
	}
	if c.scanMessage {
		armed = append(armed, "scanMessage")
	}
	if c.scan != 0 {
		armed = append(armed, "scan (reflection)")
	}
	if len(c.ctxPulls) > 0 {
		armed = append(armed, "ctxPulls")
	}
	if len(c.tagMasks) > 0 {
		armed = append(armed, "tagMasks")
	}
	if len(c.typeMasks) > 0 {
		armed = append(armed, "typeMasks")
	}
	if len(c.regexKeys) > 0 {
		armed = append(armed, "regexKeys")
	}
	if c.builtins != 0 {
		armed = append(armed, "builtins")
	}
	if len(armed) > 0 {
		t.Errorf("armadas sem nenhuma opção: %v", armed)
	}
}

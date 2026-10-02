package compare

import (
	"bytes"
	"io"
	"log/slog"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/JAS0N-SMITH/redactlog"
	"github.com/JAS0N-SMITH/redactlog/redact"
	"github.com/lrweck/cloak"
	"github.com/m-mizutani/masq"
)

// Three records from what a Go service actually logs, rather than three variants of the
// same synthetic attribute list.
//
// Each scenario says which libraries can be configured for it honestly. A library with
// no equivalent is reported as excluded rather than benchmarked with a configuration
// that quietly does nothing, which would read as a very fast winner.

type scenario struct {
	name   string
	note   string
	record []any
	// build configures one library for this scenario. A library absent from the map
	// has no equivalent here.
	build map[string]func(io.Writer) (*slog.Logger, error)
}

// An HTTP request log, which is the most common slog record in a service: one real
// email, one real client address, and the ordinary noise around them — a request id, a
// status, a duration and a user agent long enough that a substring scan has real work.
var httpRequest = []any{
	"request_id", "01HQ8K3M2N7P9Q4R6T8V0W2X4Y",
	"method", "POST",
	"route", "/v1/charges",
	"status", 201,
	"duration_ms", 143,
	"client_ip", "192.168.1.42",
	"user_agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
	"user_email", "jane.doe@example.com",
}

// A payment authorization where the card number is not named by any key. The record
// also carries numbers that look like card numbers and are not: a sixteen-digit order
// id as the payment provider sends it, which is a string, and a thirteen-digit
// millisecond timestamp plus an integer amount, which are not. That distinction
// matters, and TestScenarioValidationLeavesNonCardsAlone reports it rather than
// hiding it: a digit-count pattern only claims the string, and both a validator and a
// pattern leave the integers alone for that reason alone.
var paymentAuthorization = []any{
	"order_id", "1234567890123456",
	"amount_cents", 129900,
	"currency", "BRL",
	"card_number", "4111111111111111",
	"processed_at_ms", 1767225600000,
	"merchant_id", "MRC-88213",
}

// serviceKeys is the configuration an HTTP-facing service would actually install.
var serviceKeys = []string{"user_email", "client_ip"}

// Numbers in the payment record that are not cards. A detector that validates leaves
// all three alone; one that only counts digits claims the string one.
var notCards = []struct {
	what, num, kind string
}{
	{"order id, 16 digits as a string", "1234567890123456", "string"},
	{"millisecond time, 13 digits as an int64", "1767225600000", "int64"},
	{"amount, 6 digits as an int", "129900", "int"},
}

func scenarios() []scenario {
	return []scenario{
		{
			name:   "http_request",
			note:   "one email, one client address, ordinary noise around them",
			record: httpRequest,
			build:  keyRuleBuilders(serviceKeys),
		},
		{
			name:   "payment_authorization",
			note:   "a card under no configured key, beside two numbers that only look like one",
			record: paymentAuthorization,
			build:  panDetectionBuilders(),
		},
		{
			name:   "background_job",
			note:   "nothing sensitive, under the same production configuration",
			record: backgroundJob,
			build:  keyRuleBuilders(serviceKeys),
		},
		{
			name:   "nested_struct",
			note:   "the two secrets inside one struct, under one opaque any",
			record: nestedStruct,
			build:  structFieldBuilders(),
		},
	}
}

// loggedUser is what a service hands to slog when it logs a domain object whole, which
// is the shape most Go code reaches for before it learns to project fields.
type loggedUser struct {
	ID       int
	Email    string
	Password string
}

// A struct logged as a single value. slog hands a handler one opaque any here, so there
// is no group to walk into: masking a field inside it takes reflecting through a struct,
// which is a different capability from naming a key.
var nestedStruct = []any{
	"request_id", "01HQ8K3M2N7P9Q4R6T8V0W2X4Y",
	"user", loggedUser{ID: 4711, Email: "jane.doe@example.com", Password: "correct-horse-battery"},
	"route", "/v1/users/4711",
	"status", 200,
	"duration_ms", 38,
}

// The field names the secrets live under, which is what a key rule inside a struct is
// matched against. cloak normalizes them, so one rule covers `Password`, `password` and
// `PASSWORD`; the other libraries spell them out.
var nestedFieldNames = []string{"email", "password"}

// structFieldBuilders configures each library for a struct logged as one value.
//
// Only cloak and masq can be configured for the job itself — replace two fields and keep
// the rest — because only they reflect into an slog.Any value. The others have no
// equivalent here and are absent rather than configured for something they cannot do:
//
//   - redactlog's path DSL descends into slog groups and not into structs, and its trie
//     is compiled case-sensitively, so `user.Email` matches a group key but never a Go
//     field. Given a struct, its only move is to mask the whole value. That stops the
//     leak and discards the id with it, so it is excluded from the speed table and
//     measured on its own below, where losing the id is the point.
//   - go-slog-redact, sensitive and alesr/redact match a top-level key against a string
//     value and have no way in at all.
func structFieldBuilders() map[string]func(io.Writer) (*slog.Logger, error) {
	masqHandler := func(w io.Writer, opts ...masq.Option) (*slog.Logger, error) {
		return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{
			ReplaceAttr: masq.New(opts...),
		})), nil
	}
	// masq matches the Go field name, spelled exactly.
	masqFields := make([]masq.Option, 0, len(nestedFieldNames))
	for _, f := range nestedFieldNames {
		masqFields = append(masqFields, masq.WithFieldName(strings.ToUpper(f[:1])+f[1:]))
	}
	// The escape hatch for the built-in time attribute: masq deep-clones whatever it is
	// handed, and a time.Time carries a *time.Location, so without this the clock
	// dominates the row and the comparison stops being about the struct.
	masqFieldsPlusTime := append(slices.Clone(masqFields),
		masq.WithAllowedType(reflect.TypeFor[time.Time]()))

	return map[string]func(io.Writer) (*slog.Logger, error){
		"bare": func(w io.Writer) (*slog.Logger, error) {
			return slog.New(slog.NewJSONHandler(w, nil)), nil
		},
		"cloak": func(w io.Writer) (*slog.Logger, error) {
			return slog.New(cloak.New(slog.NewJSONHandler(w, nil),
				cloak.WithStructScan(),
				cloak.WithKeys(cloak.Redact, nestedFieldNames...))), nil
		},
		"masq":              func(w io.Writer) (*slog.Logger, error) { return masqHandler(w, masqFields...) },
		"masq+allowed-time": func(w io.Writer) (*slog.Logger, error) { return masqHandler(w, masqFieldsPlusTime...) },
	}
}

// A background worker that turned out to hold nothing sensitive, which is most of a
// background worker. It answers the question a service owner actually has: what does
// the wrapper cost per line once installed.
var backgroundJob = []any{
	"job_id", "job_01HQ8K3M2N",
	"queue", "emails",
	"attempt", 3,
	"duration_ms", 412,
	"batch_size", 500,
	"region", "sa-east-1",
	"replica", "b",
	"outcome", "ok",
}

// keyRuleBuilders configures every library with the same keys, which is the only
// masking all of them do.
func keyRuleBuilders(keys []string) map[string]func(io.Writer) (*slog.Logger, error) {
	out := map[string]func(io.Writer) (*slog.Logger, error){}
	for _, l := range libraries() {
		out[l.name] = func(w io.Writer) (*slog.Logger, error) { return l.buildKeys(w, keys) }
	}
	return out
}

// panDetectionBuilders configures content detection with no key rules anywhere, so the
// comparison is about finding a card number and not about naming a field.
//
// redactlog's PANDetector and cloak's MaskPAN are the same algorithm: locate thirteen
// to nineteen digits, then reject with Luhn. That makes this an equivalent test rather
// than two different jobs. masq is given the pattern matching it asks for, which is
// what a regex-based library does and what the false-positive check measures.
func panDetectionBuilders() map[string]func(io.Writer) (*slog.Logger, error) {
	panPattern := regexp.MustCompile(`\d{13,19}`)
	return map[string]func(io.Writer) (*slog.Logger, error){
		// The baseline the other rows are read against.
		"bare": func(w io.Writer) (*slog.Logger, error) {
			return slog.New(slog.NewJSONHandler(w, nil)), nil
		},
		"cloak": func(w io.Writer) (*slog.Logger, error) {
			return slog.New(cloak.New(slog.NewJSONHandler(w, nil),
				cloak.WithValueFunc(cloak.MaskPAN))), nil
		},
		"redactlog": func(w io.Writer) (*slog.Logger, error) {
			cfg := redactlog.Config{
				Logger:    slog.New(slog.NewJSONHandler(w, nil)),
				Detectors: []redact.Detector{redact.PANDetector()},
			}
			h, err := cfg.Build()
			if err != nil {
				return nil, err
			}
			return slog.New(h), nil
		},
		"masq": func(w io.Writer) (*slog.Logger, error) {
			return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{
				ReplaceAttr: masq.New(masq.WithRegex(panPattern)),
			})), nil
		},
	}
}

// Every library that can do content detection here must find the card, or the speed
// table is measuring a no-op.
func TestScenarioEveryParticipantFindsTheCard(t *testing.T) {
	for _, s := range scenarios() {
		if s.name != "payment_authorization" {
			continue
		}
		for name, build := range s.build {
			if name == "bare" {
				continue // the baseline is not expected to mask
			}
			t.Run(name, func(t *testing.T) {
				var b bytes.Buffer
				logger, err := build(&b)
				if err != nil {
					t.Fatalf("configuring %s: %v", name, err)
				}
				logger.Info("charge", s.record...)

				if bytes.Contains(b.Bytes(), []byte("4111111111111111")) {
					t.Errorf("%s missed the card: %s", name, b.String())
				}
				t.Logf("%-10s %s", name, b.String())
			})
		}
	}
}

// The point of validating rather than matching. A number that is not a card has to
// survive, whether it is sixteen or thirteen digits long; both are inside the range a
// digit-count pattern claims.
func TestScenarioValidationLeavesNonCardsAlone(t *testing.T) {
	for _, s := range scenarios() {
		if s.name != "payment_authorization" {
			continue
		}
		for name, build := range s.build {
			if name == "bare" {
				continue
			}
			t.Run(name, func(t *testing.T) {
				var b bytes.Buffer
				logger, err := build(&b)
				if err != nil {
					t.Fatalf("configuring %s: %v", name, err)
				}
				logger.Info("charge", s.record...)

				got := b.String()
				var claimed []string
				for _, nc := range notCards {
					if !strings.Contains(got, nc.num) {
						claimed = append(claimed, nc.what)
					}
				}
				switch len(claimed) {
				case 0:
					t.Logf("%-10s left every non-card alone", name)
				default:
					t.Logf("%-10s also masked %v, which are not cards: %s",
						name, claimed, got)
				}
			})
		}
	}
}

// Every library in the nested_struct scenario must stop the password, or the speed table
// is measuring a no-op.
func TestNestedStructNobodyLeaksThePassword(t *testing.T) {
	for _, s := range scenarios() {
		if s.name != "nested_struct" {
			continue
		}
		for name, build := range s.build {
			if name == "bare" {
				continue // the baseline is not expected to mask
			}
			t.Run(name, func(t *testing.T) {
				var b bytes.Buffer
				logger, err := build(&b)
				if err != nil {
					t.Fatalf("configuring %s: %v", name, err)
				}
				logger.Info("user loaded", s.record...)

				if bytes.Contains(b.Bytes(), []byte("correct-horse-battery")) {
					t.Errorf("%s leaked the password out of the struct: %s", name, b.String())
				}
				t.Logf("%-18s %s", name, b.String())
			})
		}
	}
}

// Who reaches inside a struct and who gives up on it, at each library's best attempt
// rather than at the configuration that suits cloak. Three outcomes are possible and
// they are not variations on the same one:
//
//	field — the two secrets are replaced and the id survives
//	value — the whole value is masked, so nothing leaks and the id is gone
//	leak  — the password reaches the sink
//
// The middle one is the reason this is a separate check instead of a note: a library
// that cannot reflect into a value has no third option, and masking the whole value
// looks like success from a grep for the secret.
//
// The id is looked for as `"ID":4711` rather than as the bare number, because the route
// in this record also contains 4711 and a search for the number alone proves nothing.
//
// The expectations are pinned rather than logged, because a dependency gaining struct
// support is exactly the event this table exists to catch. When one does, the failure is
// the news: re-measure and update the pin and the README together.
func TestNestedStructReachesTheFieldOrDropsTheValue(t *testing.T) {
	const (
		leak  = "leak"
		value = "value"
		field = "field"
	)
	want := map[string]string{
		"bare":                               leak,
		"cloak":                              field,
		"masq":                               field,
		"masq+allowed-time":                  field,
		"redactlog user.Email,user.Password": leak, // no spelling of a path descends into a struct
		"redactlog user":                     value,
		"go-slog-redact":                     leak,
		"sensitive":                          leak,
		"alesr/redact":                       leak,
	}
	// Present only if the struct was reflected into and kept its fields.
	const expandedStruct = `"ID":4711`

	for _, attempt := range nestedStructAttempts() {
		t.Run(attempt.name, func(t *testing.T) {
			var b bytes.Buffer
			logger, err := attempt.build(&b)
			if err != nil {
				t.Fatalf("configuring %s: %v", attempt.name, err)
			}
			logger.Info("user loaded", nestedStruct...)
			got := b.String()

			var outcome string
			switch {
			case strings.Contains(got, "correct-horse-battery"):
				outcome = leak
			case !strings.Contains(got, expandedStruct):
				outcome = value
			default:
				outcome = field
			}
			if outcome != want[attempt.name] {
				t.Errorf("%s: got %q, want %q\n%s", attempt.name, outcome, want[attempt.name], got)
			}
			t.Logf("%-34s %-5s %s", attempt.name, outcome, got)
		})
	}
}

type namedBuild struct {
	name  string
	build func(io.Writer) (*slog.Logger, error)
}

// nestedStructAttempts is every library's honest best attempt at the nested_struct
// record, including the ones excluded from its speed table because they cannot do the
// job. Reporting a boundary means showing what the other side of it does.
func nestedStructAttempts() []namedBuild {
	out := []namedBuild{
		{"bare", func(w io.Writer) (*slog.Logger, error) {
			return slog.New(slog.NewJSONHandler(w, nil)), nil
		}},
	}
	for _, s := range scenarios() {
		if s.name != "nested_struct" {
			continue
		}
		for name, build := range s.build {
			if name == "bare" {
				continue
			}
			out = append(out, namedBuild{name, build})
		}
	}

	// redactlog twice: the configuration that names the fields, and the only one it can
	// fall back to when handed a struct instead of a group.
	for _, paths := range [][]string{
		{"user.Email", "user.Password"},
		{"user"},
	} {
		out = append(out, namedBuild{"redactlog " + strings.Join(paths, ","), func(w io.Writer) (*slog.Logger, error) {
			cfg := redactlog.Config{
				Logger:      slog.New(slog.NewJSONHandler(w, nil)),
				RedactPaths: paths,
			}
			h, err := cfg.Build()
			if err != nil {
				return nil, err
			}
			return slog.New(h), nil
		}})
	}

	for _, l := range libraries() {
		switch l.name {
		case "go-slog-redact", "sensitive", "alesr/redact":
		default:
			continue
		}
		out = append(out, namedBuild{l.name, func(w io.Writer) (*slog.Logger, error) {
			return l.buildKeys(w, nestedFieldNames)
		}})
	}
	return out
}

func BenchmarkScenario(b *testing.B) {
	for _, s := range scenarios() {
		record, build := s.record, s.build
		for name, mk := range build {
			b.Run(s.name+"/"+name, func(b *testing.B) {
				logger, err := mk(io.Discard)
				if err != nil {
					b.Fatalf("configuring %s: %v", name, err)
				}
				b.ReportAllocs()
				for b.Loop() {
					logger.Info("event", record...)
				}
			})
		}
	}
}

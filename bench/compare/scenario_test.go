package compare

import (
	"bytes"
	"io"
	"log/slog"
	"regexp"
	"strings"
	"testing"

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
		l := l
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

func BenchmarkScenario(b *testing.B) {
	for _, s := range scenarios() {
		record, build := s.record, s.build
		for name, mk := range build {
			mk := mk
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

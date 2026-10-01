# cloak

[![Go Reference](https://pkg.go.dev/badge/github.com/lrweck/cloak.svg)](https://pkg.go.dev/github.com/lrweck/cloak)
[![Go Report Card](https://goreportcard.com/badge/github.com/lrweck/cloak)](https://goreportcard.com/report/github.com/lrweck/cloak)

A [slog.Handler](https://pkg.go.dev/log/slog#Handler) that masks PII before it
reaches your log sink.

```go
logger := slog.New(cloak.New(
    slog.NewJSONHandler(os.Stdout, nil),
    cloak.WithDefaultPII(),
))
```

Cloak wraps the handler you already use. Everything else in your code stays as-is.

## Why

PII reaches logs by accident, not by decision:

```go
slog.Info("login", "email", user.Email)                    // someone will forget
slog.Info("user " + user.Email + " logged in")             // PII in the message
slog.Info("loaded", "user", user)                          // a whole struct
slog.WithGroup("req").Info("done", "cpf", doc.Number)      // nested, easy to miss
slog.InfoContext(ctx, "checkout started")                  // PII riding in the context
```

Once written, it is already in your aggregator, your backups and someone else's
dashboard. Scrubbing it afterwards is a project; not writing it is one wrapper.

Cloak sits at the handler, so it covers every call site in the program — including
the ones nobody reviewed.

## Install

```
go get github.com/lrweck/cloak
```

Requires Go 1.27. No dependencies.

## Usage

```go
package main

import (
    "log/slog"
    "os"

    "github.com/lrweck/cloak"
)

func main() {
    handler := cloak.New(
        slog.NewJSONHandler(os.Stdout, nil),
        cloak.WithDefaultPII(),
    )
    slog.SetDefault(slog.New(handler))
}
```

```
{"time":"...","level":"INFO","msg":"payment","email":"j***@example.com","card":"****1111"}
```

## Capabilities

### Key masking

The strongest rule, and the one to reach for when you know the field.

```go
handler := cloak.New(next, cloak.WithKey(cloak.KeepLast(4), "card_number"))
```

Keys are normalized before lookup: case is folded and `_`, `-`, spaces and tabs are
ignored. So `card_number`, `cardNumber`, `CARD-NUMBER` and `Card Number` are all the
same rule, from one entry.

Dots are kept, since they separate namespaces. For qualified names that a whole-key
match cannot see:

```go
cloak.WithKeyContains(cloak.Redact, "password")   // covers db.password, user_password
```

It is looser — `token` also matches `tokens_used` — so prefer `WithKey` unless the
prefixes are known.

### Value detectors

A cheap structural pre-filter runs first, then the exact validation the format
requires (Luhn for card numbers, check digits for CPF/CNPJ, MOD-97 for IBAN). A
string only pays for the expensive check when it could plausibly match, which is what
keeps false positives down. Measured on typical non-PII log lines:

```
UUID    1.9 ns    length check, cheapest
IPv4    4.9 ns    requires "."
Email   5.0 ns    requires "@"
CNPJ   16   ns    needs 14 digits
PAN    16   ns    needs 13 digits
SSN    17   ns    needs 9 digits
CPF    18   ns    needs 11 digits
Phone  23   ns    needs 7 digits
IBAN   28   ns    needs the AA99 shape
```

The detectors run cheapest-gate-first, but that order buys no speed on its own: all of
them run on every string, so the cost is the sum either way. What the order buys is
correctness, because `maskString` chains and each detector sees the previous one's
output. That is why IPv4 runs before SSN — `192.168.1.42` is exactly nine digits, so
SSN first would turn the most common private address into `***-**-****` and leave IPv4
nothing to match. `MaskPhone` is last because it claims almost any run of digits,
documents included.

| Detector | Detects | Validation |
| --- | --- | --- |
| `MaskPAN` | Card numbers | Luhn, 13–19 digits |
| `MaskCPF` | Brazilian CPF | Both check digits |
| `MaskCNPJ` | Brazilian CNPJ | Both check digits |
| `MaskSSN` | US SSN | Structural ranges (no check digit exists) |
| `MaskIBAN` | IBAN | MOD-97 checksum |
| `MaskEmail` | Email addresses | Local part + domain syntax |
| `MaskIPv4` | IPv4 addresses | Octet range, no leading zeros |
| `MaskUUID` | Canonical UUIDs | Dash placement, hex digits |
| `MaskPhone` | Phone numbers | 7–15 digits, heuristic |

Detectors run over the whole string, so a value buried in a sentence is still caught:

```
"cpf 529.982.247-25"                      -> "cpf ***.***.***-**"
"user 42 cpf 529.982.247-25"              -> "user 42 cpf ***.***.***-**"
"card 4111 1111 1111 1111 order 42"       -> "card ****1111 order 42"
```

Add your own with any `func(string) (string, bool)`:

```go
cloak.WithValueFunc(func(s string) (string, bool) { ... })
```

### Maskers

How a matched key is rewritten.

| Masker | `4111111111111111` |
| --- | --- |
| `Redact` | `[REDACTED]` |
| `Fixed("***")` | `***` |
| `KeepLast(4)` | `************1111` |
| `KeepFirst(4)` | `4111************` |
| `KeepEnds(4, 4)` | `4111********1111` |
| `MaskMiddle(4, 4)` | alias of `KeepEnds` |

Maskers operate on the string form of the value. They are rune-aware, so
multibyte text is not cut mid-character.

### Groups and nesting

Groups are walked recursively, and every attribute is preserved — the ones that
matched and the ones that did not.

```go
slog.Group("user",
    slog.Int("id", 7),                          // kept
    slog.String("email", "john@example.com"),    // masked
    slog.String("name", "Jane"),                 // kept
)
// user.id=7 user.email=[REDACTED] user.name=Jane
```

### Structs, maps and slices

`slog.Any` hands the handler one opaque value, so a struct's fields, a map's entries
and a slice's elements are never reached by attribute rules. `%+v` does not save you:
it renders `[]*User` as `[0xc000...]` addresses, printing no PII but also masking
nothing.

Reflection fixes that. One option per shape, plus a combined one:

```go
handler := cloak.New(next,
    cloak.WithDefaultPII(),
    cloak.WithStructScan(),   // slog.Any("user", User{Email: ...})
    cloak.WithMapScan(),      // slog.Any("ctx", map[string]any{"email": ...})
    cloak.WithSliceScan(),    // slog.Any("emails", []string{...})
)

// Or all three at once:
handler := cloak.New(next, cloak.WithDefaultPII(), cloak.WithCompositeScan())
```

Each option is scoped to its shape, so `WithStructScan()` leaves slices alone. Every
option also follows pointers, since passing a struct by pointer is the common case.

How it works:

- The value keeps its type. Only the offending fields change, so the record still logs
  a structured object rather than a stringified blob.
- Fields are matched by name first (`Email` hits an `email` rule), then by value. A key
  rule always wins over a detector.
- A copy is built only when something changed, so untouched values pass through by
  identity with no allocation.
- `[]byte` is deliberately skipped: it is data, not a container of things to log, and
  walking it would rewrite a payload into decimal digits.
- `slog:"-"` fields are skipped. Unexported fields keep their original value, since
  reflection cannot write them.
- Nesting recurses, through pointers, slices of slices, and maps of structs.
- Walking stops at 32 levels, so a self-referential structure cannot hang the logger.

When a masked value cannot be represented in its original type — a `[]LogValuer`, or a
map keyed by a struct whose `LogValue()` returns something else — the container widens
to `[]any` or `map[string]any` rather than keeping the unmasked original.

Nesting composes: `[]map[string][]User`, `map[string]map[string]User` and
`map[User]any` all work, in any combination. Two consequences worth knowing:

- Masking a map key can make two distinct keys equal, in which case their entries
  merge. That is inherent to masking keys; nothing leaks, but an entry can be lost.
- A struct map key is fine on `TextHandler`, but `slog`'s `JSONHandler` rejects it
  outright — a Go limitation, present with or without cloak.

### LogValuer

`slog.LogValuer` takes precedence, because a value that knows how to log itself has
already decided what it exposes. Cloak resolves it first, then masks what came out:

```go
type Email string
func (Email) LogValue() slog.Value { return slog.StringValue("john@example.com") }

// with WithDefaultPIIValues() enabled:
slog.Info("m", "mail", Email("x"))   // cloak logs mail=j***@example.com
```

Without this, masking would look at the struct behind `LogValue()` and miss the string
the author actually meant to emit. The result is resolved once, so the wrapped handler
never evaluates `LogValue()` again.

### Options

| Option | Effect |
| --- | --- |
| `WithKey(mask, keys...)` | Mask whole-key matches |
| `WithKeyContains(mask, keys...)` | Mask substring matches |
| `WithValueFunc(fn)` | Add a value detector |
| `WithDefaultPII()` | Preset: keys plus detectors |
| `WithDefaultPIIKeys()` | Preset: keys only, no value scanning |
| `WithDefaultPIIValues()` | Preset: detectors only |
| `WithSkipValueScan(keys...)` | Never scan these keys' values |
| `WithMessageScan()` | Also scan the log message |
| `WithStructScan()` | Walk `slog.Any` structs |
| `WithMapScan()` | Walk `slog.Any` maps |
| `WithSliceScan()` | Walk `slog.Any` slices |
| `WithCompositeScan()` | All three composite options |
| `WithContextAttrs(pulls...)` | Copy masked context values onto every record |
| `New(nil, ...)` | Discard everything; useful in tests |

For custom detectors, order your own `WithValueFunc` list the same way: cheapest gate
first, and put any loose heuristic last.

Reflection runs only when a composite option is on. Without one, `reflect` is never
called on the logging path.

### Values from the context

A value carried in a context is attached once, usually far from the log call that will
expose it:

```go
ctx = context.WithValue(ctx, userKey, user)   // middleware, no logging in sight
slog.InfoContext(ctx, "checkout started")     // somewhere else, entirely
```

`WithContextAttrs` registers functions that pull values out of the context, so no
call site can leak one by forgetting a field:

```go
// package auth — owns the unexported key
func LogAttrs(ctx context.Context) []slog.Attr {
    u, ok := userFrom(ctx)          // uses the private key
    if !ok {
        return nil
    }
    return []slog.Attr{slog.Any("user", u)}
}

// package main
handler := cloak.New(next,
    cloak.WithDefaultPII(),
    cloak.WithStructScan(),
    cloak.WithContextAttrs(auth.LogAttrs, reqid.LogAttrs),
)
```

```json
{"msg":"checkout started","user":{"ID":7,"Email":"[REDACTED]","CPF":"[REDACTED]"},"request_id":"req-abc-123"}
```

**Why a function and not a context key.** The idiomatic key is an unexported type, so
naming it from the package that configures logging does not compile — and exporting it
just to configure a logger gives up the collision safety that makes the private type
worth having. The pull function lives where the key is reachable, so the key never
leaves its package. It also suits sources that are not context values at all, such as
request-scoped state held by a web framework, and can compute a value rather than
merely read one.

Masking is not special-cased: whatever a pull returns goes through exactly the same
path as an attribute you logged yourself, so key rules, detectors, composite walks,
`LogValuer` precedence and `WithSkipValueScan` all apply. Return `nil` for anything
absent, so a missing value is skipped rather than logged as null.

**A struct value still needs a composite option.** `WithStructScan()` or
`WithCompositeScan()` — otherwise the struct stays one opaque value and its fields are
not reached, exactly as with `slog.Any`. Cloak does not turn reflection on implicitly,
so that cost stays opt-in.

### The message

The message is free text that nothing marks as data, and `slog.Info("user " + email)`
is routine. `WithMessageScan()` runs the detectors over it:

```go
handler := cloak.New(next,
    cloak.WithDefaultPII(),
    cloak.WithMessageScan(),
)
```

It is off by default because it rewrites text nobody asked to rewrite. Turn it on when
the leak matters more than the log's readability.

### Skipping

For values you deliberately keep verbatim:

```go
cloak.WithSkipValueScan("raw_payload", "request_body")
```

Key masking still applies to these keys. Only the value scan is skipped.

## Default preset

`WithDefaultPII()` turns on 102 keys and 9 detectors, covering credentials and auth
(`password`, `token`, `apiKey`, `authorization`, `cookie`, `session`, `privateKey`),
identity documents (`cpf`, `cnpj`, `taxId`, `passport`, `driverLicense`, `ssn`),
contact (`email`, `phone`, `telephone`, `mobile`), location (`address`, `zip`, `cep`),
birth date, payment (`creditCard`, `cardNumber`, `pan`, `cvv`, `iban`) and bank
identifiers (`accountNumber`, `routingNumber`, `sortCode`).

Generic keys like `id`, `name` and `user` are deliberately excluded — they carry more
signal than PII, and masking them would make logs useless. Add them yourself if your
schema calls for it.

Value scanning is heuristic, so prefer `WithDefaultPIIKeys()` where masking by key is
enough. `MaskPhone` in particular will mask any long number, including IDs and
timestamps.

## Performance

Cloak adds ~30ns and no allocations to a record with no PII:

```
BenchmarkLog/passthrough-20          810.1 ns/op    320 B/op    6 allocs/op
BenchmarkLog/default_pii-20          836.1 ns/op    320 B/op    6 allocs/op
BenchmarkLogWithPII/default_pii-20  1139 ns/op     392 B/op   11 allocs/op
```

Key lookup is a single map hit (~8ns). The cost shows up only when a value detector
actually fires and a new record has to be built.

Turning on a composite option costs nothing when the logged shape does not match it,
because the kind is checked first:

```
BenchmarkCompositeScan/disabled-20    1015 ns/op    104 B/op    3 allocs/op
BenchmarkCompositeScan/map-20          958 ns/op    104 B/op    3 allocs/op
BenchmarkCompositeScan/slice-20       1001 ns/op    104 B/op    3 allocs/op
BenchmarkCompositeScan/struct-20      1634 ns/op    513 B/op   17 allocs/op
```

The struct case is the expensive one, since it rebuilds the value through reflection.

## Testing

```
go test ./...
go test -bench . -benchmem ./...
```

## License

MIT
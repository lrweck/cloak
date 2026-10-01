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
keeps false positives down.

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

### LogValuer

A `LogValue()` result is resolved once and inspected as a value, so a `LogValuer` is
never re-evaluated by the wrapped handler.

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
| `WithAnyScan()` | Also scan `slog.Any` values |
| `New(nil, ...)` | Discard everything; useful in tests |

### Two gaps worth knowing about

`slog.Info` has two places a value can hide that attribute rules do not reach by
default, so both are opt-in.

**The message.** Nothing marks it as data, and `slog.Info("user " + email)` is
routine. `WithMessageScan()` runs the detectors over it.

**`slog.Any` with a struct.** A struct is one opaque value, so its fields are never
inspected and `%+v` prints them all. `WithAnyScan()` renders it the way the wrapped
handler would and scans the result, at the cost of turning that attribute into a
masked string.

```go
handler := cloak.New(next,
    cloak.WithDefaultPII(),
    cloak.WithMessageScan(),
    cloak.WithAnyScan(),
)
```

Both are off by default on purpose: they rewrite text nobody asked to rewrite, and a
caller who knows a field is sensitive should name it with `WithKey` instead. Turn them
on when the leak matters more than the log's readability.

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
BenchmarkLog/passthrough-20          820.6 ns/op    320 B/op    6 allocs/op
BenchmarkLog/default_pii-20          843.4 ns/op    320 B/op    6 allocs/op
BenchmarkLogWithPII/default_pii-20  1139 ns/op     392 B/op   11 allocs/op
```

Key lookup is a single map hit (~8ns). The cost shows up only when a value detector
actually fires and a new record has to be built.

## Testing

```
go test ./...
go test -bench . -benchmem ./...
```

## License

MIT
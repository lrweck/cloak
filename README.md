# cloak

[![Go Reference](https://pkg.go.dev/badge/github.com/lrweck/cloak.svg)](https://pkg.go.dev/github.com/lrweck/cloak)
[![Go Report Card](https://goreportcard.com/badge/github.com/lrweck/cloak)](https://goreportcard.com/report/github.com/lrweck/cloak)

A [slog.Handler](https://pkg.go.dev/log/slog#Handler) that masks personal data before it
reaches your log sink.

```go
logger := slog.New(cloak.New(slog.NewJSONHandler(os.Stdout, nil),
    cloak.WithDefaultPII(),))
```

Cloak wraps the handler you already use. Nothing else in your code changes.

## Why

Personal data gets into logs by accident, not by decision:

```go
slog.Info("login", "email", user.Email)                 // someone forgets
slog.Info("user " + user.Email + " logged in")          // in the message
slog.Info("loaded", "user", user)                       // a whole struct
slog.WithGroup("req").Info("done", "cpf", doc.Number)   // nested
slog.InfoContext(ctx, "checkout started")               // carried in the context
```

Once written, it is already in your aggregator, your backups and someone else's
dashboard. Scrubbing it afterwards is a project. Not writing it is one wrapper.

Cloak sits at the handler, so it covers every call site in the program — including the
ones nobody reviewed.

## Install

```
go get github.com/lrweck/cloak
```

Go 1.27 or newer. No dependencies.

## Getting started

```go
package main

import ("log/slog"
    "os"

    "github.com/lrweck/cloak")

func main() {
    slog.SetDefault(slog.New(cloak.New(slog.NewJSONHandler(os.Stdout, nil),
        cloak.WithDefaultPII(),)))

    slog.Info("payment", "email", "john@example.com", "amount", 1299)
}
```

```json
{"time":"...", "level":"INFO", "msg":"payment", "email":"[REDACTED]", "amount":1299}
```

`email` is in the preset's key list, and a key rule outranks the detector that would
otherwise have produced `j***@example.com`.

## How it works

Every attribute goes through the same pipeline, and the **first rule that matches
wins**:

```
key        WithKeys             exact match on the name
           WithKeyRegex        pattern against the name
           WithKeysContaining  substring of the name
tag        WithTag              the field carries this struct tag
type       WithType[T]          the value has this Go type
value      WithValueRule        your predicate accepts it
           WithContain          it contains a secret you know
           detectors            it looks like PAN, CPF, email, IP, UUID...
```

That order is fixed and does not depend on the order you pass options. It runs from most
explicit to most inferred: a key rule names the field, a detector only guesses from the
shape of a string.

Three consequences fall out of it:

- **A key rule beats a detector.** `WithKeys(KeepLast(4), "card_number")` keeps the last
  four digits instead of the full redaction the preset would apply.
- **Rules reach inside data.** Once a composite option is on, struct fields, map values
  and slice elements each go through the whole pipeline.
- **A name means the same thing wherever it lives.** A struct field and a map entry walk
  through different code, but the same rules over the same name answer the same way —
  `WithSkipValueScan("payload")` is honoured in a map exactly as in a field.
  `TestMapAndStructAgreeOnEveryRule` compares the two paths so they cannot drift again.
- **`slog.LogValuer` is resolved first.** A value that knows how to log itself has
  already decided what it exposes, so that is what gets masked.

## How the options are shaped

Every option that takes a masker takes it **first**:

```go
cloak.WithKeys(cloak.KeepLast(4), "card_number")
cloak.WithKeysContaining(cloak.Redact, "password")
cloak.WithKeyRegex(cloak.Redact, `^x-.*-token$`)
cloak.WithTag(cloak.Redact, "cloak", "secret")
cloak.WithValuePredicate(cloak.Redact, pred)
```

That is not taste, it is Go. The subject of a key rule is a variadic list, and a variadic
parameter has to come last — so a masker in the final position is impossible for exactly
the options people reach for most. First position gives one rule with nothing to
remember.

An option that takes several subjects says so in its name: `WithKeys`,
`WithKeysContaining`. One that takes a single pattern or a single tag does not.

## Matching a key

The most direct rule, and the one to reach for when you know the field.

```go
cloak.WithKeys(cloak.Redact, "password", "card_number")
cloak.WithKeys(cloak.KeepLast(4), "card_number")   // keep the last 4 characters
```

Names are normalized before lookup: case is folded, and `_`, `-`, spaces and tabs are
ignored. So `card_number`, `cardNumber`, `CARD-NUMBER` and `Card Number` are one rule
from one entry.

For qualified names a whole-key match cannot see:

```go
cloak.WithKeysContaining(cloak.Redact, "password")   // db.password, user_password
```

It is looser — `token` also matches `tokens_used` — so prefer `WithKeys` unless you know
the prefixes.

For an anchor, which a substring cannot express:

```go
cloak.WithKeyRegex(cloak.Redact, `_key$`)          // api_key, x_api_key
cloak.WithKeyRegex(cloak.Redact, `^x-.*-token$`)   // x-auth-token
```

Patterns match the name **as written**. `normalizeKey` strips the underscores and hyphens
a pattern usually anchors on, so `_key$` would match nothing against the normalized form.

`WithKeyRegex` compiles with `MustCompile`, so a typo panics at startup instead of
becoming a rule that quietly matches nothing. Use `WithKeyRegexp` to handle the compile
error yourself.

Literal patterns are resolved when you build the handler, because Go's `regexp` is a
backtracker and a case-insensitive alternation is expensive:

```
(?i)pass|secret|token     958 ns/op   resolved to three substring tests
(?i)(pass|secret|token)  1693 ns/op   the same pattern, left to regexp
```

A bare literal is left to `regexp`, which already handles those well — the resolution
costs more than it saves when there is nothing to split.

## Matching a value

### Detectors

A cheap structural check runs first, then the exact validation the format requires. A
string only pays for the expensive check when it could plausibly match, which is what
keeps false positives down.

| Detector | Detects | Validation |
| --- | --- | --- |
| `MaskPAN` | Card numbers | Luhn, 13–19 digits |
| `MaskCPF` | Brazilian CPF | Both check digits |
| `MaskCNPJ` | Brazilian CNPJ | Both check digits |
| `MaskSSN` | US SSN | Structural ranges (no check digit exists) |
| `MaskIBAN` | IBAN | MOD-97 checksum |
| `MaskEmail` | Email addresses | Local part and domain syntax |
| `MaskIPv4` | IPv4 addresses | Octet range, no leading zeros |
| `MaskUUID` | Canonical UUIDs | Dash placement, hex digits |
| `MaskPhone` | Phone numbers | 7–15 digits, heuristic |

Detectors scan the whole string, so a value buried in a sentence is still caught:

```
"cpf 529.982.247-25"                 -> "cpf ***.***.***-**"
"user 42 cpf 529.982.247-25"         -> "user 42 cpf ***.***.***-**"
"card 4111 1111 1111 1111 order 42"  -> "card ****1111 order 42"
```

The order of the detectors matters for correctness, not speed. IPv4 runs before SSN
because `192.168.1.42` is exactly nine digits and would otherwise be masked as a social
security number. `MaskPhone` is last because it claims almost any run of digits.

### Your own rules

A detector is any `func(string) (string, bool)`:

```go
cloak.WithValueFunc(func(s string) (string, bool) {
    if strings.HasPrefix(s, "sk_live_") {
        return "sk_live_***", true
    }
    return s, false
})
```

Detectors only ever see strings. To reach an int, a duration, a time or a bool, use a
value rule:

```go
cloak.WithValuePredicate(cloak.Redact, func(v slog.Value) bool {
        return v.Kind() == slog.KindInt64 && v.Int64() > 1_000_000_000_000
    })
```

Use `WithValueRule` when deciding and replacing are separate, or when you want to
rewrite rather than only mask:

```go
cloak.WithValueRule(func(v slog.Value) (slog.Value, bool) {
    if v.Kind() != slog.KindDuration {
        return v, false
    }
    return slog.StringValue("slow"), true
})
```

A value rule is not applied to a group, since replacing one would discard its structure
rather than mask it.

## Matching a type

The strongest rule, and the hardest to misuse. Define a type and it is masked wherever it
appears:

```go
type EmailAddr string
type Password  string

cloak.WithType[EmailAddr]()
cloak.WithType[Password]()
```

```go
type Login struct {
    User     string
    Password Password
}
slog.Info("login", "user", "jane", "password", Password("hunter2"))
// password=[REDACTED]
```

The compiler rejects a type that does not exist, the value cannot be logged under a name
nobody remembered to add to a preset, and there are no false positives.

It also reaches what the detectors cannot: `slog` stores a value of a named type as
`KindAny`, not `KindString`, so `MaskEmail` and friends never see it.

## Matching a tag

The most durable way to mark a field, since renaming it does not lose the rule:

```go
type Account struct {
    ID       int
    Password string `cloak:"secret"`
}

cloak.WithTag(cloak.Redact, "cloak", "secret")
```

The tag key is part of the rule, so rules for different namespaces coexist.

## Matching a secret you already know

For when you hold the secret but not the field it will turn up in:

```go
cloak.WithContain("sk_live_51H8xQ2")
```

A token spliced into a URL, an error quoting a response body, an auth header assembled
by a client — none carry a field name worth matching, and no format detector knows what
your token looks like. It applies to the message and to every attribute. The whole value
is replaced rather than the substring, since the rest of it may carry more of the same
secret.

## Reaching inside data

### Groups

Groups are walked recursively, and every attribute is preserved, matched or not:

```go
slog.Group("user",
    slog.Int("id", 7),                        // kept
    slog.String("email", "john@example.com"), // masked
    slog.String("name", "Jane"),              // kept)
// user.id=7 user.email=[REDACTED] user.name=Jane
```

### Structs, maps and slices

`slog.Any` hands the handler one opaque value, so a struct's fields, a map's entries and
a slice's elements are not reached by attribute rules. `%+v` does not save you: it renders
`[]*User` as `[0xc000...]` addresses, printing no PII but also masking nothing.

Reflection fixes that. One option per shape, plus a combined one:

```go
cloak.WithStructScan()    // slog.Any("user", User{Email: ...})
cloak.WithMapScan()       // slog.Any("ctx", map[string]any{"email": ...})
cloak.WithSliceScan()     // slog.Any("emails", []string{...})
cloak.WithCompositeScan() // all three
```

Each is scoped to its shape, so `WithStructScan()` leaves slices alone. All of them
follow pointers, since passing a struct by pointer is the common case.

What to expect:

- The value **keeps its type**. Only the offending fields change, so the record still logs
  a structured object rather than a stringified blob.
- Fields are matched by name first, then by value. A key rule always wins.
- A copy is built only when something changed, so untouched values pass through with no
  allocation.
- Nesting recurses: `[]map[string][]User` and `map[string]map[string]User` both work.
- Walking stops at 32 levels, so a self-referential structure cannot hang the logger.
- `[]byte` is skipped on purpose. It is data, not a container of things to log, and
  walking it would rewrite a payload into decimal digits.

Reflection runs only when a composite option is on. Without one, `reflect` is never called
on the logging path.

### LogValuer

`slog.LogValuer` takes precedence, because a value that knows how to log itself has
already decided what it exposes. Cloak resolves it first, then masks what came out:

```go
type Email string
func (Email) LogValue() slog.Value { return slog.StringValue("john@example.com") }

// with WithDefaultPIIValues() enabled
slog.Info("m", "mail", Email("x"))   // mail=j***@example.com
```

The result is resolved once, so the wrapped handler never evaluates `LogValue()` again.

## The two places a value hides

### In the log message

The message is free text that nothing marks as data, and `slog.Info("user " + email)` is
routine.

```go
cloak.WithMessageScan()
```

It is off by default because it rewrites text nobody asked to rewrite. Turn it on when the
leak matters more than the log's readability.

### In the context

A value in a context is attached once, usually far from the log call that exposes it:

```go
ctx = context.WithValue(ctx, userKey, user)   // middleware, no logging in sight
slog.InfoContext(ctx, "checkout started")     // somewhere else, entirely
```

`WithContextAttrs` registers functions that pull values out, so no call site can leak one
by forgetting a field:

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
cloak.New(next, cloak.WithCompositeScan(), cloak.WithContextAttrs(auth.LogAttrs))
```

**Why a function and not a key.** The idiomatic context key is an unexported type, so
naming it from the package that configures logging does not compile — and exporting it
just to configure a logger gives up the collision safety that makes the private type worth
having. The closure lives where the key is reachable, so the key never leaves its package.

Whatever a pull returns goes through the same masking as an attribute you logged
yourself. Return `nil` for anything absent, so a missing value is skipped rather than
logged as null.

## Presets

```go
cloak.NewDefaultPII(next)   // the built-in key list plus the detectors
cloak.NewPCI(next)          // cardholder data, per PCI DSS
cloak.NewGDPR(next)         // personal data, per GDPR
cloak.NewLGPD(next)         // the same, under its Brazilian name
```

Each constructor is its option and nothing else, so a caller option still wins on any key
the preset also names:

```go
// the preset would redact card_number; this keeps the last four digits
cloak.NewPCI(next, cloak.WithKeys(cloak.KeepLast(4), "card_number"))
```

`WithDefaultPII` turns on 102 keys and 9 detectors, covering credentials, identity
documents, contact details, addresses, birth dates, payment cards and bank identifiers.
Generic keys like `id`, `name` and `user` are deliberately excluded — they carry more
signal than personal data, and masking them would make the logs useless.

`WithPCI` covers what PCI DSS forbids in logs — PAN and its aliases, CVV, expiry,
cardholder name, track data, PIN — and keeps amounts, currencies and merchant names, which
are not cardholder data and are most of what makes a transaction log worth reading.

`WithGDPR` covers the personal-data categories including article 9: health, biometric,
political, religious, sexual orientation and union membership. It leaves `name` alone on
purpose.

All of them are starting points, not compliance claims. The regulation names categories;
only your schema says which attribute holds each one.

## The redaction message

What a full redaction is replaced with belongs to the handler, not to any rule:

```go
cloak.NewPCI(next, cloak.WithRedactedValue("***"))
// pan=***, cvv=***
```

Whatever asks for the redaction gets that string: a key rule, a tag, a type, a pattern,
`WithContain`, or a preset. Partial maskers keep their own output, since `KeepLast` and
friends state exactly what they produce. Order does not matter, so the message may be set
before or after the rules that use it.

## Composing options

`Options` follows the shape `encoding/json/v2` uses: opaque, and one value carries either
a single option or a set of them.

```go
// one option
opt := cloak.WithDefaultPII()

// a set, which can be named, stored and passed around
var MinhaPolitica = cloak.JoinOptions(opt, cloak.WithMessageScan(), cloak.WithStructScan())

cloak.New(next, MinhaPolitica)
```

That is what a slice of options cannot do: a policy you want to name is a value, not a
function that returns one. Later options override earlier ones, as everywhere else here.

## Reference

| Option | Effect |
| --- | --- |
| `WithRedactedValue(msg)` | What a full redaction is replaced with |
| `WithKeys(mask, keys...)` | Mask whole-key matches |
| `WithKeysContaining(mask, keys...)` | Mask substring matches |
| `WithKeyRegex(mask, pattern)` | Mask keys matching a pattern |
| `WithKeyRegexp(mask, re)` | Same, for a pattern you compiled |
| `WithType[T](maskers...)` | Mask values of Go type `T` |
| `WithTag(mask, key, value)` | Mask struct fields carrying a tag |
| `WithContain(secrets...)` | Mask any value containing a known secret |
| `WithValueFunc(fn)` | Add a value detector |
| `WithValueRule(fn)` | Add a value rule over any kind |
| `WithValuePredicate(mask, pred)` | Mask a value of any kind when pred accepts |
| `WithDefaultPII()` | Preset: keys plus detectors |
| `WithDefaultPIIKeys()` | Preset: keys only |
| `WithDefaultPIIValues()` | Preset: detectors only |
| `WithPCI()` / `WithGDPR()` / `WithLGPD()` | Compliance presets |
| `WithSkipValueScan(keys...)` | Never scan these keys' values |
| `WithMessageScan()` | Also scan the log message |
| `WithStructScan()` | Walk `slog.Any` structs |
| `WithMapScan()` | Walk `slog.Any` maps |
| `WithSliceScan()` | Walk `slog.Any` slices |
| `WithCompositeScan()` | All three composite options |
| `WithContextAttrs(pulls...)` | Copy masked context values onto every record |
| `JoinOptions(opts...)` | Combine options into one value |
| `New(next, opts...)` | Wrap a handler |
| `New(nil, ...)` | Discard everything; useful in tests |

The maskers decide what a matched rule produces:

| Masker | `4111111111111111` |
| --- | --- |
| `Redact` | `[REDACTED]`, or `WithRedactedValue` |
| `Fixed("***")` | `***` |
| `KeepLast(4)` | `************1111` |
| `KeepFirst(4)` | `4111************` |
| `KeepEnds(4, 4)` | `4111********1111` |
| `MaskMiddle(4, 4)` | alias of `KeepEnds` |

Maskers operate on the string form of the value and are rune-aware, so multibyte text is
not cut mid-character.

## Performance

Full numbers by scenario in [bench/](bench/README.md).

The short version, each record measured against itself logged straight to `slog`:

| | bare slog | with cloak | delta |
| --- | --- | --- | --- |
| 4 attributes, nothing to mask | 527 ns, 0 allocs | 622 ns, 0 allocs | **+95 ns** |
| key lookup in isolation | — | 11 ns, 0 allocs | — |
| 9 detectors over clean sentences | — | 180 ns, 0 allocs | — |
| `slog.Any` with a struct | 785 ns, 1 alloc | 1549 ns, 6 allocs | +764 ns |

Three things to take from it:

- **The quiet path is cheap and allocation-free.** Under 100 ns over bare for a record
  where nothing matched. Key lookup is a single map hit, and a lookup that misses
  never materializes the folded key, so even `snake_case` names cost nothing. A walked
  struct or slice where nothing matched costs nothing either, at any width: the copy and
  the fallback are built only once something changes.
- **A rule that fires is not the expensive part.** Finding the value was. What a match
  costs is the replacement itself — a new string is two allocations, which is the
  floor, and the detector rows sit exactly on it.
- **Reflection costs an order of magnitude more** and is opt-in for that reason. The
  0.8–1.4 µs of the walk rows is the price of rebuilding the container: boxing each
  element out of reflection, the copy, and the masked strings.

## Gotchas

Things that are true and easy to trip over.

**A key rule masks the value stored under a matching map key**, the same as it does for a
struct field. Masking the key instead would protect nothing — `map[[REDACTED]:hunter2]` is
the same leak wearing a hat. The key name survives, because it is the field name and not
the secret.

**Unexported fields and fields tagged `slog:"-"` are dropped from a walked struct.**
`encoding/json` ignores an unexported field, but `TextHandler` renders a struct with
`%+v` and prints them, so copying one through would hand it to the sink:

```go
type acct struct {
    ID       int
    password string
}
slog.Info("m", "a", acct{ID: 7, password: "hunter2"})
// TextHandler: a="{ID:7 password:}"
```

A struct carrying one of these fields always rebuilds, even when no rule matched, because
dropping the field is itself the change. A struct with only exported fields passes
through untouched.

**A struct with a changed pointer field widens to a group on `TextHandler`.** Cloak
follows the pointer and rewrites the value behind it, but `fmt` renders a nested
pointer as an address, so keeping the struct would reach the sink as `0xc000...` with
nothing showing a rule fired. Widening shows the pointed-to value instead:

```go
slog.Info("m", "user", User{ID: 7, ShipTo: &Address{CEP: "01310-100"}})
// TextHandler: user.ID=7 user.ShipTo="&{Street:Rua X CEP:[REDACTED]}"
// JSONHandler: "user":{"ID":7,"ShipTo":{"CEP":"[REDACTED]"}}   <- unchanged
```

The masking is correct either way; only the text rendering changes, and JSON is
untouched. What still shows an address is a pointer nothing matched: rebuilding for
readability alone would break the passthrough the quiet path promises, and `fmt`
behaves the same with no cloak involved. Maps and slices holding pointers have the
same residual.

**Masking a map key can merge two entries.** If two distinct keys mask to the same text
they become one entry. Nothing leaks, but an entry can be lost.

**A struct map key works on `TextHandler` but not `JSONHandler`.** `slog`'s JSON handler
rejects it outright — a Go limitation, present with or without cloak.

**A masked value that cannot be represented in its original type widens the container.**
A `[]LogValuer`, or a map keyed by a struct whose `LogValue()` returns something else,
becomes `[]any` or `map[string]any` rather than keeping the unmasked original.

**`MaskPhone` is a heuristic** and will mask any run of 7–15 digits, including IDs and
timestamps. If that is a problem, use `WithDefaultPIIKeys()`, which masks by key only.

**Composite walking needs its own option.** A struct in a context or in a group is
reached only with `WithStructScan` or `WithCompositeScan`; cloak does not turn reflection
on implicitly.

## Examples

Runnable programs in [examples/](examples/):

| Directory | Shows |
| --- | --- |
| `basic` | The smallest useful setup |
| `keys` | Key, pattern and type rules, and how they interact |
| `containers` | Structs, maps, slices and groups |
| `pci` | A compliance preset with an override |
| `context` | Pulling masked values out of a context with a private key |

```
go run ./examples/basic
```

## Testing

```
go test ./...
go test -bench . -benchmem ./...
```

## License

MIT
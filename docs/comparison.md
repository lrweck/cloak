# Competitive comparison

Notes gathered while filling gaps in cloak. Not user-facing documentation — a working
reference for deciding what to build next. Sources are the projects' own READMEs and
pkg.go.dev, retrieved 2026-10-01.

## The libraries

- **[masq](https://github.com/m-mizutani/masq)** — v0.2.3, Go 1.24, Apache-2.0, 143 stars.
  Hooks `slog.HandlerOptions.ReplaceAttr`. Closest in spirit.
- **[go-slog-redact](https://github.com/philiprehberger/go-slog-redact)** — v0.4.0, Go 1.22,
  MIT. Handler wrapper, closest in shape.
- **[redactlog](https://pkg.go.dev/github.com/JAS0N-SMITH/redactlog)** — `slog.Handler`
  plus HTTP middleware. Compliance framing, Pino-style path DSL.
- **[loglayer redact plugin](https://go.loglayer.dev/plugins/redact.html)** — plugin for
  the LogLayer framework, not stdlib slog.
- **[alesr/redact](https://github.com/alesr/redact)** — pipeline of redaction stages.
- **[sudoki2015/sensitive](https://pkg.go.dev/github.com/sudoki2015/sensitive)** — masking
  for logs, API responses and config dumps, not slog-specific. Has presets and hashing.

## Capability matrix

Verified against source where the README was ambiguous, 2026-10-01. `—` means the
library has no equivalent; a note means it can be done, but not first-class.

| Capability | masq | slog-redact | redactlog | loglayer | sensitive | **cloak** |
| --- | --- | --- | --- | --- | --- | --- |
| Mask by Go type (`WithType[T]`) | ✅ | — | — | — | — | ✅ |
| Mask by struct tag | ✅ | — | — | — | — | ✅ |
| Mask value containing a known secret | ✅ | — | — | — | — | ✅ |
| Compliance presets (PCI/GDPR) | — | — | ✅ PCI | — | ✅ 3 presets | ✅ PCI, GDPR, LGPD |
| Hash for correlation, not exposure | — | — | — | — | ✅ | ❌ |
| Redaction counters / stats | — | ✅ atomic | — | — | — | ❌ |
| Regex over values | ✅ | — | ✅ | ✅ | — | via `WithValueFunc` |
| **Regex over keys** | — | ✅ | — | — | — | ❌ substring only |
| Path DSL with wildcards (`cards[*].pan`) | — | — | ✅ | — | — | ❌ normalized keys |
| Predicate on the raw `slog.Value`, any kind | ✅ | ✅ | — | — | — | strings only |
| Length-preserving / partial masks | ✅ `MaskWithSymbol` | ✅ `PartialMask` | ✅ | — | ✅ | ✅ `KeepFirst`/`KeepLast`/`KeepEnds` |
| HTTP middleware / body capture | — | — | ✅ | — | — | ❌ out of scope |
| Query-string redaction | — | — | ✅ | — | ✅ | ❌ |
| JSON / config-dump masking | — | — | — | — | ✅ | ❌ out of scope |
| **Content detectors with real validation** | ❌ | ❌ | Luhn + BIN | ❌ | ❌ | ✅ Luhn, CPF/CNPJ check digits, MOD-97, SSN ranges |
| Unexported fields never passed through | ✅ unsafe overwrite | ❌ | ❌ | ⚠️ skipped | ❌ | ✅ zeroed |
| Scan the log message | ⚠️ see below | ⚠️ see below | ❌ | ❌ | ❌ | ✅ `WithMessageScan` |
| Composite walk | ✅ implicit | ❌ | ❌ | ✅ | ✅ | ✅ opt-in per shape |
| Context values | ❌ | ❌ | ✅ | ❌ | ❌ | ✅ with private keys |
| `LogValuer` precedence | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |

### Two cells worth being precise about

**"Scan the log message" is not a clean win.** Because `ReplaceAttr` is handed the
built-in attributes, masq and go-slog-redact *can* reach the message — `slog` calls it
with `String("msg", msg)`, so `WithFieldName("msg")` or a key regex works. What neither
offers is a rule that knows the message is free text rather than a field, and cloak
still has to be told with `WithMessageScan()`. The advantage is real but narrower than
the matrix first claimed: three first-class rules versus two accidental one-liners.

**Unexported fields: three different behaviours.** masq overwrites them with the
redact string, using `unsafe` to reach fields reflect would refuse
(`unsafeCopyValue` in masq.go). loglayer skips them, on the grounds that they are
unreachable through structured output — which is true for JSON and false for
`TextHandler`, which prints them via `%+v`. cloak zeroes them, which is what
`encoding/json` would have produced and cannot be printed. go-slog-redact passes them
through.

## Where cloak is genuinely ahead

1. **Validation, not pattern matching.** Every other library reaches for a regex.
   Cloak checks Luhn, CPF and CNPJ check digits, IBAN MOD-97 and the SSN range
   allocation, so a 14-digit timestamp or an order number does not get masked. The
   expensive check sits behind a cheap structural gate, measured at 1.9–28 ns.
2. **The log message, as a rule rather than a key name.** Both `ReplaceAttr` libraries
   can mask it by naming `msg`, which is undocumented behaviour of the handler. Cloak
   has to be told, but so do they. Narrower than I first claimed, and worth keeping in
   mind rather than quoting as a clean win.
3. **Private context keys.** The idiomatic key is an unexported type; `WithContextAttrs`
   takes a pull function so the key never leaves its package. The alternative is
   exporting the key just to configure logging.
4. **`LogValuer` precedence.** A value that knows how to log itself is resolved first,
   then what it emitted is masked. Logging its raw struct instead misses the string the
   author meant to write.
5. **Opt-in reflection.** Nothing touches `reflect` unless a composite option is on,
   asserted by a test that counts walk entries.
6. **`ReplaceAttr` compatibility is deliberately absent.** Nearly every peer integrates
   as `HandlerOptions.ReplaceAttr`. Cloak is a handler wrapper instead, because
   `ReplaceAttr` cannot scan the message or pull values from the context. Offering both
   would mean supporting the weaker half.

## Gaps still open, in the order I would take them

0. **Regex over keys.** Found while verifying this matrix: `go-slog-redact` has
   `WithPatterns("_key$", "^x-.*-token$")` and cloak only has `WithKeyContains`, a
   substring match. That covers `x_api_key` but not `stripe_key$` or `^x-.*-token$`.
   Cloak already imports `regexp` nowhere on the hot path, so this is a config-time
   addition plus one map lookup. Cheap and clearly correct — arguably it should have
   been in the first batch.
1. **`KeepHash()` — a stable pseudonym.** Masking destroys correlation: you cannot tell
   whether two log lines refer to the same account. A truncated hash keeps that without
   exposing anything. `sensitive` offers hashing; nobody else does. Small: one masker.
2. **Redaction counters (`Stats()`).** `go-slog-redact` exposes `RedactedCount`,
   accumulated atomically and shared across `WithGroup`/`WithAttrs` children. The value
   is operational: an alert on zero redactions catches a rule that stopped matching
   after a refactor. Needs the atomic-counter placement decided.
3. **Error text.** `slog.Any("err", err)` is one opaque value, and `err.Error()` is where
   request bodies and tokens land. `loglayer` catches this with a hook that re-walks
   assembled data. Worth a decision on the API rather than a guess.
4. **Predicate over any `slog.Value` kind.** Cloak's `ValueFunc` sees strings only, so a
   rule that should inspect an int, a duration or a struct has nowhere to go. Both
   `ReplaceAttr` libraries can do it. Small once the plumbing exists.
5. **Path DSL.** `payment.cards[*].pan` is more precise than a normalized-key match.
   `redactlog` compiles its paths once. Real value, meaningful complexity — defer until
   someone asks.
6. **Query-string and header helpers.** `?api_key=…` in a logged URL. Narrow, and the
   `WithContain` rule already covers it when the secret is known.

## What I looked at and decided against

- **`MaskWithSymbol` / length-preserving masks.** Covered by `KeepEnds`.
- **`WithAllowedType`** (masq) — an escape hatch for types that must never be
  redacted. Cloak has the opposite default already: unexported and `slog:"-"` fields
  are dropped rather than passed through, so the escape hatch is not needed for safety.
- **A `Censor` interface** (masq). `Masker` plus `ValueFunc` already covers the
  decision; a third shape would be a third thing to learn.
- **`ReplaceAttr` constructor.** See above.
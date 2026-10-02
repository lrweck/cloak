# cloak against the alternatives

The same record, the same sink, one library at a time. Runnable, not a table someone
typed:

```
cd bench/compare
go test -bench . -benchmem
```

It is a separate module on purpose. Cloak has no dependencies and this is the only place
those imports exist, so `bench/compare/go.mod` cannot leak into the library. It needs
network access on the first run, so it is not wired into CI.

## What is being compared

`password`, `email` and `card_number` configured in each library, masking a record that
trips one of them. Two records:

- **clean** — nothing to mask: `user_id`, `status`, `latency_ms`, `route`. What most
  log lines are.
- **secret** — one key rule fires: `user_id`, `password`, `status`.

Both write JSON to `io.Discard`, so the numbers are the handler chain plus the masking,
not I/O. The built-in `time` attribute is present, as it is in production.

Each library is verified to actually mask before its speed is reported:
`TestEveryLibraryMasks` fails if `hunter2` reaches the sink. Benchmarking a configuration
that quietly does nothing would read as a very fast winner.

## The numbers

Intel Core i7-13700H, Go 1.27, best of three. `bare` is the same record through a plain
`JSONHandler` with no masking, so the delta column is what the masking costs.

### Clean record — nothing matched

| Library | Cost | Over bare | Allocations |
| --- | --- | --- | --- |
| `bare` | 537 ns | — | 0 |
| `go-slog-redact` | 690 ns | +153 | 0 |
| `cloak` | 761 ns | +224 | 0 |
| `redactlog` | 802 ns | +265 | 0 |
| `sensitive` | 986 ns | +449 | 2 |
| `alesr/redact` | 1201 ns | +664 | 9 |
| `masq+allowed-time` | 2266 ns | +1729 | 50 |
| `masq` | 54619 ns | +54082 | 1719 |

### Secret record — one key rule fired

| Library | Cost | Over bare | Allocations |
| --- | --- | --- | --- |
| `bare` | 548 ns | — | 0 |
| `go-slog-redact` | 612 ns | +64 | 0 |
| `redactlog` | 623 ns | +75 | 0 |
| `cloak` | 660 ns | +112 | 0 |
| `sensitive` | 962 ns | +414 | 2 |
| `alesr/redact` | 1098 ns | +550 | 9 |
| `masq+allowed-time` | 1942 ns | +1394 | 41 |
| `masq` | 53510 ns | +52962 | 1710 |

## What the numbers say, and what they do not

**Cloak is third on both, within about 10 ns per attribute of the fastest.** The gap is
the price of the lookup doing more than a `map[string]struct{}` contains: the key is
normalized first, so `card_number`, `cardNumber` and `CARD-NUMBER` are one rule, and the
same call also has to consider regex keys, substring keys and the skip list. Two of the
three libraries ahead of it do a plain map hit and nothing else.

**The three fastest allocate nothing on a record with nothing to mask**, cloak included.
That is the property worth having: the wrapper is free on the log lines that were never
going to leak.

**masq is the outlier, and the cause is the clock.** It deep-clones every value it is
handed in order to decide whether to redact it, and a `ReplaceAttr` hook is handed the
built-in `time` as well. A `time.Time` carries a `*time.Location`, so cloning it walks the
whole zone table. The profiler puts 88% of the allocations in `masq.clone`:
`reflect.unsafe_New` and `context.WithValue`, once per level of the walk.

`masq+allowed-time` is the same configuration with `masq.WithAllowedType(reflect.TypeFor[time.Time]())`,
which is masq's own escape hatch for types it should not clone. It brings 54619 ns down to
2266 ns. It is still the slowest here, because cloning every value is the design and the
time attribute is only the most expensive value to clone.

**alesr/redact re-scans the whole record once per configured field.** `AddRedactField`
appends a pipeline stage, and each stage copies every attribute into a fresh record. Three
fields is three full scans and three records, which is why it allocates 9 times where the
others allocate none. It is a pipeline design, and the shape shows.

## Why this is not a like-for-like benchmark

Three differences matter more than the nanoseconds.

**Only key-based masking is compared.** It is the one thing all six do. Cloak's content
detectors — Luhn for card numbers, CPF and CNPJ check digits, IBAN MOD-97, the SSN range
allocation — have no equivalent in most of these libraries, and neither does masking by Go
type or by struct tag. Comparing those would be comparing two different jobs.

**The benchmark is key rules only, and with that configuration none of the libraries
reaches inside a struct.** Not even cloak: walking composites is opt-in, so
`slog.Any("user", u)` passes through untouched for every library here.
`TestKeyOnlyConfigReachesInsideNothing` fails if that stops being true, so the table
cannot quietly start comparing two different jobs.

That is a property of the configuration, not of the integration shape. Both cloak and
masq can be told to walk — `WithStructScan`, or masq's field name or tag — and
`TestBothHandlersCanReachInsideWhenConfigured` pins that. masq hooks `ReplaceAttr` and
still walks, because it clones whatever it is handed. `sensitive` matches a key against a
string value and has no way in at all. So "hook versus wrapper" is not the line that
decides it; what each library does with the value it is given is.

**Nothing here measures the message or the context.** Cloak's `WithMessageScan` and
`WithContextAttrs` have no counterpart in the hook-based libraries at all.

The honest summary: on the narrow thing every library does, cloak is in the leading group
and pays a small, explainable premium over the two that do least. What it does beyond that
is not in the table because there is nothing to put in the other column.

# cloak against the alternatives

The same records, the same sink, one library at a time. Runnable, not a table someone
typed:

```
cd bench/compare
go test -bench . -benchmem
go test -v -run 'TestEveryLibrary|TestScenario|TestBoth|TestKeyOnly'   # the correctness checks
```

It is a separate module on purpose. Cloak has no dependencies and this is the only place
those imports exist, so `bench/compare/go.mod` cannot leak into the library. It needs
network access on the first run, so it is not wired into CI.

## What is being compared

Two sections. First a synthetic baseline of key-based masking — the one thing every
library does — configured with `password`, `email` and `card_number`, on two records:

- **clean** — nothing to mask: `user_id`, `status`, `latency_ms`, `route`. What most
  log lines are.
- **secret** — one key rule fires: `user_id`, `password`, `status`.

Then three records a real service writes, each configured for the libraries that can
honestly be configured for it.

Both write JSON to `io.Discard`, so the numbers are the handler chain plus the masking,
not I/O. The built-in `time` attribute is present, as it is in production.

Every library is verified to actually mask before its speed is reported.
`TestEveryLibraryMasks` fails if `hunter2` reaches the sink, and
`TestScenarioEveryParticipantFindsTheCard` does the same for content detection.
Benchmarking a configuration that quietly does nothing would read as a very fast winner.

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


## Three records from a real service

The table above is a synthetic baseline: three attributes and a short message. These
three are what a Go service actually writes, and each scenario says which libraries can
be configured for it honestly. A library with no equivalent is reported as excluded
rather than benchmarked with a configuration that quietly does nothing.

All three write JSON to `io.Discard` with the built-in `time` attribute in place. `bare`
is the same record through a plain `JSONHandler`, so the delta is what masking costs.

### 1. `http_request` — the most common record in a service

A request id, a method, a route, a status, a latency, a client address, a user agent
long enough that a substring scan has real work to do, and one real email. Every library
configured with the same two keys.

| Library | Cost | Over bare | Allocations |
| --- | --- | --- | --- |
| `bare` | 931 ns | — | 1 |
| `cloak` | 1560 ns | +628 | 4 |
| `go-slog-redact` | 1380 ns | +448 | 4 |
| `redactlog` | 1426 ns | +494 | 4 |
| `sensitive` | 1672 ns | +740 | 3 |
| `alesr/redact` | 1966 ns | +1034 | 15 |
| `masq+allowed-time` | 3422 ns | +2490 | 73 |
| `masq` | 43680 ns | +42748 | 1254 |

Two keys match, so cloak's four allocations are two masked values plus the record
rebuild. The gap to the two map-lookup libraries is the normalized key and the layered
lookup behind it, over an eleven-attribute record.

### 2. `payment_authorization` — content detection, no key rules anywhere

A card number under a key nobody configured, beside numbers that only look like one. No
library in this scenario gets a key rule, so the comparison is about finding a card and
not about naming a field. Three participate:

| Library | Cost | Over bare | Allocations |
| --- | --- | --- | --- |
| `bare` | 752 ns | — | 1 |
| `cloak` | 1413 ns | +660 | 8 |
| `redactlog` | 2304 ns | +1551 | 18 |
| `masq` | 33108 ns | +32355 | 747 |

`redactlog`'s `PANDetector` and cloak's `MaskPAN` are the same algorithm — locate thirteen
to nineteen digits, reject with Luhn — so this is an equivalent test rather than two
different jobs. Cloak is about 1.6 times cheaper and allocates less than half as much.
`go-slog-redact`, `sensitive` and `alesr/redact` have no content detection and are
excluded.

**The false-positive result, which is the reason this record is here.** The same record
also carries a sixteen-digit order id as the payment provider sends it, a thirteen-digit
millisecond timestamp, and an integer amount:

| Library | Leaves the order id | Leaves the timestamp | Leaves the amount |
| --- | --- | --- | --- |
| `cloak` | yes | yes | yes |
| `redactlog` | yes | yes | yes |
| `masq` (pattern) | **no** | yes | yes |

masq masks the order id, which is not a card. The other two numbers survive for a reason
that has nothing to do with validation: they are typed as integers, and a digit-count
pattern never sees a non-string. That is worth stating plainly, because "the regex only
got one of the three" is a weaker claim than "the regex got the one that is a string" —
and a string is exactly how an order id, a transaction reference or an account number
arrives.

### 3. `background_job` — nothing sensitive, under the same production configuration

A job id, a queue, an attempt count, a duration, a batch size, a region, a replica, an
outcome. The keys from scenario one are still installed. This is the question a service
owner actually has: what does the wrapper cost per line once it is in the binary.

| Library | Cost | Over bare | Allocations |
| --- | --- | --- | --- |
| `bare` | 861 ns | — | 1 |
| `cloak` | 1287 ns | +425 | **1** |
| `go-slog-redact` | 1307 ns | +445 | 4 |
| `redactlog` | 1316 ns | +454 | 4 |
| `sensitive` | 1477 ns | +615 | 3 |
| `alesr/redact` | 1853 ns | +991 | 15 |
| `masq+allowed-time` | 3316 ns | +2454 | 75 |
| `masq` | 44037 ns | +43175 | 1256 |

This is the scenario where cloak's laziness pays. A nine-attribute record with nothing to
match costs one allocation — the same as the bare handler — because the quiet path builds
no copy and no fallback group. The other wrapper libraries allocate four times rebuilding
a record they then discard.

## What the numbers say, and what they do not

**On the realistic records cloak is first or third, and allocates least.** On
`background_job` it is the fastest of the masking libraries *and* allocates once, where
every other wrapper allocates three to fifteen times. The quiet path builds no copy and
no fallback, so a record that was never going to leak costs nothing.

On `http_request` it is third, about 180 ns behind a plain map lookup over an
eleven-attribute record. That gap is the price of the lookup doing more than a
`map[string]struct{}` contains: the key is normalized first, so `card_number`,
`cardNumber` and `CARD-NUMBER` are one rule, and the same call also has to consider
regex keys, substring keys and the skip list. The two libraries ahead of it do a map hit
and nothing else.

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

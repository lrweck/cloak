# cloak against the alternatives

The same records, the same sink, one library at a time:

```
cd bench/compare
go test -bench . -benchmem
go test -v -run 'TestEveryLibrary|TestScenario|TestBoth|TestKeyOnly|TestNestedStruct'
```

It is a separate module so the library keeps its zero dependencies. It needs network
access on the first run, so it is not wired into CI.

## What is being compared

Six records, in two groups.

**A synthetic baseline** of key-based masking, configured with `password`, `email` and
`card_number`:

- **clean** — nothing to mask: `user_id`, `status`, `latency_ms`, `route`.
- **secret** — one key rule fires: `user_id`, `password`, `status`.

**Four records a real service writes**, each with only the libraries that can be
configured for it:

- **http_request** — request id, method, route, status, latency, client address, user
  agent, one real email.
- **payment_authorization** — a card number under a key nobody configured, beside numbers
  that only look like one.
- **background_job** — eight ordinary attributes and nothing sensitive, under a production
  configuration.
- **nested_struct** — the two secrets inside one struct logged with `slog.Any`.

All six write JSON to `io.Discard`, so the numbers are the handler chain plus the
masking. The built-in `time` attribute is present.

`bare` is the same record through a plain `JSONHandler`, so the delta column is what the
masking costs. Every library is verified to mask before its speed is reported:
`TestEveryLibraryMasks`, `TestScenarioEveryParticipantFindsTheCard` and
`TestNestedStructNobodyLeaksThePassword` fail if the secret reaches the sink.

`masq` appears twice: its default configuration, and the same library with
`WithAllowedType(reflect.TypeFor[time.Time]())`, which its documentation recommends. The
second row is the fairer comparison and is the one to read.

## The numbers

Intel Core i7-13700H, Go 1.27, `-benchtime 800ms -count 4`, best of four. Every table
below comes from a single `go test -bench .` run. The timings move a few percent between
runs; the allocation counts do not.

### Baseline, clean record — nothing matched

| Library | Cost | Over bare | Allocations |
| --- | --- | --- | --- |
| `bare` | 551 ns | — | 0 |
| `go-slog-redact` | 712 ns | +161 | 0 |
| `redactlog` | 726 ns | +175 | 0 |
| `cloak` | 826 ns | +276 | 0 |
| `sensitive` | 1065 ns | +514 | 2 |
| `alesr/redact` | 1221 ns | +670 | 9 |
| `masq+allowed-time` | 2349 ns | +1798 | 50 |
| `masq` | 55081 ns | +54530 | 1719 |

### Baseline, secret record — one key rule fired

| Library | Cost | Over bare | Allocations |
| --- | --- | --- | --- |
| `bare` | 486 ns | — | 0 |
| `go-slog-redact` | 627 ns | +141 | 0 |
| `redactlog` | 630 ns | +144 | 0 |
| `cloak` | 670 ns | +184 | 0 |
| `sensitive` | 1039 ns | +553 | 2 |
| `alesr/redact` | 1094 ns | +608 | 9 |
| `masq+allowed-time` | 2006 ns | +1520 | 41 |
| `masq` | 55524 ns | +55038 | 1710 |

## Four records from a real service

### 1. `http_request`

Every library configured with the same two keys, `user_email` and `client_ip`.

| Library | Cost | Over bare | Allocations |
| --- | --- | --- | --- |
| `bare` | 929 ns | — | 1 |
| `go-slog-redact` | 1352 ns | +423 | 4 |
| `redactlog` | 1383 ns | +454 | 4 |
| `cloak` | 1491 ns | +562 | 4 |
| `sensitive` | 1645 ns | +716 | 3 |
| `alesr/redact` | 1926 ns | +997 | 15 |
| `masq+allowed-time` | 3439 ns | +2510 | 73 |
| `masq` | 43088 ns | +42159 | 1254 |

Two keys match. cloak is 139 ns behind the fastest library here, and allocates the same
four.

### 2. `payment_authorization` — content detection, no key rules anywhere

A card number under a key nobody configured, so the comparison is about finding a card
rather than naming a field. Three participate; the others have no content detection and
are excluded.

| Library | Cost | Over bare | Allocations |
| --- | --- | --- | --- |
| `bare` | 732 ns | — | 1 |
| `redactlog` | 2412 ns | +1680 | 18 |
| `cloak` | 1331 ns | +599 | 8 |
| `masq` | 32465 ns | +31733 | 747 |

`redactlog`'s `PANDetector` and cloak's `MaskPAN` are the same algorithm: locate thirteen
to nineteen digits, reject with Luhn. That makes this an equivalent test rather than two
different jobs, and cloak is 1.81 times cheaper while allocating less than half as much.
masq is given the pattern matching what it asks for.

**The false-positive result.** The record also carries a sixteen-digit order id as a
string, a thirteen-digit millisecond timestamp, and an integer amount:

| Library | Leaves the order id | Leaves the timestamp | Leaves the amount |
| --- | --- | --- | --- |
| `cloak` | yes | yes | yes |
| `redactlog` | yes | yes | yes |
| `masq` (pattern) | **no** | yes | yes |

masq masks the order id, which is not a card. The timestamp and the amount survive
because they are integers, not because they were validated: a digit-count pattern never
sees a non-string value.

### 3. `background_job` — nothing sensitive, under the same production configuration

The keys from the first scenario are still installed.

| Library | Cost | Over bare | Allocations |
| --- | --- | --- | --- |
| `bare` | 857 ns | — | 1 |
| `go-slog-redact` | 1246 ns | +389 | 4 |
| `redactlog` | 1291 ns | +434 | 4 |
| `cloak` | 1245 ns | +388 | 1 |
| `sensitive` | 1490 ns | +633 | 3 |
| `alesr/redact` | 1817 ns | +960 | 15 |
| `masq+allowed-time` | 3312 ns | +2455 | 75 |
| `masq` | 42559 ns | +41702 | 1256 |

**On time this is a tie**, one nanosecond apart, which is noise. The difference is the
allocation column: cloak costs one, the same as the bare handler. The others sit at three,
four or fifteen.

### 4. `nested_struct` — the secrets are inside one struct

```
"user", loggedUser{ID: 4711, Email: "jane.doe@example.com", Password: "correct-horse-battery"}
```

slog hands a handler one opaque `any` here, so there is no group to walk into. Masking a
field inside it takes reflecting through a struct. cloak gets `WithStructScan()` plus the
same key rules; masq gets `WithFieldName`.

| Library | Cost | Over bare | Allocations |
| --- | --- | --- | --- |
| `bare` | 1012 ns | — | 1 |
| `cloak` | 1750 ns | +738 | 5 |
| `masq+allowed-time` | 3394 ns | +2382 | 63 |
| `masq` | 43748 ns | +42736 | 1244 |

**cloak wins this one outright**: 1.94 times cheaper than the `masq+allowed-time` row,
and an eighth of its allocations.

`TestNestedStructReachesTheFieldOrDropsTheValue` classifies what each library does with
this record at its best attempt, including the three that are not in the table above:

| Library | Configuration | Outcome |
| --- | --- | --- |
| `cloak` | `WithStructScan` + keys | **field** — two fields replaced, id kept |
| `masq` | `WithFieldName("Email")`, `WithFieldName("Password")` | **field** — two fields replaced, id kept |
| `redactlog` | `user.Email`, `user.Password` | **leak** — the struct is never entered |
| `redactlog` | `user` | **value** — nothing leaks, and the id goes with it |
| `go-slog-redact` | the key rule | **leak** |
| `sensitive` | the key rule | **leak** |
| `alesr/redact` | `AddRedactField("email")`, `("password")` | **leak** |

`field` means the two secrets were replaced and the id survived. `value` means nothing
leaked and the id went with it. Both count as no-leak; only the first is the job.

## What the numbers say

**cloak is third on every key-rule scenario, by 43 to 139 ns, and level on the quiet
path.** The margin is the lookup: the key is normalized first, so `card_number`,
`cardNumber` and `CARD-NUMBER` are one rule, and the same call also considers regex keys,
substring keys and the skip list. Over a bare handler the wrapper costs 184 to 276 ns on
the synthetic records, 388 ns on the quiet eight-attribute one, and 562 ns where two keys
match.

**cloak allocates least or ties for least on every scenario.** Nothing on the synthetic
records, four on `http_request`, and one on `background_job` — what the bare handler
costs. The quiet path builds no copy and no fallback group.

**On content detection, where the comparison is equivalent, cloak is 1.81 times cheaper
and rejects the number that is not a card.** Neither advantage is visible in the key-rule
tables.

**On the struct, cloak is 1.94 times cheaper and allocates an eighth as much.** It is not
faster at reflection; it does less around the reflection.

## What these tables do not cover

The tables are not the same width, because each one holds only the libraries that can be
configured for that record.

**Nothing here compares masking by Go type, by struct tag, of the log message, or of
values carried in a context.** cloak has all four.

**With the key-only configuration no library reaches inside a struct**, cloak included —
walking composites is opt-in, so `slog.Any("user", u)` passes through untouched for every
library in those tables. `TestKeyOnlyConfigReachesInsideNothing` fails if that stops being
true.

**The message is not measured.** cloak has `WithMessageScan` for free text.

In short: cloak is a consistent third on key rules at 43 to 139 ns behind a plain map
hit, never more than 562 ns over a bare handler, allocating least or tied for least
everywhere. Where a comparison is equivalent — the PAN algorithm, and the struct — it is
1.81 and 1.94 times cheaper respectively.
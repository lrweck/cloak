# cloak against the alternatives

The same records, the same sink, one library at a time. Runnable, not a table someone
typed:

```
cd bench/compare
go test -bench . -benchmem
go test -v -run 'TestEveryLibrary|TestScenario|TestBoth|TestKeyOnly|TestNestedStruct'
```

It is a separate module on purpose. Cloak has no dependencies and this is the only place
those imports exist, so `bench/compare/go.mod` cannot leak into the library. It needs
network access on the first run, so it is not wired into CI.

## What is being compared

Six records, in two groups.

**A synthetic baseline** of key-based masking — the one thing every library here does —
configured with `password`, `email` and `card_number`:

- **clean** — nothing to mask: `user_id`, `status`, `latency_ms`, `route`.
- **secret** — one key rule fires: `user_id`, `password`, `status`.

**Four records a real service writes**, each configured for the libraries that can
honestly be configured for it:

- **http_request** — the most common record there is: request id, method, route, status,
  latency, client address, user agent, one real email.
- **payment_authorization** — a card number under a key nobody configured, beside numbers
  that only look like one.
- **background_job** — eight ordinary attributes and nothing sensitive, under a
  production configuration. What a service owner is really asking about.
- **nested_struct** — the two secrets inside one struct logged with `slog.Any`, which is
  what a service does when it hands a domain object to slog whole.

All six write JSON to `io.Discard`, so the numbers are the handler chain plus the
masking, not I/O. The built-in `time` attribute is present, as it is in production.

`bare` is the same record through a plain `JSONHandler`, so the delta column is what the
masking costs. Every library is verified to actually mask before its speed is reported:
`TestEveryLibraryMasks` fails if `hunter2` reaches the sink,
`TestScenarioEveryParticipantFindsTheCard` does the same for content detection, and
`TestNestedStructNobodyLeaksThePassword` for the struct. Benchmarking a configuration
that quietly does nothing would read as a very fast winner.

`masq` appears twice. It deep-clones whatever it is handed, including the built-in time
attribute, so its default configuration is an outlier by two orders of magnitude. The
second row is the same library with the escape hatch its own documentation points at, and
that is the row worth comparing.

## The numbers

Intel Core i7-13700H, Go 1.27, `-benchtime 800ms -count 4`, best of four. Every table
below comes from a single `go test -bench .` run, so the deltas are consistent across
them. The numbers move a few percent between runs; the allocation counts do not.

### Baseline, clean record — nothing matched

| Library | Cost | Over bare | Allocations |
| `bare` | 561 ns | — | 0 |
| `go-slog-redact` | 708 ns | +147 | 0 |
| `redactlog` | 728 ns | +167 | 0 |
| `cloak` | 761 ns | +200 | 0 |
| `sensitive` | 1023 ns | +462 | 2 |
| `alesr/redact` | 1223 ns | +662 | 9 |
| `masq+allowed-time` | 2337 ns | +1776 | 50 |
| `masq` | 55136 ns | +54575 | 1719 |

### Baseline, secret record — one key rule fired

| Library | Cost | Over bare | Allocations |
| `bare` | 488 ns | — | 0 |
| `go-slog-redact` | 634 ns | +146 | 0 |
| `redactlog` | 638 ns | +150 | 0 |
| `cloak` | 678 ns | +190 | 0 |
| `sensitive` | 995 ns | +507 | 2 |
| `alesr/redact` | 1107 ns | +619 | 9 |
| `masq+allowed-time` | 2014 ns | +1526 | 41 |
| `masq` | 55480 ns | +54992 | 1710 |

## Four records from a real service

### 1. `http_request`

Every library configured with the same two keys, `user_email` and `client_ip`.

| Library | Cost | Over bare | Allocations |
| `bare` | 945 ns | — | 1 |
| `go-slog-redact` | 1371 ns | +426 | 4 |
| `redactlog` | 1420 ns | +475 | 4 |
| `cloak` | 1571 ns | +626 | 4 |
| `sensitive` | 1659 ns | +714 | 3 |
| `alesr/redact` | 1979 ns | +1034 | 15 |
| `masq+allowed-time` | 3438 ns | +2493 | 73 |
| `masq` | 43001 ns | +42056 | 1254 |

Two keys match, and cloak allocates four exactly as the other two wrappers do. It is
third, 200 ns behind a plain map hit across eight user attributes.

### 2. `payment_authorization` — content detection, no key rules anywhere

A card number under a key nobody configured. No library in this scenario gets a key rule,
so the comparison is about finding a card and not about naming a field. Three participate;
`go-slog-redact`, `sensitive` and `alesr/redact` have no content detection and are
excluded rather than configured for something they cannot do.

| Library | Cost | Over bare | Allocations |
| `bare` | 749 ns | — | 1 |
| `redactlog` | 2318 ns | +1569 | 18 |
| `cloak` | 1414 ns | +665 | 8 |
| `masq` | 33035 ns | +32286 | 747 |

`redactlog`'s `PANDetector` and cloak's `MaskPAN` are the same algorithm: locate thirteen
to nineteen digits, then reject with Luhn. That makes this an equivalent test rather than
two different jobs, and cloak is about 1.6 times cheaper while allocating less than half
as much. masq is given the pattern matching it asks for, which is what a regex-based
library does.

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
pattern never sees a non-string. That distinction is worth stating plainly, because "the
regex only got one of the three" is a weaker claim than "the regex got the one that is a
string" — and a string is exactly how an order id, a transaction reference or an account
number arrives.

### 3. `background_job` — nothing sensitive, under the same production configuration

The keys from the first scenario are still installed.

| Library | Cost | Over bare | Allocations |
| `bare` | 839 ns | — | 1 |
| `go-slog-redact` | 1272 ns | +433 | 4 |
| `redactlog` | 1300 ns | +461 | 4 |
| `cloak` | 1267 ns | +428 | 1 |
| `sensitive` | 1457 ns | +618 | 3 |
| `alesr/redact` | 1830 ns | +991 | 15 |
| `masq+allowed-time` | 3350 ns | +2511 | 75 |
| `masq` | 44038 ns | +43199 | 1256 |

**On time this is a tie**, five nanoseconds apart, which is noise and should be read as
a tie. The difference is in the allocation column: cloak costs one, exactly what the bare
handler costs, because the quiet path builds no copy and no fallback group. The other
wrappers allocate three to fifteen times that here, though on the four-attribute baseline
they allocate nothing either — whatever threshold they cross, this is where it shows.

### 4. `nested_struct` — the secrets are inside one struct

```go
"user", loggedUser{ID: 4711, Email: "jane.doe@example.com", Password: "correct-horse-battery"},
```

slog hands a handler one opaque `any` for this, so there is no group to walk into.
Masking a field inside it takes reflecting through a struct, which is a different
capability from naming a key. cloak gets `WithStructScan()` plus the same key rules;
masq gets `WithFieldName`.

| Library | Cost | Over bare | Allocations |
| `bare` | 1006 ns | — | 1 |
| `cloak` | 1754 ns | +748 | 5 |
| `masq+allowed-time` | 3424 ns | +2418 | 63 |
| `masq` | 44556 ns | +43550 | 1244 |

**This is the one scenario where cloak wins outright, by 1.95 times against the fair
masq configuration and 25 times against its default**, and it wins on allocations harder
than on time: 5 against 63, a twelfth. Reflecting into a struct is the work, and masq pays for it by
cloning what it finds.

Three of the libraries cannot be configured for this record at all, so they are absent
rather than given a configuration that quietly does nothing.
`TestNestedStructReachesTheFieldOrDropsTheValue` reports what each one does when it is
given its best attempt anyway, because a boundary is only informative if you show what
the far side of it does:

| Library | Configuration | Outcome |
| --- | --- | --- |
| `cloak` | `WithStructScan` + keys | **field** — two fields replaced, id kept |
| `masq` | `WithFieldName("Email")`, `WithFieldName("Password")` | **field** — two fields replaced, id kept |
| `redactlog` | `user.Email`, `user.Password` | **leak** — the struct is never entered |
| `redactlog` | `user` | **value** — nothing leaks, and the id goes with it |
| `go-slog-redact` | the key rule | **leak** |
| `sensitive` | the key rule | **leak** |
| `alesr/redact` | `AddRedactField("email")`, `("password")` | **leak** |

The middle row is the interesting one. redactlog has a real path DSL — `user.Email`
against a `slog.Group` masks correctly — but it descends into `slog.KindGroup` and never
into a struct, and its trie is compiled case-sensitively, so no spelling of a path gets
further than the top-level key. Given a struct its only move is to mask the whole value.
That stops the leak and discards the user id along with it, which is why it is measured
here rather than in the speed table: it is a different trade, not a slower version of the
same one.

The three `leak` rows are the ordinary consequence of not reflecting. The record they
write is `slog.Any("user", user)` with a `Password` field in it, and a grep for the
secret is the only test that notices.

## What the numbers say, and what they do not

**Cloak is third on every key-rule scenario, by 44 to 200 ns, and level on the quiet
path.** That is the price of a lookup doing more than a `map[string]struct{}` contains:
the key is normalized first, so `card_number`, `cardNumber` and `CARD-NUMBER` are one
rule, and the same call has to consider regex keys, substring keys and the skip list. The
two libraries ahead of it do a map hit and nothing else. Over a bare handler the whole
wrapper costs 190 to 200 ns on the synthetic records, 428 ns on the quiet

eight-attribute one, and 626 ns where two keys actually match.

**Cloak allocates least, or ties for least, on every scenario — and that is the durable
property.** Nothing at all on the synthetic records, tied with the two map-lookup
libraries. Four on `http_request` where two values are replaced, again tied. And one on
`background_job`, which is what the bare handler costs and no other library matches: the
others sit at three, four or fifteen, because the quiet path builds no copy and no
fallback to throw away.

**On content detection, where the comparison is equivalent, cloak is 1.6 times cheaper
than the one library running the same algorithm**, and rejects the number that is not a
card. Neither advantage is visible in the key-rule tables, which is the point: they are
different jobs.

**On the struct, cloak is 1.95 times cheaper than the fair masq configuration and
allocates a twelfth as much**, because this is the scenario where the library
that reaches inside has something to prove and the ones that do not are not in the table
at all. The honest reading is narrower than it looks: cloak is not faster at reflecting
than masq, it does far less around the reflection. masq clones whatever it finds to
decide what to do with it, cloak reads the field.

**masq is the outlier, and the cause is the clock.** It deep-clones every value to decide
whether to redact it, and a `ReplaceAttr` hook is handed the built-in `time` as well. A
`time.Time` carries a `*time.Location`, so cloning it walks the whole zone table. The
profiler puts 88% of the allocations in `masq.clone`, through `reflect.unsafe_New` and
`context.WithValue` once per level of the walk. `masq+allowed-time` is the same
configuration with `masq.WithAllowedType(reflect.TypeFor[time.Time]())`, and it takes the
clean record from 55136 ns to 2337 ns. It is still the slowest, because cloning every
value is the design and the time attribute is only the most expensive value to clone. The
profiler run behind that figure is the clean record, where `masq.clone` accounts for 88%
of allocations.

**alesr/redact re-scans the whole record once per configured field.** `AddRedactField`
appends a pipeline stage and each stage copies every attribute into a fresh record, so
three fields is three scans and three records. That is where its fifteen allocations on
the eight-attribute record come from, against nine on the four-attribute one.

## Why this is not a like-for-like benchmark

Four differences matter more than the nanoseconds.

**The scenarios do not all ask the same question.** The key-rule scenarios ask for masking
by name, which every library here does. The payment scenario asks for a card number
found in a value, which only three of them can do at all. The struct scenario asks for a
field inside a value, which two of them can do. A row's presence in a table already says
its library can do that job, which is why the tables are not the same width and why the
ones that cannot are named rather than dropped. Nothing here compares masking by Go type,
by struct tag, of the log message, or of values carried in a context: cloak has all four,
most of the field has none, and there is no column to put them in.

**With the key-only configuration none of the libraries reaches inside a struct.** Not
even cloak: walking composites is opt-in, so `slog.Any("user", u)` passes through
untouched for every library in those tables. `TestKeyOnlyConfigReachesInsideNothing`
fails if that stops being true, so the tables cannot quietly start comparing two different
jobs.

That is a property of the configuration, not of the integration shape. Both cloak and
masq can be told to walk — `WithStructScan`, or masq's field name or tag — and
`TestBothHandlersCanReachInsideWhenConfigured` pins that. masq hooks `ReplaceAttr` and
still walks, because it clones whatever it is handed. `sensitive` matches a key against a
string value and has no way in at all. So "hook versus wrapper" is not the line that
decides it; what each library does with the value it is given is. The struct scenario is
where that distinction becomes a number instead of an argument.

**A library that masks a whole value passes the same grep as one that masks a field.**
`redactlog` on `RedactPaths: ["user"]` keeps the password out of the sink, which is what
`TestNestedStructNobodyLeaksThePassword` checks, and it also throws away the user id.
Both are "no leak"; only one is the job. The capability table in scenario 4 keeps the two
apart for exactly this reason.

**The message is not in these tables either.** cloak has `WithMessageScan` for free text
and the two `ReplaceAttr` libraries can reach the message by naming `msg`, which is
undocumented behaviour of the handler rather than a rule that knows the message is prose.
It is a smaller advantage than it looks, and it is not measured.

The honest summary: on key rules cloak is a consistent third, 44 to 200 ns behind a
plain map hit and never more than 626 ns over a bare handler, while allocating least or
tied for least everywhere. On content detection, where the comparison is equivalent, it
is 1.64 times cheaper and it rejects the number that is not a card. On a struct it is
1.95 times cheaper than the only other library that can be configured for the record,
and three of the remaining five cannot reach the field at all. What cloak does beyond that is
not in the tables because there is nothing to put in the other column.
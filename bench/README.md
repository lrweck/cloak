# Benchmarks

How cloak compares with the other libraries that mask PII in Go logs, on the same record
through the same sink: [compare/](compare/README.md).

```
cd bench/compare && go test -bench . -benchmem     # needs network on first run
```

The numbers below are cloak's own, by scenario.

```
go test -bench Scenario -benchmem
go test -bench Scenario -benchmem -benchtime 2s   # steadier numbers
```

## How to read these

A single number for "what cloak costs" is meaningless: the work depends on whether a
rule fired, how wide the record is, and whether reflection is on. So each record is
logged twice with the identical record — once straight to `slog`, once through cloak —
and the interesting number is the difference between the pair.

Two things the pairing keeps honest. The sink's own cost depends on the shape:
marshaling a map allocates inside `encoding/json` whether cloak is in the path or not,
and a bare handler logging a different record would attribute that cost to the masking.
And the quiet path — a record where nothing matches — is the case worth optimizing,
because most records in a real log are quiet.

The sink is `io.Discard` behind a `JSONHandler`, so what is measured is cloak plus the
handler chain, not the cost of formatting or of writing bytes.

## Scenarios

Intel Core i7-13700H, Go 1.27, `linux/amd64`, `-benchtime 1s -count 6`, best of six. One
`go test -bench .` run produced every row here and every row in the root README, so the
two files cannot disagree. The delta is the masking; run-to-run it varies by tens of
nanoseconds.

| Scenario | bare slog | with cloak | delta | what it exercises |
| --- | --- | --- | --- | --- |
| `no_pii_text` | 448 ns, 0 allocs | 569 ns, 0 allocs | **+121 ns** | no PII in the text |
| `key_only_no_detectors` | 458 ns, 0 allocs | 588 ns, 0 allocs | **+130 ns** | 102 key rules, no format scan |
| `key_rule_fires` | 382 ns, 0 allocs | 455 ns, 0 allocs | **+73 ns** | one key rule redacting |
| `detector_fires` | 390 ns, 0 allocs | 792 ns, 2 allocs | +402 ns | the email detector matching |
| `preset_mixed_record` | 612 ns, 0 allocs | 897 ns, 0 allocs | +285 ns | keys and detectors together |
| `preset_wide_record` | 1484 ns, 1 allocs | 2693 ns, 2 allocs | +1209 ns | 20 attributes, mostly unmatched |
| `groups_nested` | 576 ns, 0 allocs | 1086 ns, 4 allocs | +510 ns | two nested groups |
| `struct_walk` | 729 ns, 1 allocs | 1465 ns, 6 allocs | +736 ns | `slog.Any` with a struct |
| `map_walk` | 1291 ns, 10 allocs | 2489 ns, 23 allocs | +1198 ns | `slog.Any` with a map |
| `slice_walk` | 660 ns, 1 allocs | 2010 ns, 17 allocs | +1350 ns | `slog.Any` with a slice |
| `message_scan` | 415 ns, 0 allocs | 884 ns, 2 allocs | +470 ns | an email inside the message |
| `context_attrs` | 386 ns, 0 allocs | 1654 ns, 8 allocs | +1268 ns | a masked pull on every record |

### What the numbers say

**The quiet path is cheap and allocation-free.** A record with nothing to mask costs
under 100 ns over a bare `slog` handler and allocates nothing. Most of the delta is
`normalizeKey` and the map lookup that follows it — and since the lookup that misses
never materializes the folded form, even `snake_case` keys cost no allocation.

**A composite where nothing matches is free too.** Walking a struct used to box every
field into a group it then discarded, plus a folded key and a rebuild copy: a per-field
toll that showed up at 8–9 allocations for a four-field struct. The copy and the group
are now built only once something changes or the shape breaks, and a struct whose fields
are all exported costs nothing over the bare handler at any width.
`TestPassthroughStructCostDoesNotGrowWithWidth` pins that by comparing a 2-field struct
against a 20-field one, so the check is about the slope rather than a fixed number that
would drift with the sink.

**Key lookup alone is 11 ns.** `BenchmarkKeyLookup` measures the lookup in isolation:
one map hit, no allocation.

**A rule that fires costs about the same as one that does not.** `key_rule_fires` is
only 140 ns over bare. Masking a string is not the expensive part; finding the value
was. What a match does cost is the replacement itself: a new string is two allocations
(the bytes and the boxing), which is the floor — `detector_fires` and `message_scan`
both sit exactly on it at 2 allocs.

**The detectors are gated twice.** Each one runs a structural pre-filter first and only
pays for its exact validation when the shape is plausible:

| Detector | Typical text that does not match |
| --- | --- |
| `MaskUUID` | 11 ns |
| `MaskEmail` | 29 ns |
| `MaskIPv4` | 28 ns |
| `MaskCPF` | 105 ns |
| `MaskCNPJ` | 93 ns |
| `MaskSSN` | 95 ns |
| `MaskPAN` | 106 ns |
| `MaskIBAN` | 170 ns |
| `MaskPhone` | 155 ns |

Nine detectors over six sentences that hold none of them costs about 180 ns, and
`BenchmarkDetectorsComposed` shows that running them twice is no slower than once —
the pre-filter is what makes the composition affordable.

**Reflection is opt-in and clearly marked.** `WithStructScan`, `WithMapScan` and
`WithSliceScan` cost 0.8–1.4 µs over bare, an order of magnitude above the key path.
The price is the copy: boxing each element out of reflection, the rebuilt container,
and the masked strings themselves. Without one of them, `reflect` is never called on
the logging path at all (`TestReadmeCompositeOptionsAreOptIn` and `walkCalls` pin
that). Note the bare column for `map_walk`: 10 of the 27 allocations belong to the
JSON sink marshaling the map, not to the masking.

**A slice where nothing matched is free too.** The rebuilt slice and the widened
fallback are both built on demand, and a plain string element is masked straight from
reflection instead of being boxed into an any only to be read back out. A twenty-element
slice of unmatched strings costs nothing over the bare handler.

**Maps still rebuild eagerly.** `walkMap` cannot defer its copy the way the struct and
the slice do: map entries are unordered, so a copy taken at the first change cannot tell
which entries the loop has already rewritten, and re-inserting an original key next to
its masked twin leaks rather than duplicates. The string-keyed fallback cannot be
rebuilt from the result either, since a converted non-string key renders differently.
Reverting the attempt failed `TestMapWithStructKey`. What maps do get is `MapRange` in
place of `Seq2`: the range-over-func iterator allocates twice per entry on top of the
two boxes `Interface` needs, which took a two-entry passthrough from 12 allocations to
8.

## Scaling with record width

Key rules only, no detectors, no reflection. The delta is the wrapper's own cost per
attribute.

| Attributes | bare slog | key rules | delta | per attribute |
| --- | --- | --- | --- | --- |
| 1 | 446 ns | 545 ns | +99 ns | 99 ns |
| 5 | 607 ns | 887 ns | +280 ns | 56 ns |
| 10 | 968 ns | 1474 ns | +506 ns | 51 ns |
| 20 | 1520 ns | 2765 ns | +1245 ns | 62 ns |
| 50 | 3398 ns | 6770 ns | +3372 ns | 67 ns |

The cost is linear in the number of attributes at about 50–70 ns each, with zero
allocations up to ten attributes. There is no cliff: records wider than the 16-slot
stack buffer fall back to `append` and allocate, which is slower but not different in
kind, and `TestHandleWideRecordKeepsEveryAttribute` covers it.

## Reproducing

Numbers come from this machine and will differ on yours. What should reproduce is the
*shape*: the quiet path near the bare handler with zero allocations, a matched string
at exactly two, reflection an order of magnitude above the key path, and no allocation
when nothing matched.
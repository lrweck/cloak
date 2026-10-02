# Benchmarks

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

Intel Core i7-13700H, Go 1.27, `linux/amd64`. Each row is the same record through a
bare handler and through cloak; the delta is the masking.

| Scenario | bare slog | with cloak | delta | what it exercises |
| --- | --- | --- | --- | --- |
| `no_pii_text` | 472 ns, 0 allocs | 599 ns, 0 allocs | **+127 ns** | nothing matched |
| `key_only_no_detectors` | 458 ns, 0 allocs | 675 ns, 0 allocs | +217 ns | 102 key rules, no format scan |
| `key_rule_fires` | 402 ns, 0 allocs | 542 ns, 0 allocs | +140 ns | one key rule redacting |
| `detector_fires` | 461 ns, 0 allocs | 844 ns, 2 allocs | +383 ns | the email detector matching |
| `preset_mixed_record` | 630 ns, 0 allocs | 914 ns, 0 allocs | +284 ns | keys and detectors together |
| `preset_wide_record` | 1534 ns, 1 alloc | 2866 ns, 2 allocs | +1332 ns | 20 attributes, mostly unmatched |
| `groups_nested` | 704 ns, 0 allocs | 1323 ns, 4 allocs | +619 ns | two nested groups |
| `struct_walk` | 751 ns, 1 alloc | 1857 ns, 14 allocs | +1106 ns | `slog.Any` with a struct |
| `map_walk` | 1289 ns, 10 allocs | 3040 ns, 28 allocs | +1751 ns | `slog.Any` with a map |
| `slice_walk` | 696 ns, 1 alloc | 2209 ns, 19 allocs | +1513 ns | `slog.Any` with a slice |
| `message_scan` | 477 ns, 0 allocs | 896 ns, 2 allocs | +419 ns | an email inside the message |
| `context_attrs` | 395 ns, 0 allocs | 2081 ns, 17 allocs | +1686 ns | a masked pull on every record |

### What the numbers say

**The quiet path is cheap and allocation-free.** A record with nothing to mask costs
about 130 ns over a bare `slog` handler and allocates nothing. Most of the delta is
`normalizeKey` and the map lookup that follows it — and since the lookup that misses
never materializes the folded form, even `snake_case` keys cost no allocation.

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
`WithSliceScan` cost 1.1–1.8 µs over bare, an order of magnitude above the key path.
The price is the copy: boxing each element out of reflection, the rebuilt container,
and the masked strings themselves. Without one of them, `reflect` is never called on
the logging path at all (`TestReadmeCompositeOptionsAreOptIn` and `walkCalls` pin
that). Note the bare column for `map_walk`: 10 of the 28 allocations belong to the
JSON sink marshaling the map, not to the masking.

## Scaling with record width

Key rules only, no detectors, no reflection. The delta is the wrapper's own cost per
attribute.

| Attributes | bare slog | key rules | delta | per attribute |
| --- | --- | --- | --- | --- |
| 1 | 438 ns | 526 ns | +88 ns | 88 ns |
| 5 | 697 ns | 1009 ns | +312 ns | 62 ns |
| 10 | 951 ns | 1462 ns | +511 ns | 51 ns |
| 20 | 1504 ns | 2897 ns | +1393 ns | 70 ns |
| 50 | 3394 ns | 6810 ns | +3416 ns | 68 ns |

The cost is linear in the number of attributes at about 50–70 ns each, with zero
allocations up to ten attributes. There is no cliff: records wider than the 16-slot
stack buffer fall back to `append` and allocate, which is slower but not different in
kind, and `TestHandleWideRecordKeepsEveryAttribute` covers it.

## Reproducing

Numbers come from this machine and will differ on yours. What should reproduce is the
*shape*: the quiet path near the bare handler with zero allocations, a matched string
at exactly two, reflection an order of magnitude above the key path, and no allocation
when nothing matched.
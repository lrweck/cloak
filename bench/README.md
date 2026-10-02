# Benchmarks

```
go test -bench Scenario -benchmem
go test -bench Scenario -benchmem -benchtime 2s   # steadier numbers
```

## How to read these

A single number for "what cloak costs" is meaningless: the work depends on whether a
rule fired, how wide the record is, and whether reflection is on. So each record is
logged twice — once straight to `slog`, once through cloak — and the interesting number
is the difference between the pair.

The sink is `io.Discard` behind a `JSONHandler`, so what is measured is cloak plus the
handler chain, not the cost of formatting or of writing bytes.

## Scenarios

Intel Core i7-13700H, Go 1.27, `linux/amd64`.

| Scenario | cloak | bare slog | delta | allocs | what it exercises |
| --- | --- | --- | --- | --- | --- |
| `no_pii_text` | 661 ns | 530 ns | **+131 ns** | 1 | nothing matched |
| `key_only_no_detectors` | 637 ns | 530 ns | +107 ns | 1 | 102 key rules, no format scan |
| `key_rule_fires` | 541 ns | — | — | 0 | one key rule redacting |
| `detector_fires` | 911 ns | — | — | 3 | the email detector matching |
| `preset_mixed_record` | 935 ns | — | — | 1 | keys and detectors together |
| `preset_wide_record` | 3132 ns | — | — | 22 | 20 attributes, mostly unmatched |
| `groups_nested` | 1121 ns | — | — | 4 | two nested groups |
| `struct_walk` | 1804 ns | — | — | 17 | `slog.Any` with a struct |
| `map_walk` | 2892 ns | — | — | 28 | `slog.Any` with a map |
| `slice_walk` | 2129 ns | — | — | 22 | `slog.Any` with a slice |
| `message_scan` | 952 ns | — | — | 2 | an email inside the message |
| `context_attrs` | 2266 ns | — | — | 21 | a masked pull on every record |

### What the numbers say

**The quiet path is cheap.** A record with nothing to mask costs about 130 ns and one
allocation over a bare `slog` handler — roughly 30 ns per attribute. Most of the cost
is `normalizeKey` and the map lookup that follows it.

**Key lookup alone is 7.5 ns.** `BenchmarkKeyLookup` in `cloak_bench_test.go` measures
the lookup in isolation: one map hit, no allocation.

**A rule that fires costs about the same as one that does not.** `key_rule_fires` is
faster than `no_pii_text` because the record has one attribute instead of four. Masking
a string is not the expensive part; finding the string was.

**The detectors are gated twice.** Each one runs a structural pre-filter first and only
pays for its exact validation when the shape is plausible:

| Detector | Typical text that does not match |
| --- | --- |
| `MaskUUID` | 11 ns |
| `MaskEmail` | 28 ns |
| `MaskIPv4` | 29 ns |
| `MaskCPF` | 97 ns |
| `MaskCNPJ` | 106 ns |
| `MaskSSN` | 107 ns |
| `MaskPAN` | 107 ns |
| `MaskIBAN` | 172 ns |
| `MaskPhone` | 158 ns |

Nine detectors over a sentence that holds none of them costs about 210 ns, and
`BenchmarkDetectorsComposed` shows that running them twice is no slower than once —
the pre-filter is what makes the composition affordable.

**Reflection is opt-in and clearly marked.** `WithStructScan`, `WithMapScan` and
`WithSliceScan` cost 1.8–2.9 µs, an order of magnitude above the key path. Without one
of them, `reflect` is never called on the logging path at all
(`TestReadmeCompositeOptionsAreOptIn` and `walkCalls` pin that).

## Scaling with record width

Key rules only, no detectors, no reflection. The delta is the wrapper's own cost per
attribute.

| Attributes | bare slog | key rules | delta | per attribute |
| --- | --- | --- | --- | --- |
| 1 | 395 ns | 509 ns | +114 ns | 114 ns |
| 5 | 642 ns | 1036 ns | +394 ns | 79 ns |
| 10 | 971 ns | 1712 ns | +741 ns | 74 ns |
| 20 | 1529 ns | 3132 ns | +1603 ns | 80 ns |
| 50 | 3435 ns | 7271 ns | +3836 ns | 77 ns |

The cost is linear in the number of attributes and settles at about 80 ns each. There
is no cliff: records wider than the 16-slot stack buffer fall back to `append` and
allocate, which is slower but not different in kind, and `TestHandleWideRecordKeepsEveryAttribute`
covers it.

## Reproducing

Numbers come from this machine and will differ on yours. What should reproduce is the
*shape*: the quiet path near the bare handler, reflection an order of magnitude above
the key path, and no allocation when nothing matched.
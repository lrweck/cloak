# cloak

PII redaction and masking for Go's `log/slog`.

## Features

- `slog.Handler` wrapper with recursive group handling.
- Explicit key masking with `WithKey`.
- Value detectors with a **fast pre-filter → exact validation → masking** pipeline.
- Built-in detectors for PAN/Luhn, CPF, CNPJ, SSN, IBAN, email, IPv4, UUID and phone.
- Generic maskers: `Redact`, `Fixed`, `KeepLast`, `KeepFirst`, `KeepEnds`.
- `WithDefaultPII()` preset for common PII/sensitive attributes and values.
- Attribute keys are normalized for case-insensitive O(1) lookup; ASCII `_`, `-`, spaces and tabs are ignored.
- `LogValuer` values are resolved once before inspection.

## Example

```go
package main

import (
    "log/slog"
    "os"

    "github.com/lrweck/cloak"
)

func main() {
    logger := slog.New(cloak.New(
        slog.NewJSONHandler(os.Stdout, nil),
        cloak.WithDefaultPII(),
        cloak.WithKey(cloak.KeepLast(4), "card_number"),
    ))

    logger.Info("payment", "email", "john@example.com", "card_number", "4111111111111111")
}
```

When a field's semantic meaning is known, prefer `WithKey`; value scanning is opt-in because heuristic detectors such as phone numbers can have false positives.

## Built-in value detectors

- `MaskPAN`: 13–19 digits with Luhn validation.
- `MaskCPF`: Brazilian CPF with both check digits.
- `MaskCNPJ`: Brazilian CNPJ with both check digits.
- `MaskSSN`: US SSN structural/range validation.
- `MaskIBAN`: IBAN MOD-97 validation.
- `MaskEmail`: conventional email syntax.
- `MaskIPv4`: syntactic IPv4 validation.
- `MaskUUID`: canonical UUID validation.
- `MaskPhone`: heuristic 7–15 digit phone detection.

Each detector performs a cheap structural check before its expensive/exact validation.

## Default PII keys

The preset covers common aliases for credentials/authentication, identity documents, email/phone, addresses, birth dates, payment cards, bank accounts and routing identifiers. Examples include `password`, `passwd`, `pwd`, `apiKey`, `accessToken`, `refreshToken`, `authorization`, `cpf`, `cnpj`, `taxId`, `passportNumber`, `socialSecurityNumber`, `emailAddress`, `phoneNumber`, `creditCardNumber`, `cardNumber`, `cvv`, `iban`, `accountNumber`, etc.

Generic keys such as `id` and `name` are intentionally excluded.

## License

MIT

// Command pci shows a compliance preset, and the one thing worth doing with it:
// overriding a rule when your schema disagrees with the default.
//
//	go run ./examples/pci
package main

import (
	"log/slog"
	"os"

	"github.com/lrweck/cloak"
)

func main() {
	// Cardholder data goes, everything that makes a transaction log worth reading
	// stays: amounts, currencies, merchant names, latency.
	logger := slog.New(cloak.NewPCI(
		slog.NewJSONHandler(os.Stdout, nil),
		// The redaction message is the handler's, whatever asked for the redaction.
		cloak.WithRedactedValue("***"),
		// A caller option still wins on any key the preset also names. Keeping the
		// last four digits is usually what you want for a PAN: enough to correlate,
		// not enough to charge with.
		cloak.WithKey(cloak.KeepLast(4), "card_number"),
		// One preset per handler, so the rules do not accumulate across loggers.
		cloak.WithMessageScan(),
	))

	logger.Info("charge",
		"card_number", "4111111111111111",
		"cvv", "123",
		"cardholdername", "Jane Doe",
		"amount", 1299,
		"currency", "BRL",
		"merchant", "Livraria X",
		"latency_ms", 143,
		// The preset matches names, not concepts. "cardholder" is not a name PCI DSS
		// uses, so it passes through untouched. Only your schema says which attribute
		// holds cardholder data, which is why a preset is a starting point.
		"cardholder", "Jane Doe",
	)

	// Presets are starting points, not compliance claims. GDPR and LGPD cover the
	// personal-data categories, including the sensitive ones in article 9.
	lgpd := slog.New(cloak.NewLGPD(slog.NewTextHandler(os.Stdout, nil)))
	lgpd.Info("record",
		"health", "HIV-positive",
		"biometric", "face-template-9f2",
		"country", "Brazil",
	)
}

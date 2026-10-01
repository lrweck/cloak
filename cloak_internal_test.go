package cloak

import "testing"

// newConfigForBench builds a config the way New does, for benchmarks.
func newConfigForBench() *config {
	return &config{keys: make(map[string]Masker), skip: make(map[string]struct{})}
}

// normalizeForTest mirrors normalizeKey for the exported preset lists.
func normalizeForTest(s string) string { return normalizeKey(s) }

// Every key must survive normalization uniquely, or a list is hiding a typo.
func TestPresetKeysAreDistinct(t *testing.T) {
	for name, keys := range map[string][]string{
		"PCI": PCIKeys, "GDPR": GDPRKeys, "LGPD": LGPDKeys, "default": DefaultPIIKeys,
	} {
		seen := map[string]string{}
		for _, k := range keys {
			n := normalizeKey(k)
			if prev, dup := seen[n]; dup {
				t.Errorf("%s: %q and %q both normalize to %q", name, prev, k, n)
			}
			seen[n] = k
		}
		if len(keys) == 0 {
			t.Errorf("%s: empty key list", name)
		}
	}
}

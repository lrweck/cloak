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

// countDetectors reports how many value rules the options install, built-ins and user
// detectors alike.
func countDetectors(opts ...Option) int {
	c := &config{keys: make(map[string]Masker), skip: make(map[string]struct{})}
	for _, o := range opts {
		o(c)
	}
	return len(c.values)
}

// Composing presets must not scan twice. WithDefaultPII already installs the
// detectors, so adding WithDefaultPIIValues alongside it is the likely mistake.
func TestComposedPresetsInstallEachDetectorOnce(t *testing.T) {
	cases := []struct {
		name string
		opts []Option
		want int // zero means the whole set
	}{
		{"preset twice", []Option{WithDefaultPII(), WithDefaultPII()}, 0},
		{"preset plus values", []Option{WithDefaultPII(), WithDefaultPIIValues()}, 0},
		{"values twice", []Option{WithDefaultPIIValues(), WithDefaultPIIValues()}, 0},
		{"pci plus preset", []Option{WithPCI(), WithDefaultPII()}, 0},
		{"gdpr plus preset", []Option{WithGDPR(), WithDefaultPII()}, 0},
		{"lgpd plus gdpr", []Option{WithLGPD(), WithGDPR()}, 5},
		{"all three presets", []Option{WithPCI(), WithGDPR(), WithDefaultPII()}, 0},
		{"built-in offered by name first", []Option{
			WithValueFunc(MaskPAN), WithDefaultPIIValues(),
		}, 0},
		{"built-in offered by name last", []Option{
			WithDefaultPIIValues(), WithValueFunc(MaskPAN),
		}, 0},
		{"pci alone", []Option{WithPCI()}, 1},
		{"gdpr alone", []Option{WithGDPR()}, 5},
	}
	full := len(DefaultPIIValueFuncs())
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			want := tc.want
			if want == 0 {
				want = full
			}
			if got := countDetectors(tc.opts...); got != want {
				t.Fatalf("installed %d detectors, want %d", got, want)
			}
		})
	}
}

// A user detector is never deduplicated, because two closures from one literal share a
// code pointer while capturing different values. Treating them as equal would drop a
// rule silently.
func TestUserDetectorsAreNeverDeduplicated(t *testing.T) {
	cases := []struct {
		name string
		opts []Option
		want int
	}{
		{
			"two closures from one literal",
			[]Option{
				WithValueFunc(func(string) (string, bool) { return "", true }),
				WithValueFunc(func(string) (string, bool) { return "", true }),
			},
			2,
		},
		{
			"two distinct named functions",
			[]Option{
				WithValueFunc(MaskEmail),
				WithValueFunc(MaskIPv4),
			},
			2,
		},
		{
			"maskers keepLast with different arities",
			[]Option{
				WithKey(KeepLast(4), "a"),
				WithKey(KeepLast(9), "b"),
			},
			0, // maskers are not detectors
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := countDetectors(tc.opts...); got != tc.want {
				t.Fatalf("installed %d detectors, want %d", got, tc.want)
			}
		})
	}
}

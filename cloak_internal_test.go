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
func countDetectors(opts ...Options) int {
	c := &config{keys: make(map[string]Masker), skip: make(map[string]struct{})}
	for _, o := range opts {
		o.apply(c)
	}
	return len(c.values)
}

// Composing presets must not scan twice. WithDefaultPII already installs the
// detectors, so adding WithDefaultPIIValues alongside it is the likely mistake.
func TestComposedPresetsInstallEachDetectorOnce(t *testing.T) {
	cases := []struct {
		name string
		opts []Options
		want int // zero means the whole set
	}{
		{"preset twice", []Options{WithDefaultPII(), WithDefaultPII()}, 0},
		{"preset plus values", []Options{WithDefaultPII(), WithDefaultPIIValues()}, 0},
		{"values twice", []Options{WithDefaultPIIValues(), WithDefaultPIIValues()}, 0},
		{"pci plus preset", []Options{WithPCI(), WithDefaultPII()}, 0},
		{"gdpr plus preset", []Options{WithGDPR(), WithDefaultPII()}, 0},
		{"lgpd plus gdpr", []Options{WithLGPD(), WithGDPR()}, 5},
		{"all three presets", []Options{WithPCI(), WithGDPR(), WithDefaultPII()}, 0},
		{"built-in offered by name first", []Options{
			WithValueFunc(MaskPAN), WithDefaultPIIValues(),
		}, 0},
		{"built-in offered by name last", []Options{
			WithDefaultPIIValues(), WithValueFunc(MaskPAN),
		}, 0},
		{"pci alone", []Options{WithPCI()}, 1},
		{"gdpr alone", []Options{WithGDPR()}, 5},
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
		opts []Options
		want int
	}{
		{
			"two closures from one literal",
			[]Options{
				WithValueFunc(func(string) (string, bool) { return "", true }),
				WithValueFunc(func(string) (string, bool) { return "", true }),
			},
			2,
		},
		{
			"two distinct named functions",
			[]Options{
				WithValueFunc(MaskEmail),
				WithValueFunc(MaskIPv4),
			},
			2,
		},
		{
			"maskers keepLast with different arities",
			[]Options{
				WithKeys(KeepLast(4), "a"),
				WithKeys(KeepLast(9), "b"),
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

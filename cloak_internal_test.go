package cloak

// newConfigForBench builds a config the way New does, for benchmarks.
func newConfigForBench() *config {
	return &config{keys: make(map[string]Masker), skip: make(map[string]struct{})}
}

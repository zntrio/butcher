package butcher

// Option is the butcher option setting function signature
type Option func(*Butcher) error

// WithAlgorithm defines the algorithm to use for hashing password
func WithAlgorithm(algo string) Option {
	return func(b *Butcher) error {
		b.algorithm = algo
		return nil
	}
}

// WithSalt defines the salt value for the hashing password
func WithSalt(value []byte) Option {
	return func(b *Butcher) error {
		b.salt = &value
		return nil
	}
}

// WithIterations defines the iteration count to use in password derivation
func WithIterations(value int) Option {
	return func(b *Butcher) error {
		b.iterations = &value
		return nil
	}
}

// WithCPUCost defines the CPU cost in password derivation
func WithCPUCost(value int) Option {
	return func(b *Butcher) error {
		b.cpucost = &value
		return nil
	}
}

// WithMemoryCost defines the memory cost in password derivation
func WithMemoryCost(value int) Option {
	return func(b *Butcher) error {
		b.memcost = &value
		return nil
	}
}

// WithParallelism defines the parallelism value in password derivation
func WithParallelism(value int) Option {
	return func(b *Butcher) error {
		b.parallelism = &value
		return nil
	}
}

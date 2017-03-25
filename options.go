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

// WithNonce defines the nonce factory value for salt generation
func WithNonce(factory func() []byte) Option {
	return func(b *Butcher) error {
		b.nonce = factory
		return nil
	}
}

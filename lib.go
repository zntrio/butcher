package butcher

import (
	"errors"
	"fmt"

	"zenithar.org/go/butcher/hasher"
)

// -----------------------------------------------------------------------------

var (
	// ErrButcherStrategyNotSupported is raised when caller try to invoke not supported algorithm
	ErrButcherStrategyNotSupported = errors.New("butcher: given strategy is not supported")
)

// -----------------------------------------------------------------------------

// Butcher defines the hasher configuration
type Butcher struct {
	algorithm string
	nonce     func() []byte
}

// -----------------------------------------------------------------------------

// New butcher instance is buildded according options
func New(options ...Option) (*Butcher, error) {
	var err error

	// Initialize default butcher
	butcher := Butcher{
		algorithm: hasher.BcryptSha512,
		nonce:     RandomNonce(16),
	}

	// Iterates on given options
	for _, option := range options {
		err = option(&butcher)
		if err != nil {
			break
		}
	}

	// Initialize hash strategy
	if _, ok := hasher.Strategies[butcher.algorithm]; !ok {
		return nil, ErrButcherStrategyNotSupported
	}

	return &butcher, err
}

// -----------------------------------------------------------------------------

// Hash the given password with the hash strategy
func (b *Butcher) Hash(password []byte) (string, error) {
	strategy, ok := hasher.Strategies[b.algorithm]
	if !ok {
		return "", ErrButcherStrategyNotSupported
	}

	hashedPassword, err := strategy(b.nonce()).Hash(password)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%s$%s", b.algorithm, hashedPassword), nil
}

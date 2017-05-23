package butcher

import (
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"go.zenithar.org/butcher/hasher"
)

// -----------------------------------------------------------------------------

const (
	// DefaultAlgorithm defines the default algorithm to use when not specified
	DefaultAlgorithm = hasher.Pbkdf2Blake2b512
)

var (
	// DefaultNonce defines the default nonce generation factory to use when not specified
	DefaultNonce = RandomNonce(64)
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
		algorithm: DefaultAlgorithm,
		nonce:     DefaultNonce,
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

	switch b.algorithm {
	case hasher.Argon2i:
		// Remove '$' prefix of argon2 representation
		return fmt.Sprintf("%s", hashedPassword[1:]), nil
	default:
		return fmt.Sprintf("%s$%s", b.algorithm, hashedPassword), nil
	}
}

// Verify cleartext password with encoded one
func Verify(encoded []byte, password []byte) (bool, error) {
	parts := strings.SplitN(string(encoded), "$", 5)

	// Check supported algorithm
	strategy, ok := hasher.Strategies[parts[0]]
	if !ok {
		return false, ErrButcherStrategyNotSupported
	}

	// Extract salt
	salt, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return false, fmt.Errorf("butcher: error occurs when decoding salt part, %v", err)
	}

	// Hash given password
	hashedPassword, err := strategy(FixedNonce(salt)()).Hash(password)
	if err != nil {
		return false, fmt.Errorf("butcher: unable to hash given password, %v", err)
	}

	// TODO: Move to a specific encoder
	switch parts[0] {
	case hasher.Argon2i:
		// Remove '$' prefix of argon2 representation
		hashedPassword = fmt.Sprintf("%s", hashedPassword[1:])
	default:
		hashedPassword = fmt.Sprintf("%s$%s", parts[0], hashedPassword)
	}

	// Compare using time constant operation
	return subtle.ConstantTimeCompare(encoded, []byte(hashedPassword)) == 1, nil
}

// NeedsUpgrade returns the password hash upgrade need when DefaultAlgorithm is changed
func NeedsUpgrade(encoded []byte) bool {
	return strings.HasPrefix(string(encoded), DefaultAlgorithm)
}

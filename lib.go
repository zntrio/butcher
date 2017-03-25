package butcher

import (
	"encoding/hex"
	"fmt"
)

// -----------------------------------------------------------------------------

// Butcher defines the hasher configuration
type Butcher struct {
	password    []byte
	algorithm   string
	salt        *[]byte
	iterations  *int
	cpucost     *int
	memcost     *int
	parallelism *int
}

// -----------------------------------------------------------------------------

// New butcher instance is buildded according options
func New(algo string, options ...Option) (*Butcher, error) {
	var err error

	// Initialize default butcher
	butcher := Butcher{}

	// Iterates on given options
	for _, option := range options {
		err = option(&butcher)
		if err != nil {
			break
		}
	}

	return &butcher, err
}

// -----------------------------------------------------------------------------

func (b *Butcher) String() string {
	switch b.algorithm {
	case "scrypt":
		return fmt.Sprintf("scrypt$%s$%d$%d$%d$%s", hex.EncodeToString(*b.salt), *b.cpucost, *b.memcost, *b.parallelism, hex.EncodeToString(b.password))
	default:
		if b.iterations != nil {
			return fmt.Sprintf("%s$%s$%d$%s", b.algorithm, hex.EncodeToString(*b.salt), *b.iterations, hex.EncodeToString(b.password))
		}

		return fmt.Sprintf("%s$%s$%s", b.algorithm, hex.EncodeToString(*b.salt), hex.EncodeToString(b.password))
	}
}

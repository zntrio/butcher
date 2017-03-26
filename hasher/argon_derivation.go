package hasher

import (
	"fmt"

	"github.com/lhecker/argon2"
)

type argonDeriver struct {
	salt []byte
}

func newArgon2Deriver(salt []byte) (Strategy, error) {
	c := &argonDeriver{
		salt: salt,
	}
	return c, nil
}

func (d *argonDeriver) Hash(password []byte) (string, error) {
	// Initialize Argon 2 default config
	cfg := argon2.DefaultConfig()

	// Return hash encoded argon2i
	hashEncoded, err := cfg.Hash([]byte(password), d.salt)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%s", hashEncoded.Encode()), nil
}

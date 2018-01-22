package hasher

import (
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/argon2"
)

type argonDeriver struct {
	salt    []byte
	time    uint32
	memory  uint32
	threads uint8
	keyLen  uint32
}

func newArgon2Deriver(salt []byte) (Strategy, error) {
	c := &argonDeriver{
		salt:    salt,
		time:    4,
		memory:  32 * 1024,
		threads: 4,
		keyLen:  64,
	}
	return c, nil
}

func (d *argonDeriver) Hash(password []byte) (string, error) {
	// Return hash encoded argon2i
	hash := argon2.Key([]byte(password), d.salt, d.time, d.memory, d.threads, d.keyLen)

	return fmt.Sprintf(
		"v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		d.memory,
		d.time,
		d.threads,
		base64.RawStdEncoding.EncodeToString(d.salt),
		base64.RawStdEncoding.EncodeToString(hash),
	), nil
}

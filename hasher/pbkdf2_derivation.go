package hasher

import (
	"encoding/hex"
	"fmt"
	"hash"

	"golang.org/x/crypto/pbkdf2"
)

type pbkdf2Deriver struct {
	h          func() hash.Hash
	salt       []byte
	iterations int
	keylen     int
}

func newPbkdf2Deriver(hash func() hash.Hash, salt []byte, iterations int, keyLen int) (Strategy, error) {
	c := &pbkdf2Deriver{
		h:          hash,
		salt:       salt,
		iterations: iterations,
		keylen:     keyLen,
	}
	return c, nil
}

func (d *pbkdf2Deriver) Hash(password []byte) (string, error) {
	hashedPassword := pbkdf2.Key(password, d.salt, d.iterations, d.keylen, d.h)
	return fmt.Sprintf("%s$%d$%s", hex.EncodeToString(d.salt), d.iterations, hex.EncodeToString(hashedPassword)), nil
}

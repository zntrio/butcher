package hasher

import (
	"encoding/base64"
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
	return fmt.Sprintf("$i=%d,l=%d$%s$%s", d.iterations, d.keylen, base64.RawStdEncoding.EncodeToString(d.salt), base64.RawStdEncoding.EncodeToString(hashedPassword)), nil
}

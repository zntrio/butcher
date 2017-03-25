package hasher

import (
	"crypto/hmac"
	"encoding/hex"
	"fmt"
	"hash"
	"sync"

	"golang.org/x/crypto/bcrypt"
)

type bcryptDeriver struct {
	mu   sync.Mutex
	h    hash.Hash
	salt []byte
	cost int
}

func newBcryptDeriver(hash func() hash.Hash, salt []byte, cost int) (Strategy, error) {
	c := &bcryptDeriver{
		h:    hmac.New(hash, salt),
		salt: salt,
		cost: cost,
		mu:   sync.Mutex{},
	}
	return c, nil
}

func (d *bcryptDeriver) digest(data []byte) []byte {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.h.Reset()
	d.h.Write(data)
	return d.h.Sum(nil)
}

func (d *bcryptDeriver) Hash(password []byte) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword(d.digest(password), d.cost)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%s$%d$%s", hex.EncodeToString(d.salt), d.cost, hex.EncodeToString(hashedPassword)), nil
}

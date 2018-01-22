/*
 * The MIT License (MIT)
 * Copyright (c) 2018 Thibault NORMAND
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software
 * and associated documentation files (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or substantial
 * portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
 * TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

package hasher

import (
	"crypto/hmac"
	"encoding/base64"
	"fmt"
	"hash"
	"sync"

	"golang.org/x/crypto/scrypt"
)

type scryptDeriver struct {
	mu     sync.Mutex
	h      hash.Hash
	salt   []byte
	n      int
	r      int
	p      int
	keyLen int
}

func newScryptDeriver(hash func() hash.Hash, salt []byte, cost int) (Strategy, error) {
	c := &scryptDeriver{
		h:      hmac.New(hash, salt),
		salt:   salt,
		n:      17,
		r:      8,
		p:      1,
		keyLen: 64,
		mu:     sync.Mutex{},
	}
	return c, nil
}

func (d *scryptDeriver) digest(data []byte) []byte {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.h.Reset()
	d.h.Write(data)
	return d.h.Sum(nil)
}

func (d *scryptDeriver) Hash(password []byte) (string, error) {
	hashedPassword, err := scrypt.Key(d.digest(password), d.salt, 1<<uint(d.n), d.r, d.p, d.keyLen)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("$n=%d,r=%d,p=%d$%s$%s", d.n, d.r, d.p, base64.RawStdEncoding.EncodeToString(d.salt), base64.RawStdEncoding.EncodeToString(hashedPassword)), nil
}

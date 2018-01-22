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

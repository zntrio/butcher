/*
 * The MIT License (MIT)
 * Copyright (c) 2019 Thibault NORMAND
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package hasher

import (
	"crypto/sha512"
	"hash"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/blake2b"
)

//Algorithm is the password hashing strategy code
type Algorithm uint8

const (
	// Argon2id defines the argon2i hashing algorithm
	Argon2id = Algorithm(0x01)
	// Pbkdf2HmacSha512 defines pbkdf2+hmac-sha512 hashing algorithm
	Pbkdf2HmacSha512 = Algorithm(0x02)
	//ScryptBlake2b512 defines scrypt+blake2b-512 hashing algorithm
	ScryptBlake2b512 = Algorithm(0x03)
)

const (
	pbkdf2Iterations = 500000
)

// Strategies defines available hashing strategies
var Strategies = map[Algorithm]func(func() []byte) Strategy{
	Argon2id: func(salt func() []byte) Strategy {
		s, _ := newArgon2Deriver(salt(), argon2.IDKey)
		return s
	},
	ScryptBlake2b512: func(salt func() []byte) Strategy {
		s, _ := newScryptDeriver(func() hash.Hash {
			h, err := blake2b.New512(nil)
			if err != nil {
				panic(err.Error())
			}
			return h
		}, salt())
		return s
	},
	Pbkdf2HmacSha512: func(salt func() []byte) Strategy {
		s, _ := newPbkdf2Deriver(sha512.New, salt(), pbkdf2Iterations, sha512.Size)
		return s
	},
}

// Licensed to Butcher under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Butcher licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package hasher

import (
	"crypto/sha512"
	"hash"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/blake2b"
)

// Algorithm is the password hashing strategy code
type Algorithm uint8

const (
	// Argon2id defines the argon2i hashing algorithm
	Argon2id = Algorithm(0x01)
	// Pbkdf2HmacSha512 defines pbkdf2+hmac-sha512 hashing algorithm
	Pbkdf2HmacSha512 = Algorithm(0x02)
	// ScryptBlake2b512 defines scrypt+blake2b-512 hashing algorithm
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

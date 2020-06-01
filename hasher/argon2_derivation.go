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

type kdFunc func(password, salt []byte, time, memory uint32, threads uint8, keyLen uint32) []byte

type argonDeriver struct {
	salt    []byte
	time    uint32
	memory  uint32
	threads uint8
	keyLen  uint32
	kdf     kdFunc
}

func newArgon2Deriver(salt []byte, kdf kdFunc) (Strategy, error) {
	return &argonDeriver{
		salt:    salt,
		time:    6,
		memory:  128 * 1024,
		threads: 4,
		keyLen:  64,
		kdf:     kdf,
	}, nil
}

// -----------------------------------------------------------------------------

func (d *argonDeriver) Hash(password []byte) (*Metadata, error) {
	// Return hash encoded argon2i
	hash := d.kdf([]byte(password), d.salt, d.time, d.memory, d.threads, d.keyLen)

	return &Metadata{
		Algorithm: uint8(Argon2id),
		Version:   uint8(1),
		Salt:      d.salt,
		Hash:      hash,
	}, nil
}

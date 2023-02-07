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
	"golang.org/x/crypto/scrypt"
)

type scryptDeriver struct {
	salt   []byte
	n      int
	r      int
	p      int
	keyLen int
}

func newScryptDeriver(salt []byte) (Strategy, error) {
	return &scryptDeriver{
		salt:   salt,
		n:      17,
		r:      8,
		p:      1,
		keyLen: 64,
	}, nil
}

// -----------------------------------------------------------------------------

func (d *scryptDeriver) Hash(password []byte) (*Metadata, error) {
	hashedPassword, err := scrypt.Key(password, d.salt, 1<<uint(d.n), d.r, d.p, d.keyLen)
	if err != nil {
		return nil, err
	}

	return &Metadata{
		Algorithm: uint8(Scrypt),
		Version:   uint8(1),
		Salt:      d.salt,
		Hash:      hashedPassword,
	}, nil
}

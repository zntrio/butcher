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
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	cbor "github.com/fxamacker/cbor/v2"
)

// Metadata represents hasher result
type Metadata struct {
	_ struct{} `cbor:",toarray"`

	Algorithm uint8  `cbor:"1,keyasint"`
	Version   uint8  `cbor:"2,keyasint"`
	Salt      []byte `cbor:"3,keyasint"`
	Hash      []byte `cbor:"4,keyasint"`
}

// Pack metadata as BASE64URL CBOR payload
func (m *Metadata) Pack() (string, error) {
	// Encode as CBOR
	payload, err := cbor.Marshal(m)
	if err != nil {
		return "", fmt.Errorf("unable to serialize metadata: %w", err)
	}

	// Return encoded struct
	return base64.RawStdEncoding.EncodeToString(payload), nil
}

// Decode metadata from string
func Decode(r io.Reader) (*Metadata, error) {
	// Check arguments
	if r == nil {
		return nil, errors.New("reader must not be nil")
	}

	// Decode as list
	meta := &Metadata{}
	if err := cbor.NewDecoder(base64.NewDecoder(base64.RawStdEncoding, io.LimitReader(r, 138))).Decode(meta); err != nil {
		return nil, fmt.Errorf("unable to decode metadata: %w", err)
	}

	// Rebuild metadata instance
	return meta, nil
}

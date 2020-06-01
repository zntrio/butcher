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
	"fmt"
	"io"
	"io/ioutil"
	"regexp"

	"github.com/ugorji/go/codec"
)

var (
	cborHandle = new(codec.CborHandle)
	metaFormat = regexp.MustCompile("^[-A-Za-z0-9/+]{138}$")
)

// Metadata represents hasher result
type Metadata struct {
	// nolint
	_struct bool `codec:",toarray"` // encode struct as an array

	Algorithm uint8
	Version   uint8
	Salt      []byte
	Hash      []byte
}

// Pack metadata as BASE64URL CBOR payload
func (m *Metadata) Pack() (string, error) {
	// Encode as CBOR
	var bs []byte
	if err := codec.NewEncoderBytes(&bs, cborHandle).Encode(m); err != nil {
		return "", err
	}

	// Return encoded struct
	return base64.RawStdEncoding.EncodeToString(bs), nil
}

// Decode metadata from string
func Decode(r io.Reader) (*Metadata, error) {
	// Read all
	buf, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("butcher: unable to read encoded metadata: %v", err)
	}

	// Check format
	if !metaFormat.Match(buf) {
		return nil, fmt.Errorf("butcher: invalid hash format")
	}

	// Decode base64
	input, err := base64.RawStdEncoding.DecodeString(string(buf))
	if err != nil {
		return nil, fmt.Errorf("butcher: unable to decode given metadata: %v", err)
	}

	// Decode as list
	meta := &Metadata{}
	if err := codec.NewDecoderBytes(input, cborHandle).Decode(meta); err != nil {
		return nil, fmt.Errorf("butcher: unable to deserialize metadata: %v", err)
	}

	// Rebuild metadata instance
	return meta, nil
}

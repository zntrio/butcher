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
	_struct bool `codec:",toarray"` //encode struct as an array

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

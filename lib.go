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

package butcher

import (
	"bytes"
	"crypto/subtle"
	"errors"
	"fmt"
	"sync"

	"github.com/zntrio/butcher/hasher"
)

// -----------------------------------------------------------------------------

const (
	// DefaultAlgorithm defines the default algorithm to use when not specified
	DefaultAlgorithm = hasher.Argon2id
	// ExpectedAlgorithmVersion defines the lower supported version of the hashing strategy
	ExpectedAlgorithmVersion = uint8(0x01)
)

// DefaultSaltFunc defines the default salt generation factory to use when not specified
var DefaultSaltFunc = RandomNonce(32)

var (
	// Default butcher instance
	defaultInstance *Butcher
	once            sync.Once
)

// -----------------------------------------------------------------------------

var (
	// ErrInvalidHash is raised when caller try to invoke not supported algorithm
	ErrInvalidHash = errors.New("butcher: invalid hash")
	// ErrStrategyNotSupported is raised when caller try to invoke not supported algorithm
	ErrStrategyNotSupported = errors.New("butcher: given strategy is not supported")
)

// -----------------------------------------------------------------------------

// Butcher defines the hasher configuration
type Butcher struct {
	algorithm hasher.Algorithm
	strategy  hasher.Strategy
	saltFunc  func() []byte
	pepper    []byte
}

// -----------------------------------------------------------------------------

// New butcher instance is buildded according options
func New(options ...Option) (*Butcher, error) {
	var err error

	// Initialize default butcher
	butcher := Butcher{
		algorithm: DefaultAlgorithm,
		saltFunc:  DefaultSaltFunc,
		pepper:    nil,
	}

	// Iterates on given options
	for _, option := range options {
		option(&butcher)
	}

	// Initialize hash strategy
	if _, ok := hasher.Strategies[butcher.algorithm]; !ok {
		return nil, ErrStrategyNotSupported
	}

	// Assign strategy to instance
	butcher.strategy = hasher.Strategies[butcher.algorithm](butcher.saltFunc)

	return &butcher, err
}

// -----------------------------------------------------------------------------

// Hash the given password with the hash strategy
func (b *Butcher) Hash(password []byte) (string, error) {
	// Check supported algorithm
	strategy, ok := hasher.Strategies[b.algorithm]
	if !ok {
		return "", ErrStrategyNotSupported
	}

	// Peppering password
	var peppered []byte
	peppered = append(peppered, password...)
	if len(b.pepper) > 0 {
		peppered = append(peppered, b.pepper...)
	}

	// Hash password
	meta, err := strategy(b.saltFunc).Hash(peppered)
	if err != nil {
		return "", err
	}

	// Return result
	return meta.Pack()
}

// Verify cleartext password with encoded one
func (b *Butcher) Verify(encoded, password []byte) (bool, error) {
	// Decode from string
	m, err := hasher.Decode(bytes.NewReader(encoded))
	if err != nil {
		return false, ErrInvalidHash
	}

	// Check supported algorithm
	strategy, ok := hasher.Strategies[hasher.Algorithm(m.Algorithm)]
	if !ok {
		return false, ErrStrategyNotSupported
	}

	// Peppering password
	var peppered []byte
	peppered = append(peppered, password...)
	if len(b.pepper) > 0 {
		peppered = append(peppered, b.pepper...)
	}

	// Hash given password
	pmeta, err := strategy(FixedNonce(m.Salt)).Hash(peppered)
	if err != nil {
		return false, fmt.Errorf("butcher: unable to hash given password, %v", err)
	}

	// Encode given password
	hashedPassword, err := pmeta.Pack()
	if err != nil {
		return false, fmt.Errorf("butcher: unable to encode given password, %v", err)
	}

	// Time constant compare
	return subtle.ConstantTimeCompare(encoded, []byte(hashedPassword)) == 1, nil
}

// NeedsUpgrade returns the password hash upgrade need when DefaultAlgorithm is changed
func (b *Butcher) NeedsUpgrade(encoded []byte) bool {
	// Decode from string
	m, err := hasher.Decode(bytes.NewReader(encoded))
	if err != nil {
		return false
	}
	return hasher.Algorithm(m.Algorithm) != DefaultAlgorithm && m.Version < ExpectedAlgorithmVersion
}

// -----------------------------------------------------------------------------

// Hash password using default instance
func Hash(password []byte) (string, error) {
	return defaultInstance.Hash(password)
}

// Verify password using default instance
func Verify(encoded, password []byte) (bool, error) {
	return defaultInstance.Verify(encoded, password)
}

// NeedsUpgrade returns the password hash upgrade need when DefaultAlgorithm is changed
func NeedsUpgrade(encoded []byte) bool {
	return defaultInstance.NeedsUpgrade(encoded)
}

func init() {
	once.Do(func() {
		defaultInstance, _ = New()
	})
}

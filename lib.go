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

package butcher

import (
	"bytes"
	"crypto/subtle"
	"errors"
	"fmt"
	"sync"

	"go.zenithar.org/butcher/hasher"
)

// -----------------------------------------------------------------------------

const (
	// DefaultAlgorithm defines the default algorithm to use when not specified
	DefaultAlgorithm = hasher.Argon2id
	// ExpectedAlgorithmVersion defines the lower supported version of the hashing strategy
	ExpectedAlgorithmVersion = uint8(0x01)
)

var (
	// DefaultSaltFunc defines the default salt generation factory to use when not specified
	DefaultSaltFunc = RandomNonce(32)
)

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
	return meta.Encode()
}

// Verify cleartext password with encoded one
func (b *Butcher) Verify(encoded []byte, password []byte) (bool, error) {
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
	hashedPassword, err := pmeta.Encode()
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
func Verify(encoded []byte, password []byte) (bool, error) {
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

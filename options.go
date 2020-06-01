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

import "zntr.io/butcher/hasher"

// Option is the butcher option setting function signature
type Option func(*Butcher)

// WithAlgorithm defines the algorithm to use for hashing password
func WithAlgorithm(algo hasher.Algorithm) Option {
	return func(b *Butcher) {
		b.algorithm = algo
	}
}

// WithSaltFunc defines the salt factory value for salt generation
func WithSaltFunc(factory func() []byte) Option {
	return func(b *Butcher) {
		b.saltFunc = factory
	}
}

// WithPepper defines the password peppering value
func WithPepper(value []byte) Option {
	return func(b *Butcher) {
		b.pepper = value
	}
}

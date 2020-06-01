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

package butcher_test

import (
	"fmt"
	"testing"

	"zntr.io/butcher"
	"zntr.io/butcher/hasher"

	"github.com/stretchr/testify/require"
)

func TestDefaultButcher(t *testing.T) {
	t.Parallel()

	password := []byte("foo")

	encoded, err := butcher.Hash(password)
	require.NoError(t, err, "Password encoding should not raise error")
	require.NotNil(t, encoded, "Encoded password should not be nil")

	valid, err := butcher.Verify([]byte(encoded), password)
	require.NoError(t, err, "Password verification should not raise error")
	require.True(t, valid, "Password should be valid")

	upgrade := butcher.NeedsUpgrade([]byte(encoded))
	require.False(t, upgrade, "Password should not need upgrades")
}

func TestButcherStrategies(t *testing.T) {
	strategies := []hasher.Algorithm{hasher.Argon2id, hasher.ScryptBlake2b512, hasher.Pbkdf2HmacSha512}

	for _, algo := range strategies {
		algorithm := algo
		t.Run(fmt.Sprintf("%d", algorithm), func(t *testing.T) {
			t.Parallel()

			b, err := butcher.New(
				butcher.WithAlgorithm(algorithm),
				butcher.WithPepper([]byte("foobar")),
				butcher.WithSaltFunc(butcher.RandomNonce(32)),
			)
			require.NoError(t, err, "Error should not be raised")
			require.NotNil(t, b, "Butcher instance should not be nil")

			out, err := b.Hash([]byte("toto"))
			require.NoError(t, err, "Hash should not raise error")
			require.NotEmpty(t, out, "Encoded password should not be empty")

			fmt.Printf("%s\n", out)

			out2, err := b.Hash([]byte("toto"))
			require.NoError(t, err, "Hash should not raise error")
			require.NotEmpty(t, out, "Encoded password should not be empty")
			require.NotEqual(t, out, out2, "Same password should not have same output")

			ok, err := b.Verify([]byte(out2), []byte("toto"))
			require.NoError(t, err, "Password validation should not raise an error")
			require.True(t, ok, "Password should be valid")

			ok, err = b.Verify([]byte(out2), []byte("titi"))
			require.NoError(t, err, "Password validation mismatch should not raise an error")
			require.False(t, ok, "Password should not be valid")
		})

	}
}

func BenchmarkArgon2id(b *testing.B) {
	butch, _ := butcher.New(butcher.WithAlgorithm(hasher.Argon2id))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// nolint
		butch.Hash([]byte("toto"))
	}
}

func BenchmarkPbkdf2Sha512(b *testing.B) {
	butch, _ := butcher.New(butcher.WithAlgorithm(hasher.Pbkdf2HmacSha512))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// nolint
		butch.Hash([]byte("toto"))
	}
}

func BenchmarkScryptBlake2b512(b *testing.B) {
	butch, _ := butcher.New(butcher.WithAlgorithm(hasher.ScryptBlake2b512))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// nolint
		butch.Hash([]byte("toto"))
	}
}

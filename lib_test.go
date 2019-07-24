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

package butcher_test

import (
	"fmt"
	"testing"

	"go.zenithar.org/butcher"
	"go.zenithar.org/butcher/hasher"

	"github.com/stretchr/testify/require"
)

func TestDefaultButcher(t *testing.T) {
	t.Parallel()

	var (
		password = []byte("foo")
	)

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
		butch.Hash([]byte("toto"))
	}
}

func BenchmarkPbkdf2Sha512(b *testing.B) {
	butch, _ := butcher.New(butcher.WithAlgorithm(hasher.Pbkdf2HmacSha512))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		butch.Hash([]byte("toto"))
	}
}

func BenchmarkScryptBlake2b512(b *testing.B) {
	butch, _ := butcher.New(butcher.WithAlgorithm(hasher.ScryptBlake2b512))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		butch.Hash([]byte("toto"))
	}
}

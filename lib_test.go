/*
 * The MIT License (MIT)
 * Copyright (c) 2018 Thibault NORMAND
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software
 * and associated documentation files (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or substantial
 * portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
 * TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

package butcher_test

import (
	"strings"
	"testing"

	"go.zenithar.org/butcher"
	"go.zenithar.org/butcher/hasher"
)

func TestDefaultButcher(t *testing.T) {
	b, _ := butcher.New()

	out, err := b.Hash([]byte("toto"))
	if out == "" {
		t.Fatal("Result should not be empty !")
	}
	if err != nil {
		t.Fatal("Error should be nil")
	}
	if !strings.HasPrefix(out, butcher.DefaultAlgorithm) {
		t.Fatal("Result should have a valid prefix")
	}

	out2, _ := b.Hash([]byte("toto"))
	if out == out2 {
		t.Fatal("Hash should be different for same password")
	}

	ok, err := butcher.Verify([]byte(out), []byte("toto"))
	if err != nil {
		t.Fatal("Hash verification should not return an error")
	}
	if !ok {
		t.Fatal("Hash verification should be valid")
	}

	ok, err = butcher.Verify([]byte(out2), []byte("toto"))
	if err != nil {
		t.Fatal("Hash verification should not return an error")
	}
	if !ok {
		t.Fatal("Hash verification should be valid")
	}
}

func TestButcherStrategies(t *testing.T) {

	strategies := []string{hasher.Argon2i, hasher.Pbkdf2Blake2b512, hasher.Pbkdf2Keccak512, hasher.Pbkdf2Sha512, hasher.ScryptBlake2b512}

	for _, algo := range strategies {
		b, _ := butcher.New(butcher.WithAlgorithm(algo))
		out, err := b.Hash([]byte("toto"))

		if out == "" {
			t.Fatal("Result should not be empty !")
		}
		if err != nil {
			t.Fatal("Error should be nil")
		}
		if !strings.HasPrefix(out, algo) {
			t.Fatal("Result should have a valid prefix")
		}

		out2, _ := b.Hash([]byte("toto"))
		if out == out2 {
			t.Fatal("Hash should be different for same password")
		}

		ok, err := butcher.Verify([]byte(out2), []byte("toto"))
		if err != nil {
			t.Logf("Given Hash: %s", out2)
			t.Logf("Error : %v", err)
			t.Fatal("Hash verification should not return an error")
		}
		if !ok {
			t.Logf("Given Hash: %s", out2)
			t.Fatal("Hash verification should be valid")
		}
	}

}

func BenchmarkPbkdf2Blake2b512(b *testing.B) {
	butch, _ := butcher.New(butcher.WithAlgorithm(hasher.Pbkdf2Blake2b512))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		butch.Hash([]byte("toto"))
	}
}

func BenchmarkPbkdf2Keccac512(b *testing.B) {
	butch, _ := butcher.New(butcher.WithAlgorithm(hasher.Pbkdf2Keccak512))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		butch.Hash([]byte("toto"))
	}
}

func BenchmarkPbkdf2Sha512(b *testing.B) {
	butch, _ := butcher.New(butcher.WithAlgorithm(hasher.Pbkdf2Sha512))
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

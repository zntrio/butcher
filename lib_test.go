package butcher_test

import (
	"strings"
	"testing"

	"zenithar.org/go/butcher"
	"zenithar.org/go/butcher/hasher"
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

	strategies := []string{hasher.Argon2i, hasher.BcryptBlake2b512, hasher.Pbkdf2Blake2b512, hasher.Pbkdf2Keccak512, hasher.Pbkdf2Sha512, hasher.BcryptSha512}

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
	}

}

func BenchmarkBcryptBlake2b512(b *testing.B) {
	butch, _ := butcher.New(butcher.WithAlgorithm(hasher.BcryptBlake2b512))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		butch.Hash([]byte("toto"))
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

func BenchmarkBcryptSha512(b *testing.B) {
	butch, _ := butcher.New(butcher.WithAlgorithm(hasher.BcryptSha512))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		butch.Hash([]byte("toto"))
	}
}

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
		t.Fatal("Resout should not be empty !")
	}
	if err != nil {
		t.Fatal("Error should be nil")
	}
	if !strings.HasPrefix(out, "bcrypt+sha512") {
		t.Fatal("Result should have a valid prefix")
	}

	out2, _ := b.Hash([]byte("toto"))
	if out == out2 {
		t.Fatal("Hash should be different for same password")
	}
}

func TestButcherStrategies(t *testing.T) {

	strategies := []string{hasher.BcryptBlake2b512, hasher.Pbkdf2Blake2b512, hasher.Pbkdf2Keccak512, hasher.Pbkdf2Sha512, hasher.BcryptSha512}

	for _, algo := range strategies {
		b, _ := butcher.New(butcher.WithAlgorithm(algo))
		out, err := b.Hash([]byte("toto"))
		if out == "" {
			t.Fatal("Resout should not be empty !")
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

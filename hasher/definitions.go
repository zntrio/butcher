package hasher

import (
	"crypto/sha512"

	"github.com/minio/blake2b-simd"
	"golang.org/x/crypto/sha3"
)

const (
	// BcryptBlake2b512 defines bcrypt+blake2b-512 hashing algorithm
	BcryptBlake2b512 = "bcrypt+blake2b-512"
	// Pbkdf2Blake2b512 defines pbkdf2+blake2b-512 hashing algorithm
	Pbkdf2Blake2b512 = "pbkdf2+blake2b-512"
	// Pbkdf2Sha512 defines pbkdf2+sha512 hashing algorithm
	Pbkdf2Sha512 = "pbkdf2+sha512"
	// Pbkdf2Keccak512 defines pbkdf2+sha3-512 hashing algorithm
	Pbkdf2Keccak512 = "pbkdf2+sha3-512"
	// BcryptSha512 defines bcrypt+sha512 hashing algorithm
	BcryptSha512 = "bcrypt+sha512"
)

// Strategies defines available hashing strategies
var Strategies = map[string]func([]byte) Strategy{
	BcryptBlake2b512: func(salt []byte) Strategy {
		s, _ := newBcryptDeriver(blake2b.New512, salt, 12)
		return s
	},
	Pbkdf2Blake2b512: func(salt []byte) Strategy {
		s, _ := newPbkdf2Deriver(blake2b.New512, salt, 50000, blake2b.Size)
		return s
	},
	Pbkdf2Sha512: func(salt []byte) Strategy {
		s, _ := newPbkdf2Deriver(sha512.New, salt, 50000, sha512.Size)
		return s
	},
	Pbkdf2Keccak512: func(salt []byte) Strategy {
		s, _ := newPbkdf2Deriver(sha3.New512, salt, 50000, 64)
		return s
	},
	BcryptSha512: func(salt []byte) Strategy {
		s, _ := newBcryptDeriver(sha512.New, salt, 12)
		return s
	},
}

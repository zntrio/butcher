package butcher

import "crypto/rand"

// NonceFactory defines the function signature that returns a salt factory
type NonceFactory func() []byte

// FixedNonce returns a nonce factory that returns the given salt
func FixedNonce(salt []byte) func() []byte {
	return func() []byte {
		return salt
	}
}

// RandomNonce returns a nonce factory that returns a random length bound salt
func RandomNonce(length int) func() []byte {
	return func() []byte {
		salt := make([]byte, length)
		rand.Read(salt)
		return salt
	}
}

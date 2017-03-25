package hasher

// Strategy defines hash algorithm strategy contract
type Strategy interface {
	Hash([]byte) (string, error)
}

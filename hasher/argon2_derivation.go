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

package hasher

type kdFunc func(password, salt []byte, time, memory uint32, threads uint8, keyLen uint32) []byte

type argonDeriver struct {
	salt    []byte
	time    uint32
	memory  uint32
	threads uint8
	keyLen  uint32
	kdf     kdFunc
}

func newArgon2Deriver(salt []byte, kdf kdFunc) (Strategy, error) {
	return &argonDeriver{
		salt:    salt,
		time:    6,
		memory:  128 * 1024,
		threads: 4,
		keyLen:  64,
		kdf:     kdf,
	}, nil
}

// -----------------------------------------------------------------------------

func (d *argonDeriver) Hash(password []byte) (*Metadata, error) {
	// Return hash encoded argon2i
	hash := d.kdf([]byte(password), d.salt, d.time, d.memory, d.threads, d.keyLen)

	return &Metadata{
		Algorithm: uint8(Argon2id),
		Version:   uint8(1),
		Salt:      d.salt,
		Hash:      hash,
	}, nil
}

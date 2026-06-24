package testdc

import (
	"crypto/aes"
	"crypto/cipher"
)

func newCTR(key, iv []byte) cipher.Stream {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	return cipher.NewCTR(block, iv)
}

package ssgo

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/sha1"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

var PrimaryKey []byte
var KeySize = 32 // salt size = key size

const NonceSize = 12
const TagSize = 16

var NewKey func([]byte) (cipher.AEAD, error)

func NewAESGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func SetCipher(cipher string, password string) {
	switch cipher {
	case "aes-128-gcm":
		KeySize = 16
		NewKey = NewAESGCM
	case "aes-256-gcm":
		NewKey = NewAESGCM
	case "chacha20-poly1305":
		NewKey = chacha20poly1305.New
	default:
		fmt.Printf("method: %v not in [aes-128-gcm, aes-256-gcm, chacha20-poly1305] \n", cipher)
		os.Exit(1)
	}
	PrimaryKey = bytesToKey(password, KeySize)
}

type Nonce [NonceSize]byte

func (nonce *Nonce) increase() {
	var c = 1
	for i, b := range nonce {
		c += int(b)
		nonce[i] = byte(c)
		c >>= 8
	}
}

// EVP_bytesToKey, deriving master key from password
func bytesToKey(passsword string, keySize int) []byte {
	var res []byte
	data := []byte(passsword)
	hash := md5.New()
	for len(res) < keySize {
		hash.Write(res)
		hash.Write(data)
		res = hash.Sum(res)
		hash.Reset()
	}
	return res
}

var INFO = []byte("ss-subkey")

func sessinoKey(salt []byte) (cipher.AEAD, error) {
	hkdf := hkdf.New(sha1.New, PrimaryKey, salt, INFO)
	okm := make([]byte, KeySize)
	if _, err := io.ReadFull(hkdf, okm); err != nil {
		return nil, err
	}
	return NewKey(okm)
}

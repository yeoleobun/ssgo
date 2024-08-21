package ssgo

import (
	"crypto/md5"
	"crypto/sha1"
	"io"
	"log"

	"golang.org/x/crypto/hkdf"
)

// EVP_BytesToKey, deriving key from password
func EVP_BytesToKey(passsword string, keySize int) []byte {
	var res []byte
	data := []byte(passsword)
	hash := md5.New()
	for len(res) < keySize {
		hash.Write(res)
		hash.Write(data)
		res = hash.Sum(res)
		hash.Reset()
	}
	log.Printf("primary key: %v", res)
	return res
}

func HKDF_SHA1(salt []byte, ikm []byte, keySize int) []byte {
	hkdf := hkdf.New(sha1.New, ikm, salt, []byte("ss-subkey"))
	okm := make([]byte, keySize)
	if _, err := io.ReadFull(hkdf, okm); err != nil {
		panic("generate session key failed")
	}
	return okm
}

package ssgo

import (
	"bytes"
	"testing"
)

func TestDeriveKey(t *testing.T) {
	passsword := "barfoo!"
	target := []byte{179, 173, 196, 120, 57, 224, 71, 235, 34, 136, 112, 82, 109, 200, 252, 48, 179, 71, 40, 127, 252, 163, 4, 93, 206, 160, 107, 63, 223, 9, 10, 203}
	if !bytes.Equal(EVP_BytesToKey(passsword, 16), target[:16]) {
		t.Fatal("deriving 16 bytes key faild")
	}
	if !bytes.Equal(EVP_BytesToKey(passsword, 32), target) {
		t.Fatal("deriving 32 bytes key faild")
	}

	salt := [32]byte{73, 209, 149, 63, 118, 64, 79, 14, 224, 69, 250, 36, 232, 175, 9, 171, 99, 138, 200, 0, 251, 86, 220, 88, 141, 153, 128, 99, 6, 131, 8, 10}
	res1 := HKDF_SHA1(salt[:16], EVP_BytesToKey(passsword, 16), 16)
	target1 := []byte{247, 48, 116, 16, 6, 14, 169, 127, 98, 50, 188, 127, 237, 108, 232, 211, 213, 149, 241, 224}

	if !bytes.Equal(res1, target1[:16]) {
		t.Fatal("deriving 16 bytes session key failed")
	}
	res2 := HKDF_SHA1(salt[:], EVP_BytesToKey(passsword, 32), 32)
	target2 := []byte{195, 251, 65, 117, 35, 38, 227, 4, 109, 131, 133, 22, 92, 143, 91, 222, 234, 210, 213, 130, 188, 47, 212, 191, 140, 26, 184, 5, 20, 139, 82, 226, 62, 187, 67, 108, 185, 178, 165, 179}

	if !bytes.Equal(res2, target2[:32]) {
		t.Fatal("deriving 32 bytes session key failed")
	}

}

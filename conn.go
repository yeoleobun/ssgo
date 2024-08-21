package ssgo

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"io"
	"iter"
	"log/slog"
	"net"

	"golang.org/x/crypto/chacha20poly1305"
)

var PrimaryKey = EVP_BytesToKey("barfoo!", 32)

const FOUR_K int = 4096

const SaltSize = 32
const KeySize = 32
const NonceSize = 12
const TagSize = 16
const MaxPayloadSize = 0x3fff

type Nonce [NonceSize]byte

func (nonce *Nonce) increase() {
	var c = 1
	for i, b := range nonce {
		c += int(b)
		nonce[i] = byte(c)
		c >>= 8
	}
}

func Rest(bytes []byte) []byte {
	return bytes[len(bytes):cap(bytes)]
}

func Grow(bytes *[]byte, n int) {
	*bytes = (*bytes)[:len(*bytes)+n]
}

func Consume(bytes *[]byte, n int) {
	*bytes = (*bytes)[n:]
}

// ciphertext is a slice of buff
func ensure(conn net.Conn, buff *[]byte, ciphertext *[]byte, n int) (err error) {
	if len(*ciphertext) >= n {
		return nil
	}

	if cap(*buff) < n {
		newBuff := make([]byte, (n+FOUR_K-1)/FOUR_K*FOUR_K)
		*buff = newBuff
	}

	if cap(*ciphertext) < n {
		m := copy(*buff, *ciphertext)
		*ciphertext = (*buff)[:m]
	}

	var m int
	m, err = io.ReadAtLeast(conn, Rest(*ciphertext), n-len(*ciphertext))
	Grow(ciphertext, m)
	return
}

func DecryptSeq(conn net.Conn) iter.Seq2[[]byte, error] {
	return func(yield func([]byte, error) bool) {
		buff := make([]byte, FOUR_K)
		n, err := conn.Read(buff)
		if err != nil && !yield(nil, err) {
			return
		}
		key := HKDF_SHA1(buff[:SaltSize], PrimaryKey, KeySize)
		aead, _ := chacha20poly1305.New(key)
		var nonce Nonce
		ciphertext := buff[SaltSize:n]
		for {
			err := ensure(conn, &buff, &ciphertext, 2+TagSize)
			if err != nil && !yield(nil, err) {
				break
			}

			_, err = aead.Open(ciphertext[:0], nonce[:], ciphertext[:2+TagSize], nil)
			if err != nil && !yield(nil, err) {
				break
			}

			nonce.increase()
			length := int(binary.BigEndian.Uint16(ciphertext))
			Consume(&ciphertext, 2+TagSize)

			ensure(conn, &buff, &ciphertext, length+TagSize)
			if !yield(aead.Open(ciphertext[:0], nonce[:], ciphertext[:length+TagSize], nil)) {
				break
			}
			nonce.increase()
			Consume(&ciphertext, length+TagSize)
		}
	}
}

type EncryptWriter struct {
	conn   net.Conn
	aead   cipher.AEAD
	nonce  Nonce
	header [2 + TagSize]byte
}

func Split(conn net.Conn) (io.Writer, iter.Seq2[[]byte, error]) {
	return &EncryptWriter{conn: conn}, DecryptSeq(conn)
}

// b should have at least TagSize remaining capacity
func (w *EncryptWriter) Write(b []byte) (n int, err error) {
	var buffers net.Buffers = make([][]byte, 0, 3)
	if w.aead == nil {
		salt := make([]byte, SaltSize)
		rand.Read(salt)
		key := HKDF_SHA1(salt, PrimaryKey, KeySize)
		w.aead, _ = chacha20poly1305.New(key)
		buffers = append(buffers, salt)
	}

	binary.BigEndian.PutUint16(w.header[:], uint16(len(b)))
	buffers = append(buffers, w.aead.Seal(w.header[:0], w.nonce[:], w.header[:2], nil))
	w.nonce.increase()
	buffers = append(buffers, w.aead.Seal(b[:0], w.nonce[:], b, nil))
	w.nonce.increase()
	for len(buffers) > 0 {
		_, err = buffers.WriteTo(w.conn)
		if err != nil {
			slog.Debug("write buffers", "err", err)
			return
		}
	}
	n = len(b)
	return
}

func WriteAll(conn io.Writer, bytes []byte) error {
	for len(bytes) > 0 {
		n, err := conn.Write(bytes)
		if err != nil {
			return err
		}
		bytes = bytes[n:]
	}
	return nil
}

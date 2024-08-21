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

const _4k = 4096

const SaltSize = 32
const KeySize = 32
const NonceSize = 12
const TagSize = 16
const MaxPayloadSize = 0x3fff

type Nonce [NonceSize]byte

func (nonce *Nonce) increase() {
	c := 1
	for i, b := range nonce {
		c += int(b)
		nonce[i] = byte(c)
		c >>= 8
	}
}

func rest(bytes []byte) []byte {
	return bytes[len(bytes):cap(bytes)]
}

func grow(bytes *[]byte, n int) {
	*bytes = (*bytes)[:len(*bytes)+n]
}

func consume(bytes *[]byte, n int) {
	*bytes = (*bytes)[n:]
}

func ensure(conn net.Conn, buff *[]byte, ciphertext *[]byte, n int) error {
	if len(*ciphertext) >= n {
		return nil
	}

	if cap(*buff) < n {
		newBuff := make([]byte, (n+_4k-1)/_4k*_4k)
		*buff = newBuff
	}

	if cap(*ciphertext) < n {
		m := copy(*buff, *ciphertext)
		*ciphertext = (*buff)[:m]
	}

	m, err := io.ReadAtLeast(conn, rest(*ciphertext), n-len(*ciphertext))
	grow(ciphertext, m)
	if err != nil {
		return err
	}
	return nil
}

func DecryptSeq(conn net.Conn) iter.Seq2[[]byte, error] {
	return func(yield func([]byte, error) bool) {
		buff := make([]byte, _4k)
		n, err := conn.Read(buff)
		if err != nil {
			yield(nil, err)
			return
		}
		key := HKDF_SHA1(buff[:SaltSize], PrimaryKey, KeySize)
		aead, err := chacha20poly1305.New(key)
		if err != nil {
			yield(nil, err)
			return
		}
		var nonce Nonce
		ciphertext := buff[SaltSize:n]
		i := 0
		for {
			err := ensure(conn, &buff, &ciphertext, 2+TagSize)
			if err != nil && !yield(nil, err) {
				break
			}

			_, err = aead.Open(ciphertext[:0], nonce[:], ciphertext[:2+TagSize], nil)
			if err != nil && !yield(nil, err) {
				slog.Debug("decrypt length ", "err", err, "index", i)
				break
			}

			nonce.increase()
			length := int(binary.BigEndian.Uint16(ciphertext))
			consume(&ciphertext, 2+TagSize)

			ensure(conn, &buff, &ciphertext, length+TagSize)
			if !yield(aead.Open(ciphertext[:0], nonce[:], ciphertext[:length+TagSize], nil)) {
				slog.Debug("decrypt payload ", "err", err, "index", i)
				break
			}
			nonce.increase()
			consume(&ciphertext, length+TagSize)
			i += 1
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
	return NewConnWrapper(conn), DecryptSeq(conn)
}

func NewConnWrapper(conn net.Conn) *EncryptWriter {
	return &EncryptWriter{conn: conn}
}

// b should have TagSize remaining capacity
func (w *EncryptWriter) Write(b []byte) (n int, err error) {
	var buffers net.Buffers
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
			return
		}
	}
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

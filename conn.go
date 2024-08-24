package ssgo

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"io"
	"iter"
	"log/slog"
	"net"
	"sync"
	"time"
)

// split connection to encryt writer and decrypt iter
func Split(conn net.Conn) (io.Writer, iter.Seq2[[]byte, error]) {
	return &EncryptWriter{conn: conn}, DecryptIter(conn)
}

// encrypt and flush to coon
type EncryptWriter struct {
	conn   net.Conn
	aead   cipher.AEAD
	nonce  Nonce
	header [2 + TagSize]byte
}

// b should have at least TagSize remaining bytes
func (w *EncryptWriter) Write(b []byte) (n int, err error) {
	var buffers net.Buffers = make([][]byte, 0, 3)
	if w.aead == nil {
		salt := make([]byte, KeySize)
		if _, err = rand.Read(salt); err != nil {
			slog.Error("generating salt", "error", err)
			return
		}

		if w.aead, err = sessinoKey(salt); err != nil {
			slog.Error("deriving session key", "error", err)
			return
		}
		push(&buffers, salt)
	}

	// encrypt header
	binary.BigEndian.PutUint16(w.header[:], uint16(len(b)))
	push(&buffers, w.aead.Seal(w.header[:0], w.nonce[:], w.header[:2], nil))
	w.nonce.increase()

	// encryt payload
	push(&buffers, w.aead.Seal(b[:0], w.nonce[:], b, nil))
	w.nonce.increase()
	for len(buffers) > 0 {
		if _, err = buffers.WriteTo(w.conn); err != nil {
			return
		}
	}
	n = len(b)
	return
}

func DecryptIter(conn net.Conn) iter.Seq2[[]byte, error] {
	return func(yield func([]byte, error) bool) {
		var (
			n          int
			err        error
			aead       cipher.AEAD
			nonce      Nonce
			buff       = make([]byte, FourK)
			ciphertext []byte
		)

		if n, err = io.ReadAtLeast(conn, buff, KeySize); err != nil {
			yield(nil, err)
			return
		}

		if aead, err = sessinoKey(buff[:KeySize]); err != nil {
			yield(nil, err)
			return
		}

		ciphertext = buff[KeySize:n]

		// ensure ciphertext has at least n bytes
		var ensure = func(n int) (err error) {
			if len(ciphertext) >= n {
				return
			}

			// create a bigger buffer of size n round to 4k
			if cap(buff) < n {
				buff = make([]byte, (n+FourK-1)/FourK*FourK)
			}

			// shift ciphertext to head of buff
			if cap(ciphertext) < n {
				ciphertext = buff[:copy(buff, ciphertext)]
			}

			m, err := io.ReadAtLeast(conn, rest(ciphertext), n-len(ciphertext))
			grow(&ciphertext, m)
			return
		}

		for {
			if err = ensure(2 + TagSize); err != nil {
				yield(nil, err)
				break
			}

			if _, err = aead.Open(ciphertext[:0], nonce[:], ciphertext[:2+TagSize], nil); err != nil {
				yield(nil, err)
				break
			}

			length := int(binary.BigEndian.Uint16(ciphertext))
			nonce.increase()
			consume(&ciphertext, 2+TagSize)

			if err = ensure(length + TagSize); err != nil {
				yield(nil, err)
				break
			}

			if !yield(aead.Open(ciphertext[:0], nonce[:], ciphertext[:length+TagSize], nil)) {
				break
			}

			nonce.increase()
			consume(&ciphertext, length+TagSize)
		}
	}
}

const TIMEOUT = 30 * time.Second

// relay between plain conn and encrypted conn
func Relay(plain net.Conn, encrypted net.Conn, enc io.Writer, dec iter.Seq2[[]byte, error]) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		encrypted.SetReadDeadline(time.Now().Add(TIMEOUT))
		for text, err := range dec {
			if err != nil {
				plain.SetDeadline(time.Now())
				break
			}
			if err = WriteAll(plain, text); err != nil {
				break
			}
			encrypted.SetReadDeadline(time.Now().Add(TIMEOUT))
		}
		wg.Done()
	}()

	go func() {
		buff := make([]byte, FourK)
		for {
			plain.SetReadDeadline(time.Now().Add(TIMEOUT))
			n, err := plain.Read(buff[:FourK-TagSize])
			if err != nil {
				encrypted.SetDeadline(time.Now())
				break
			}
			if err = WriteAll(enc, buff[:n]); err != nil {
				break
			}
		}
		wg.Done()
	}()

	wg.Wait()
	plain.Close()
	encrypted.Close()
}

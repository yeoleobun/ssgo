package ssgo

import (
	"encoding/binary"
	"errors"
	"io"
	"iter"
	"log/slog"
	"net"
	"os"
	"strconv"
)

const FourK int = 4096

func init() {
	if logLevelStr := os.Getenv("LOG_LEVEL"); len(logLevelStr) > 0 {
		switch logLevelStr {
		case "DEBUG":
			slog.SetLogLoggerLevel(slog.LevelDebug)
		case "INFO":
			slog.SetLogLoggerLevel(slog.LevelInfo)
		case "WARN":
			slog.SetLogLoggerLevel(slog.LevelWarn)
		case "ERROR":
			slog.SetLogLoggerLevel(slog.LevelError)
		}
	}
}

func rest[T any](bytes []T) []T {
	return bytes[len(bytes):cap(bytes)]
}

func grow[T any](bytes *[]T, n int) {
	*bytes = (*bytes)[:len(*bytes)+n]
}

func consume[T any](bytes *[]T, n int) {
	*bytes = (*bytes)[n:]
}

func push[T any, S ~[]T](slice *S, ts ...T) {
	*slice = append(*slice, ts...)
}

// func drain[T any](ch chan T) {
// 	for _, ok := <-ch; ok; _, ok = <-ch {
// 	}
// }

func WriteAll(w io.Writer, buff []byte) (err error) {
	for len(buff) > 0 {
		var n int
		if n, err = w.Write(buff); err != nil {
			return
		}
		buff = buff[n:]
	}
	return
}

var ErrNotEnough = errors.New("not enough")

func ParseAddress(bytes []byte) (addr string, rest []byte, err error) {
	err = ErrNotEnough
	if len(bytes) < 7 {
		return
	}
	switch bytes[0] {
	case 1:
		var ip net.IP = bytes[1:5]
		addr = ip.String()
		consume(&bytes, 5)
	case 3:
		n := int(bytes[1])
		if len(bytes) < n+4 {
			return
		}
		addr = string(bytes[2 : 2+n])
		consume(&bytes, n+2)
	case 4:
		if len(bytes) < 19 {
			return
		}
		var ip net.IP = bytes[1:17]
		addr = "[" + ip.String() + "]"
		consume(&bytes, 17)
	}
	err = nil
	port := int(binary.BigEndian.Uint16(bytes[:2]))
	addr += ":" + strconv.Itoa(port)
	rest = bytes[2:]
	return
}

func Next[K any, V any](seq *iter.Seq2[K, V]) (K, V) {
	next, stop := iter.Pull2(*seq)
	// shoud be ok
	k, v, _ := next()
	*seq = func(yield func(K, V) bool) {
		for k, v, ok := next(); ok && yield(k, v); k, v, ok = next() {
		}
		stop()
	}
	return k, v
}

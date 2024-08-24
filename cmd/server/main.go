package main

import (
	"flag"
	"fmt"
	"l1zz/ssgo"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strconv"
	"time"
)

func main() {

	address := flag.String("address", "0.0.0.0", "address")
	port := flag.Int("port", 0, "port")
	method := flag.String("method", "", "encryption method, [aes-128-gcm, aes-256-gcm, chacha20-poly1305]")
	password := flag.String("password", "", "password")

	flag.Parse()

	if *port*len(*password)*len(*method) == 0 {
		fmt.Println("port, method and pasword are required")
		flag.Usage()
		os.Exit(1)
	}

	ssgo.SetCipher(*method, *password)

	addr := *address + ":" + strconv.Itoa(*port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		slog.Error("listening", "err", err)
		return
	}

	slog.Info("listening on", "addr", listener.Addr().String())

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				slog.Error("accept", "error", err)
				break
			}
			go process(conn)
		}
	}()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	<-c
	listener.Close()
}

func process(conn net.Conn) {
	enc, dec := ssgo.Split(conn)

	bytes, err := ssgo.Next(&dec)
	if err != nil {
		slog.Error("first request", "cause", err)
		return
	}

	addr, bytes, err := ssgo.ParseAddress(bytes)
	if err != nil {
		slog.Error("parse address", "cause", err)
		return
	}

	slog.Debug("connect", "addr", addr)

	remote, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		slog.Error("unreachable", "addr", addr)
		return
	}

	if err := ssgo.WriteAll(remote, bytes); err != nil {
		return
	}

	ssgo.Relay(remote, conn, enc, dec)
}

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

	server := flag.String("server", "", "remote address")
	serverPort := flag.Int("server-port", 0, "remote listening port")
	localAddress := flag.String("local-address", "localhost", "local address")
	localPort := flag.Int("local-port", 1080, "local listening port")
	method := flag.String("method", "", "encryption method, in [aes-128-gcm, aes-256-gcm, chacha20-poly1305]")
	password := flag.String("password", "", "password")

	flag.Parse()

	if len(*server)**serverPort*len(*method)*len(*password) == 0 {
		fmt.Println("server,server-port, pasword and method are required")
		flag.Usage()
		os.Exit(1)
	}

	ssgo.SetCipher(*method, *password)

	serverAddr = *server + ":" + strconv.Itoa(*serverPort)
	localAddr := *localAddress + ":" + strconv.Itoa(*localPort)

	listener, err := net.Listen("tcp", localAddr)
	if err != nil {
		slog.Error("listening", "cause", err)
		os.Exit(1)
	}

	slog.Info("listening on", "addr", listener.Addr().String())

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				slog.Error("accept", "cause", err)
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

var NO_AUTHENTICATION = [2]byte{5, 0}
var serverAddr string

func process(client net.Conn) {
	var (
		m      int
		n      int
		err    error
		addr   string
		remote net.Conn
		buff   = make([]byte, ssgo.FourK)
	)

	// method selection
	if _, err = client.Read(buff); err != nil {
		return
	}

	if _, err = client.Write(NO_AUTHENTICATION[:]); err != nil {
		return
	}

	// request
	if n, err = client.Read(buff); err != nil {
		return
	}

	buff[1] = 0
	client.Write(buff[:n])

	// fill first request
	if m, err = client.Read(buff[n : len(buff)-ssgo.TagSize]); err != nil {
		return
	}

	if addr, _, err = ssgo.ParseAddress(buff[3:]); err != nil {
		slog.Error("parse address", "cause", err)
		return
	}

	slog.Debug("connect", "addr", addr)

	if remote, err = net.DialTimeout("tcp", serverAddr, time.Second); err != nil {
		slog.Error("connect", "cause", err)
		return
	}

	enc, dec := ssgo.Split(remote)

	if err = ssgo.WriteAll(enc, buff[3:m+n]); err != nil {
		return
	}

	buff = nil
	ssgo.Relay(client, remote, enc, dec)
}

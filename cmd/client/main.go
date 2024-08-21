package main

import (
	"l1zz/ssgo"
	"log"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"sync"
)

func main() {
	slog.SetLogLoggerLevel(slog.LevelDebug)
	listener, err := net.Listen("tcp", "localhost:1080")
	if err != nil {
		log.Fatal(err)
	}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				log.Fatal(err)
			}
			go process(conn)
		}
	}()
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	<-c
}

var NO_AUTHENTICATION = [2]byte{5, 0}

func process(client net.Conn) {
	defer client.Close()
	remote, err := net.Dial("tcp", "localhost:8388")
	if err != nil {
		return
	}
	defer remote.Close()
	// wrapper := ssgo.NewConnWrapper(remote)
	enc, dec := ssgo.Split(remote)

	buff := make([]byte, 4096)

	// method selection
	_, err = client.Read(buff)
	if err != nil {
		return
	}
	_, err = client.Write(NO_AUTHENTICATION[:])
	if err != nil {
		return
	}

	// request
	n, err := client.Read(buff)
	if err != nil {
		return
	}

	buff[1] = 0
	client.Write(buff[:n])

	// fill first request
	m, err := client.Read(buff[n : cap(buff)-16])
	if err != nil {
		return
	}

	_, err = enc.Write(buff[3 : m+n])
	if err != nil {
		return
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		for text, err := range dec {
			if err != nil {
				log.Println(err)
				break
			}
			err := ssgo.WriteAll(client, text)
			if err != nil {
				log.Println(err)
				break
			}
		}
		wg.Done()
	}()
	go func() {
		for {
			n, err := client.Read(buff[:4096-16])
			if err != nil {
				log.Println(err)
				break
			}
			err = ssgo.WriteAll(enc, buff[:n])
			if err != nil {
				log.Println(err)
				break
			}
		}
		wg.Done()
	}()
	wg.Wait()
}

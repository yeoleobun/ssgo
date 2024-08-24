.PHONY: client server

all: client server

client:
	go build -o bin/client l1zz/ssgo/cmd/client

server:
	go build -o bin/server l1zz/ssgo/cmd/server

clean:
	rm -rf bin/

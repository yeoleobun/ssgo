# ssgo

shadowsocks of go impletation

## Supoorted features:
- [x] TCP
- [ ] UDP

## Supported ciphers (AEAD only):
- [x] aes-128-gcm
- [x] aes-256-gcm
- [x] chacha20-poly1305

Build
-----

    $ make all
    
Usage
-----
### client

    $ bin/client -server <SERVER> -server-port <SERVER_PORT> -local-port <LOCAL_PORT> -password <PASSWORD> -method <METHOD>

`bin/client -help` for detail

### server

    $ bin/server -port <PORT> -password <PASSWORD> -method <METHOD>

`bin/server -help` for detail

Example
-------


    $ bin/client -server 127.0.0.1 -server-port 8388 -local-port 1080 -password "barfoo!" -method chacha20-poly1305

    $ bin/server -port 8388 -password "barfoo!" -method chacha20-poly1305      





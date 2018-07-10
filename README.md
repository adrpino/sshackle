# sshackle

(pronounced like [_shackle_](https://en.wikipedia.org/wiki/Shackle)). 

Ssh bruteforcer implemented in Go, with tunelling requests through Tor. It attempts to connect to a list of IP addresses with a list of passwords, trying all combinations. These requests are made concurrently `:3`.

It only works for Password Authentication.

To run, you'll need to have [Tor](https://www.torproject.org/download/download) installed running on your local network.

### Installation
```
go get github.com/adrpino/sshackle
```

### Usage
```
sshackle --pass passfile --ip ipfile
```

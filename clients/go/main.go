// PQCC Go client (crypto/tls). Usage: version | <variant> <mode> <host> <port>
// Trust comes only from the variant's root CA; hostname verification is on.
package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"time"
)

func fail(stage string, err error) {
	fmt.Fprintf(os.Stderr, "stage failed: %s\n%v\n", stage, err)
	os.Exit(1)
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == "version" {
		fmt.Println("Go", runtime.Version())
		return
	}
	variant, mode, host, port := os.Args[1], os.Args[2], os.Args[3], os.Args[4]
	dir := "/certs/out/" + variant + "/"

	rootPEM, err := os.ReadFile(dir + "root.crt")
	if err != nil {
		fail("read root certificate", err)
	}
	block, _ := pem.Decode(rootPEM)
	root, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		fail("parse root certificate", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	cfg := &tls.Config{RootCAs: pool, ServerName: host}

	if mode == "mtls" {
		pair, err := tls.LoadX509KeyPair(dir+"client-chain.crt", dir+"client.key")
		if err != nil {
			fail("load client certificate/key", err)
		}
		cfg.Certificates = []tls.Certificate{pair}
	}

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 15 * time.Second}, "tcp", net.JoinHostPort(host, port), cfg)
	if err != nil {
		fail("handshake", err)
	}
	defer conn.Close()
	cs := conn.ConnectionState()
	fmt.Println("Protocol version:", tls.VersionName(cs.Version))
	fmt.Println("Negotiated group:", cs.CurveID)
	fmt.Println("Cipher:", tls.CipherSuiteName(cs.CipherSuite))
	fmt.Println("Peer signature algorithm:", cs.PeerCertificates[0].SignatureAlgorithm)

	conn.SetDeadline(time.Now().Add(15 * time.Second))
	fmt.Fprint(conn, "GET / HTTP/1.0\r\n\r\n")
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		fail("HTTP exchange", err)
	}
	fmt.Print("Response: ", line)
	if !strings.HasPrefix(line, "HTTP/1.0 200") {
		fail("HTTP exchange", fmt.Errorf("unexpected response: %q", line))
	}
}

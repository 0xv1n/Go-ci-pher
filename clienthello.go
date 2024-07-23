package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"time"

	utls "github.com/refraction-networking/utls"
)

// List of cipher suites supported by the Go TLS implementation
// https://github.com/golang/go/blob/master/src/crypto/tls/cipher_suites.go
var goCipherSuites = []uint16{
	utls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	utls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
	utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	utls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
	utls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	utls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
	utls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	utls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	utls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	utls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	utls.TLS_RSA_WITH_AES_256_GCM_SHA384,
	utls.TLS_RSA_WITH_AES_128_CBC_SHA256,
	utls.TLS_RSA_WITH_AES_128_CBC_SHA,
	utls.TLS_RSA_WITH_AES_256_CBC_SHA,
	utls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
	utls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
	utls.TLS_RSA_WITH_RC4_128_SHA,
	utls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
	utls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
}

func main() {
	if len(os.Args) != 2 {
		fmt.Printf("Usage: %s <domain>\n", os.Args[0])
		return
	}

	domain := os.Args[1]

	fmt.Printf("Probing %s for supported cipher suites...\n", domain)

	supportedCipherSuites := make([]uint16, 0)

	for _, suite := range goCipherSuites {
		if probeCipherSuite(domain, suite) {
			supportedCipherSuites = append(supportedCipherSuites, suite)
		}
	}

	if equalCipherSuites(supportedCipherSuites, goCipherSuites) {
		fmt.Println("The server is likely a Go web server.")
	} else {
		fmt.Println("The server is not a Go web server.")
	}

	for _, suite := range supportedCipherSuites {
		fmt.Printf("Supported Cipher Suite: %s\n", tls.CipherSuiteName(suite))
	}
}

func probeCipherSuite(domain string, suite uint16) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:443", domain), 10*time.Second)
	if err != nil {
		fmt.Printf("Failed to connect: %v\n", err)
		return false
	}
	defer conn.Close()

	config := &utls.Config{
		InsecureSkipVerify: true,
		ServerName:         domain,
	}

	clientHelloSpec := utls.ClientHelloSpec{
		CipherSuites: []uint16{suite},
		Extensions: []utls.TLSExtension{
			&utls.SNIExtension{ServerName: domain},
		},
	}

	uconn := utls.UClient(conn, config, utls.HelloCustom)
	uconn.ApplyPreset(&clientHelloSpec)

	err = uconn.Handshake()
	if err != nil {
		return false
	}

	return true
}

func equalCipherSuites(a, b []uint16) bool {
	if len(a) != len(b) {
		return false
	}

	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}

	return true
}

package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"time"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Printf("Usage: %s <domain>\n", os.Args[0])
		return
	}

	domain := os.Args[1]
	fmt.Printf("Probing %s for supported cipher suites...\n", domain)

	cipherSuites := []uint16{
		tls.TLS_RSA_WITH_RC4_128_SHA,
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
		tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_AES_128_GCM_SHA256,
		tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_CHACHA20_POLY1305_SHA256,
	}

	for _, suite := range cipherSuites {
		supported := probeCipherSuite(domain, suite)
		if supported {
			fmt.Printf("Supported Cipher Suite: %s\n", tls.CipherSuiteName(suite))
		}
	}
}

func probeCipherSuite(domain string, suite uint16) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:443", domain), 10*time.Second)
	if err != nil {
		fmt.Printf("Failed to connect: %v\n", err)
		return false
	}
	defer conn.Close()

	config := &tls.Config{
		CipherSuites:       []uint16{suite},
		InsecureSkipVerify: true, // Skip verification for probing purposes
	}

	tlsConn := tls.Client(conn, config)
	err = tlsConn.Handshake()
	if err != nil {
		return false
	}
	defer tlsConn.Close()
  
	return true
}

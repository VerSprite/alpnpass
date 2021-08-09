package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strconv"
	"sync"
)

// Configuration is the config for the ALPN MITM proxy.
type Configuration struct {

	// Port configuration.
	InputPort       string // Proxy will listen on this port in SSL...
	InterceptorPort string // ...then forward to this port in plain...
	ReturnPort      string // ...then expect a new connection on this port in plain...
	OutputPort      string // ...then connect to this port in SSL.

	// IP address configuration.
	InputBindIP          string // Bind address.
	InterceptorConnectIP string // Connect address.
	ReturnBindIP         string // Bind address.
	OutputConnectIP      string // Connect address.

	// TLS settings.
	Hostname   string // Hostname for SSL verification only.
	MinVersion string // Minimum protocol version allowed.
	MaxVersion string // Maximum protocol version allowed.

	// SSL configuration.
	CACert     string   // CA certificate.
	ServerCert string   // Server SSL certificate.
	ServerKey  string   // Server SSL private key.
	ClientCert string   // Client SSL certificate (optional).
	ClientKey  string   // Client SSL private key (optional).
	ALPN       []string // ALPN protocols to announce.
	Ciphers    []string // Supported cipher suite IDs.
}

// Default settings.
var settings = Configuration{

	// Default ports.
	InputPort:       "1111",
	InterceptorPort: "2222",
	ReturnPort:      "3333",
	OutputPort:      "4444",

	// Defaults to running everything locally.
	InputBindIP:          "127.0.0.1",
	InterceptorConnectIP: "127.0.0.1",
	ReturnBindIP:         "127.0.0.1",
	OutputConnectIP:      "127.0.0.1",

	// TLS settings.
	Hostname:   "127.0.0.1",
	MinVersion: "SSL30",
	MaxVersion: "TLS13",

	// You must create these files yourself.
	CACert:     "ca.crt",
	ServerCert: "server.crt",
	ServerKey:  "server.key",
	ClientCert: "server.crt",
	ClientKey:  "server.key",

	// ALPN protocols list.
	ALPN: []string{

		// HTTP/2 will be the most common case.
		"h2",

		// Official IANA list:
		// https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids
		"h2c",
		"http/1.1",
		"http/1.0",
		"spdy/3",
		"spdy/2",
		"spdy/1",
		"stun.turn",
		"stun.nat-discovery",
		"webrtc",
		"c-webrtc",
		"ftp",
		"imap",
		"pop3",
		"managesieve",
		"coap",
		"xmpp-client",
		"xmpp-server",
		"acme-tls/1",
		"mqtt",
		"dot",
		"ntske/1",
		"sunrpc",

		// Some additional ones from Vulners:
		// https://vulners.com/nessus/ALPN_PROTOCOL_ENUMERATION.NASL
		"spdy/3.1",
		"h2-14",
		"h2-15",
		"h2-16",
	},
}

// Get all supported ciphersuites by default, even the insecure ones.
// In fact, get the insecure ones first... >:)
func getAllCipherSuites() []string {
	var names []string
	for _, cipher := range tls.InsecureCipherSuites() {
		names = append(names, cipher.Name)
	}
	for _, cipher := range tls.CipherSuites() {
		names = append(names, cipher.Name)
	}
	return names
}

// Fetch a ciphersuite ID given its name.
func getCipherSuiteID(name string) uint16 {
	for _, cipher := range tls.CipherSuites() {
		if name == cipher.Name {
			return cipher.ID
		}
	}
	for _, cipher := range tls.InsecureCipherSuites() {
		if name == cipher.Name {
			return cipher.ID
		}
	}
	return 0
}

// Convert our list of cipher name strings into numeric IDs we can use.
func convertCipherSuiteNamesToIDs(ciphers []string) []uint16 {
	var ids []uint16
	for _, name := range ciphers {
		id := getCipherSuiteID(name)
		if id != 0 {
			ids = append(ids, id)
		}
	}
	return ids
}

// Program entry point.
func main() {

	// Fill in the default list of ciphers.
	settings.Ciphers = getAllCipherSuites()

	// Check the command line arguments.
	if len(os.Args) > 2 {
		fmt.Fprintf(os.Stderr, "usage: %s [alpnpass.json]\n", os.Args[0])
		return
	}

	// Useful for debugging.
	//log.SetFlags(log.Lshortfile)

	// User can optionally provide a different config file.
	filename := "alpnpass.json"
	if len(os.Args) == 2 {
		filename = os.Args[1]
		log.Println("[main] Reading configuration file:", filename)
	}

	// Load the configuration. Use default values if file is missing.
	_, err := os.Stat(filename)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("[main] Configuration file %s not found, using default values\n", filename)
		} else {
			log.Fatal(err)
		}
	} else {
		file, err := os.Open(filename)
		if err != nil {
			log.Fatal(err)
		}
		defer file.Close()
		decoder := json.NewDecoder(file)
		err = decoder.Decode(&settings)
		if err != nil {
			log.Fatal(err)
		}
	}

	// Show the resulting configuration after merging the defaults.
	prettyJSON, err := json.MarshalIndent(settings, "", "\t")
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("[main] Using configuration:\n%s\n", prettyJSON)

	// Validate the configuration values.
	i, err := strconv.Atoi(settings.InputPort)
	if err != nil || i <= 0 || i > 65535 {
		log.Fatalf("[main] Fatal: Bad value for InputPort: %v\n", settings.InputPort)
	}
	i, err = strconv.Atoi(settings.InterceptorPort)
	if err != nil || i <= 0 || i > 65535 {
		log.Fatalf("[main] Fatal: Bad value for InterceptorPort: %v\n", settings.InterceptorPort)
	}
	i, err = strconv.Atoi(settings.ReturnPort)
	if err != nil || i <= 0 || i > 65535 {
		log.Fatalf("[main] Fatal: Bad value for ReturnPort: %v\n", settings.ReturnPort)
	}
	i, err = strconv.Atoi(settings.OutputPort)
	if err != nil || i <= 0 || i > 65535 {
		log.Fatalf("[main] Fatal: Bad value for OutputPort: %v\n", settings.OutputPort)
	}
	if settings.InputBindIP == "" {
		log.Fatal("[main] Fatal: missing InputBindIP\n")
	}
	if settings.InterceptorConnectIP == "" {
		log.Fatal("[main] Fatal: missing InterceptorConnectIP\n")
	}
	if settings.ReturnBindIP == "" {
		log.Fatal("[main] Fatal: missing ReturnBindIP\n")
	}
	if settings.OutputConnectIP == "" {
		log.Fatal("[main] Fatal: missing OutputConnectIP\n")
	}
	if net.ParseIP(settings.InputBindIP) == nil {
		log.Printf("[main] Warning: invalid IP address for InputBindIP: %v\n", settings.InputBindIP)
	}
	if net.ParseIP(settings.ReturnBindIP) == nil {
		log.Printf("[main] Warning: invalid IP address for ReturnBindIP: %v\n", settings.ReturnBindIP)
	}
	if settings.Hostname == "" {
		log.Fatal("[main] Fatal: missing Hostname\n")
	}
	switch settings.MinVersion {
	case "SSL30":
	case "TLS10":
	case "TLS11":
	case "TLS12":
	case "TLS13":
	default:
		log.Fatalf("[main] Fatal: invalid MinVersion: %v\n", settings.MinVersion)
	}
	switch settings.MaxVersion {
	case "SSL30":
	case "TLS10":
	case "TLS11":
	case "TLS12":
	case "TLS13":
	default:
		log.Fatalf("[main] Fatal: invalid MaxVersion: %v\n", settings.MaxVersion)
	}
	_, err = os.Stat(settings.CACert)
	if err != nil {
		log.Fatalf("[main] Fatal: cannot find CA certificate: %v\n", settings.CACert)
	}
	_, err = os.Stat(settings.ServerCert)
	if err != nil {
		log.Fatalf("[main] Fatal: cannot find SSL certificate: %v\n", settings.ServerCert)
	}
	_, err = os.Stat(settings.ServerKey)
	if err != nil {
		log.Fatalf("[main] Fatal: cannot find SSL private key: %v\n", settings.ServerKey)
	}
	if settings.ClientCert != "" {
		_, err = os.Stat(settings.ClientCert)
		if err != nil {
			settings.ClientCert = ""
			log.Printf("[main] Warning: cannot find SSL certificate: %v\n", settings.ClientCert)
		}
	}
	if settings.ClientKey != "" {
		_, err = os.Stat(settings.ClientKey)
		if err != nil {
			settings.ClientKey = ""
			log.Printf("[main] Warning: cannot find SSL private key: %v\n", settings.ClientKey)
		}
	}
	if len(settings.ALPN) == 0 {
		log.Println("[main] Warning: empty ALPN protocol list")
	}
	if len(settings.Ciphers) == 0 {
		log.Println("[main] Warning: empty ciphersuite list")
	}
	for _, cipher := range settings.Ciphers {
		if getCipherSuiteID(cipher) == 0 {
			log.Fatalf("[main] Fatal: invalid ciphersuite name: %v\n", cipher)
		}
	}

	// Get the CA certificate.
	ca, err := ioutil.ReadFile(settings.CACert)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
	block, _ := pem.Decode(ca)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
	certPool := x509.NewCertPool()
	certPool.AddCert(cert)

	// Get the SSL certificate and private key.
	cer, err := tls.LoadX509KeyPair(settings.ServerCert, settings.ServerKey)
	if err != nil {
		log.Println(err)
		return
	}

	// Get the values of MinVersion and MaxVersion.
	var MinVersion uint16
	switch settings.MinVersion {
	case "SSL30":
		MinVersion = tls.VersionSSL30
	case "TLS10":
		MinVersion = tls.VersionTLS10
	case "TLS11":
		MinVersion = tls.VersionTLS11
	case "TLS12":
		MinVersion = tls.VersionTLS12
	case "TLS13":
		MinVersion = tls.VersionTLS13
	default:
		MinVersion = tls.VersionSSL30
	}
	var MaxVersion uint16
	switch settings.MaxVersion {
	case "SSL30":
		MaxVersion = tls.VersionSSL30
	case "TLS10":
		MaxVersion = tls.VersionTLS10
	case "TLS11":
		MaxVersion = tls.VersionTLS11
	case "TLS12":
		MaxVersion = tls.VersionTLS12
	case "TLS13":
		MaxVersion = tls.VersionTLS13
	default:
		MaxVersion = tls.VersionTLS13
	}

	// Setup the TLS configuration.
	config := &tls.Config{
		Certificates: []tls.Certificate{cer},
		RootCAs:      certPool,
		ServerName:   settings.Hostname,
		ClientAuth:   tls.NoClientCert,
		ClientCAs:    certPool,
		NextProtos:   settings.ALPN,
		CipherSuites: convertCipherSuiteNamesToIDs(settings.Ciphers),
		MinVersion:   MinVersion,
		MaxVersion:   MaxVersion,
	}

	// Listen on the input port.
	ln, err := net.Listen("tcp", settings.InputBindIP+":"+settings.InputPort)
	if err != nil {
		log.Println(err)
		return
	}
	defer ln.Close()

	// Accept new connections on the input port.
	// We can only accept one connection at a time,
	// as there is no way to track multiple connections
	// after they go through an external proxy.
	for {
		log.Println("[main] Waiting for incoming connections...")
		conn, err := ln.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		tlsConn := tls.Server(conn, config)
		handleNewConnection(tlsConn)
	}
}

// This synchronous function handles incoming connections
// on the input port and sets up the entire proxy chain.
func handleNewConnection(conn *tls.Conn) {
	defer conn.Close()
	log.Println("[main] Received connection from: ", conn.RemoteAddr())

	// Perform the TLs handshake.
	err := conn.Handshake()
	if err != nil {
		log.Println(err)
		return
	}

	// Get the ALPN negotiated protocol, if any.
	// We will preserve this into the second SSL connection.
	state := conn.ConnectionState()
	log.Printf("[main] Negotiated ALPN protocol: %v\n", state.NegotiatedProtocol)

	// Listen on the return port from the external TCP proxy.
	ln, err := net.Listen("tcp", settings.ReturnBindIP+":"+settings.ReturnPort)
	if err != nil {
		log.Println(err)
		return
	}
	defer ln.Close()

	// Connect to the external TCP proxy.
	clientConn, err := net.Dial("tcp", settings.InterceptorConnectIP+":"+settings.InterceptorPort)
	if err != nil {
		log.Printf("[main] Error: %s\n", err)
		return
	}
	defer clientConn.Close()
	log.Printf("[main] Connected to TCP proxy at: %s:%s\n", settings.InterceptorConnectIP, settings.InterceptorPort)

	// Accept return connections from the TCP proxy.
	retconn, err := ln.Accept()
	if err != nil {
		log.Fatal(err)
	}
	log.Println("[main] Received return connection from TCP proxy at: ", retconn.RemoteAddr())

	// Load the CA certificate.
	ca, err := ioutil.ReadFile(settings.CACert)
	block, _ := pem.Decode(ca)
	cacert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Println(err)
		return
	}
	certPool := x509.NewCertPool()
	certPool.AddCert(cacert)

	// Load the SSL certificate and private key.
	certificates := []tls.Certificate{}
	if settings.ClientCert != "" && settings.ClientKey != "" {
		cert, err := tls.LoadX509KeyPair(settings.ClientCert, settings.ClientKey)
		if err != nil {
			log.Printf("[main] Error: %s\n", err)
			return
		}
		certificates = []tls.Certificate{cert}
	}

	// Setup the TLS configuration for connecting to the target.
	// Note that this configuration is deliberately insecure!
	config := tls.Config{
		Certificates:       certificates,
		InsecureSkipVerify: true,
		RootCAs:            certPool,
		NextProtos:         []string{state.NegotiatedProtocol},
		CipherSuites:       convertCipherSuiteNamesToIDs(getAllCipherSuites()),
	}

	// Connect to the SSL capable target, preserving the ALPN negotiated protocol.
	retClientConn, err := tls.Dial("tcp", settings.OutputConnectIP+":"+settings.OutputPort, &config)
	if err != nil {
		log.Printf("[main] Error: %s\n", err)
		return
	}
	defer retClientConn.Close()
	log.Printf("[main] Connected to target at: %s:%s\n", settings.OutputConnectIP, settings.OutputPort)

	// Now we can pipe all of the traffic through the plain TCP proxy.
	// When one of the pipe goroutines fails, we assume this means the
	// TCP connection was broken in at least one place, so we destroy the
	// whole chain. There should be a more elegant way but this will do.
	ctx, cancel := context.WithCancel(context.Background())
	cnd := sync.NewCond(&sync.Mutex{})
	go pipe(ctx, cnd, conn, clientConn, "client -> us")
	go pipe(ctx, cnd, clientConn, conn, "us -> interceptor")
	go pipe(ctx, cnd, retconn, retClientConn, "interceptor -> us again")
	go pipe(ctx, cnd, retClientConn, retconn, "us again -> server")
	cnd.L.Lock()
	cnd.Wait()
	cnd.L.Unlock()
	cancel()
}

// This goroutine pipes data from "src" to "dst".
func pipe(ctx context.Context, cnd *sync.Cond, src, dst io.ReadWriter, tag string) {

	// Signal our parent when we're done.
	defer cnd.Signal()

	// 64k data buffer.
	buff := make([]byte, 0xffff)

	// Loop until we reach an error or we are canceled.
	for {
		select {

		// Cancel signal received.
		case <-ctx.Done():
			return

		// Keep working!
		default:

			// Read from "src" into the buffer.
			n, err := src.Read(buff)
			if err != nil {
				log.Printf("[%s] Read failed '%s'\n", tag, err)
				return
			}
			log.Printf("[%s] Read %d bytes\n", tag, n)
			b := buff[:n]

			// Write from the buffer into "dst".
			n, err = dst.Write(b)
			if err != nil {
				log.Printf("[%s] Write failed '%s'\n", tag, err)
				return
			}
			log.Printf("[%s] Wrote %d bytes\n", tag, n)
		}
	}
}

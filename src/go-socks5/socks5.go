package socks5

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"golang.org/x/net/context"
	"sync/atomic"
)

const (
	socks5Version = uint8(5)
)

// Config is used to setup and configure a Server
type Config struct {
	// AuthMethods can be provided to implement custom authentication
	// By default, "auth-less" mode is enabled.
	// For password-based auth use UserPassAuthenticator.
	AuthMethods []Authenticator

	// If provided, username/password authentication is enabled,
	// by appending a UserPassAuthenticator to AuthMethods. If not provided,
	// and AUthMethods is nil, then "auth-less" mode is enabled.
	Credentials CredentialStore

	// Resolver can be provided to do custom name resolution.
	// Defaults to DNSResolver if not provided.
	Resolver NameResolver

	// Rules is provided to enable custom logic around permitting
	// various commands. If not provided, PermitAll is used.
	Rules RuleSet

	// Rewriter can be used to transparently rewrite addresses.
	// This is invoked before the RuleSet is invoked.
	// Defaults to NoRewrite.
	Rewriter AddressRewriter

	// BindIP is used for bind or udp associate
	BindIP net.IP

	// Logger can be used to provide a custom log target.
	// Defaults to stdout.
	Logger *log.Logger

	// AccessLogger can be used to provide a custom access log target.
	// Defaults to stdout.
	AccessLogger *log.Logger

	// ErrorLogger can be used to provide a custom error log target.
	// Defaults to stdout.
	ErrorLogger *log.Logger

	// Optional function for dialing out
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

// ConnWrapper is a wrapper around a net.Conn that provides a way to log read/write bytes
type ConnWrapper struct {
	net.Conn
	ReadBytes int64
	WriteBytes int64
}

// Read reads data from the connection
func (c *ConnWrapper) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	// c.readBytes += int64(n) is not atomic
	atomic.AddInt64(&c.ReadBytes, int64(n))
	return n, err
}

// Write writes data to the connection
func (c *ConnWrapper) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	// c.writeBytes += int64(n) is not atomic
	atomic.AddInt64(&c.WriteBytes, int64(n))
	return n, err
}

// Server is reponsible for accepting connections and handling
// the details of the SOCKS5 protocol
type Server struct {
	config      *Config
	authMethods map[uint8]Authenticator
}

// New creates a new Server and potentially returns an error
func New(conf *Config) (*Server, error) {
	// Ensure we have at least one authentication method enabled
	if len(conf.AuthMethods) == 0 {
		if conf.Credentials != nil {
			conf.AuthMethods = []Authenticator{&UserPassAuthenticator{conf.Credentials}}
		} else {
			conf.AuthMethods = []Authenticator{&NoAuthAuthenticator{}}
		}
	}

	// Ensure we have a DNS resolver
	if conf.Resolver == nil {
		conf.Resolver = DNSResolver{}
	}

	// Ensure we have a rule set
	if conf.Rules == nil {
		conf.Rules = PermitAll()
	}

	// Ensure we have a log target
	if conf.Logger == nil {
		conf.Logger = log.New(os.Stdout, "", log.LstdFlags)
	}

	server := &Server{
		config: conf,
	}

	server.authMethods = make(map[uint8]Authenticator)

	for _, a := range conf.AuthMethods {
		server.authMethods[a.GetCode()] = a
	}

	return server, nil
}

// ListenAndServe is used to create a listener and serve on it
func (s *Server) ListenAndServe(network, addr string) error {
	l, err := net.Listen(network, addr)
	if err != nil {
		return err
	}
	return s.Serve(l)
}

// Serve is used to serve connections from a listener
func (s *Server) Serve(l net.Listener) error {
	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		go s.ServeConn(conn)
	}
	return nil
}

// ServeConn is used to serve a single connection.
func (s *Server) ServeConn(conn net.Conn) error {
	defer conn.Close()

	// Wrap the connection to log read/write bytes
	wrappedConn := &ConnWrapper{Conn: conn}

	remoteAddr, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return fmt.Errorf("Invalid remote address type: %T", conn.RemoteAddr())
	}
	bufConn := bufio.NewReader(wrappedConn)

	// Read the version byte
	version := []byte{0}
	if _, err := bufConn.Read(version); err != nil {
		s.config.Logger.Printf("[ERR] socks %s: Failed to get version byte: %v", remoteAddr, err)
		return err
	}

	// Ensure we are compatible
	if version[0] != socks5Version {
		err := fmt.Errorf("Unsupported SOCKS version: %v", version)
		s.config.Logger.Printf("[ERR] socks %s: %v", remoteAddr, err)
		return err
	}

	// Authenticate the connection
	authContext, err := s.authenticate(conn, bufConn)
	if err != nil {
		err = fmt.Errorf("Failed to authenticate: %w", err)
		s.config.Logger.Printf("[ERR] socks %s: %v", remoteAddr, err)
		return err
	}

	request, err := NewRequest(bufConn)
	if err != nil {
		if err == unrecognizedAddrType {
			if err := sendReply(wrappedConn, addrTypeNotSupported, nil); err != nil {
				return fmt.Errorf("Failed to send reply: %v", err)
			}
		}
		return fmt.Errorf("Failed to read destination address: %v", err)
	}
	request.AuthContext = authContext
	request.RemoteAddr = &AddrSpec{IP: remoteAddr.IP, Port: remoteAddr.Port}

	// Process the client request
	if err := s.handleRequest(request, wrappedConn); err != nil {
		err = fmt.Errorf("Failed to handle request: %v", err)
		s.config.Logger.Printf("[ERR] socks %s: %v", remoteAddr, err)
		return err
	}

	// log access
	// remoteAddr, identity, time_now, request, bytes_in, bytes_out
	s.config.AccessLogger.Printf("%s %s %s %s %d %d",
		remoteAddr,
		authContext.Payload["Username"],
		time.Now().Format(time.RFC3339),
		request.DestAddr.String(),
		wrappedConn.ReadBytes,
		wrappedConn.WriteBytes,
	)

	return nil
}

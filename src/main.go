package main

import (
	"context"
	"encoding/json"
	"flag"
	"io"
	"log"
	"net"
	"os"

	"github.com/armon/go-socks5"
	"github.com/kisom/netallow"
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
)

type ACL struct {
	*netallow.BasicNet
}

// ACL.Allow implements the socks5.RuleSet interface.
func (acl *ACL) Allow(ctx context.Context, request *socks5.Request) (context.Context, bool) {
	if request.Command != socks5.ConnectCommand {
		return ctx, false
	}
	if !acl.Permitted(request.DestAddr.IP) {
		return ctx, false
	}
	log.Printf("Accept: %q, %s, %s", request.AuthContext.Payload["Username"], request.RemoteAddr, request.DestAddr)
	return ctx, true
}

// ACL.String and ACL.Set implement the flag.Value interface.
func (acl *ACL) String() string {
	b, _ := json.Marshal(acl.BasicNet)
	return string(b)
}

// ACL.String and ACL.Set implement the flag.Value interface.
func (acl *ACL) Set(s string) error {
	r, w := io.Pipe()
	go json.NewEncoder(w).Encode(s)
	return json.NewDecoder(r).Decode(acl.BasicNet)
}

type RadiusCredentials struct {
	Server string
	Secret []byte
}

// RadiusCredentials.Valid implements the socks5.CredentialStore interface.
func (r *RadiusCredentials) Valid(username, password string) bool {
	packet := radius.New(radius.CodeAccessRequest, r.Secret)
	rfc2865.UserName_SetString(packet, username)
	rfc2865.UserPassword_SetString(packet, password)
	response, err := radius.Exchange(context.Background(), packet, r.Server)
	if err != nil {
		log.Printf("Radius error: %s\n", err)
		return false
	}
	return response.Code == radius.CodeAccessAccept
}

var (
	ListenAddr   string
	RadiusAddr   string
	RadiusSecret string
	ServerACL    = ACL{BasicNet: netallow.NewBasicNet()}
)

func init() {
	log.SetFlags(log.Flags() | log.Lshortfile)
	// Don't repeat timestamp if logging to systemd journal (v231+)
	if _, ok := os.LookupEnv("JOURNAL_STREAM"); ok {
		log.SetFlags(log.Flags() &^ (log.Ldate | log.Ltime))
	}

	ServerACL.Add(&net.IPNet{IP: net.ParseIP("192.0.2.0"), Mask: net.CIDRMask(24, 32)})
	ServerACL.Add(&net.IPNet{IP: net.ParseIP("198.51.100.0"), Mask: net.CIDRMask(24, 32)})
	ServerACL.Add(&net.IPNet{IP: net.ParseIP("203.0.113.0"), Mask: net.CIDRMask(24, 32)})
	ServerACL.Add(&net.IPNet{IP: net.ParseIP("2001:db8::"), Mask: net.CIDRMask(32, 128)})
}

func main() {
	flag.StringVar(&ListenAddr, "l", "127.0.0.1:1080", "listen address")
	flag.StringVar(&RadiusAddr, "r", "127.0.0.1:1812", "RADIUS server address")
	flag.StringVar(&RadiusSecret, "s", "", "RADIUS secret")
	flag.Var(&ServerACL, "a", "allowed IP addresses")
	flag.Parse()

	server, err := socks5.New(&socks5.Config{
		Credentials: &RadiusCredentials{
			Server: RadiusAddr,
			Secret: []byte(RadiusSecret),
		},
		Rules:  &ServerACL,
		Logger: log.Default(),
	})
	if err != nil {
		log.Fatalf("Error creating socks5 server: %s", err)
	}
	if err := server.ListenAndServe("tcp", ListenAddr); err != nil {
		log.Fatalf("Error starting socks5 server: %s", err)
	}
}

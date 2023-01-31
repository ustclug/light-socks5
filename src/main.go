package main

import (
	"context"
	"encoding/json"
	"io"
	"log"
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

func getEnv(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
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
}

func main() {
	ListenAddr = getEnv("GANTED_LISTEN", "127.0.0.1:6626")
	RadiusAddr = getEnv("RADIUS_SERVER", "127.0.0.1:1812")
	RadiusSecret = getEnv("RADIUS_SECRET", "")
	ServerACL.Set(getEnv("GANTED_ACL", ""))

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

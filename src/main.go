package main

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"time"

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

type RadiusCacheItem struct {
	Password string
	LastUsed time.Time
}

var radiusCache sync.Map
var authCacheRetention time.Duration
var authCacheGC time.Duration

func updateCache(username, password string) {
	radiusCache.Store(username, RadiusCacheItem{
		Password: password,
		LastUsed: time.Now(),
	})
}

func isCacheExpired(item RadiusCacheItem) bool {
	return time.Since(item.LastUsed) >= authCacheRetention
}

// RadiusCredentials.Valid implements the socks5.CredentialStore interface.
func (r *RadiusCredentials) Valid(username, password string) bool {
	if v, ok := radiusCache.Load(username); ok {
		item := v.(RadiusCacheItem)
		if item.Password == password && !isCacheExpired(item) {
			updateCache(username, password)
			return true
		}
	}
	packet := radius.New(radius.CodeAccessRequest, r.Secret)
	rfc2865.UserName_SetString(packet, username)
	rfc2865.UserPassword_SetString(packet, password)
	response, err := radius.Exchange(context.Background(), packet, r.Server)
	if err != nil {
		log.Printf("[ERR] Radius error: %s\n", err)
		return false
	}
	if response.Code == radius.CodeAccessAccept {
		updateCache(username, password)
		return true
	}
	return false
}

func getEnv(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}

func init() {
	log.SetFlags(log.Flags() | log.Lshortfile)
	// Don't repeat timestamp if logging to systemd journal (v231+)
	if _, ok := os.LookupEnv("JOURNAL_STREAM"); ok {
		log.SetFlags(log.Flags() &^ (log.Ldate | log.Ltime))
	}
}

func cacheGC() {
	ticker := time.NewTicker(authCacheGC)
	defer ticker.Stop()
	for range ticker.C {
		radiusCache.Range(func(key, value interface{}) bool {
			item := value.(RadiusCacheItem)
			if isCacheExpired(item) {
				radiusCache.Delete(key)
			}
			return true
		})
	}
}

func main() {
	listenAddr := getEnv("GANTED_LISTEN", "127.0.0.1:6626")
	radiusAddr := getEnv("RADIUS_SERVER", "127.0.0.1:1812")
	radiusSecret := getEnv("RADIUS_SECRET", "")
	serverACL := &ACL{BasicNet: netallow.NewBasicNet()}
	err := serverACL.Set(getEnv("GANTED_ACL", ""))
	if err != nil {
		panic(err)
	}
	authCacheRetention, err = time.ParseDuration(getEnv("GANTED_AUTH_CACHE_RETENTION", "10m"))
	if err != nil {
		panic(err)
	}
	authCacheGC, err = time.ParseDuration(getEnv("GANTED_AUTH_CACHE_GC", "10m"))
	if err != nil {
		panic(err)
	}

	dialer := &net.Dialer{}
	bindAddr := getEnv("GANTED_BIND_OUTPUT", "")
	if bindAddr != "" {
		dialer.LocalAddr = &net.TCPAddr{IP: net.ParseIP(bindAddr)}
	}

	// Clear expired cache entries at interval of GANTED_AUTH_CACHE_GC
	go cacheGC()

	server, err := socks5.New(&socks5.Config{
		Credentials: &RadiusCredentials{
			Server: radiusAddr,
			Secret: []byte(radiusSecret),
		},
		Rules:  serverACL,
		Logger: log.Default(),
		Dial:   dialer.DialContext,
	})
	if err != nil {
		log.Fatalf("[ERR] Create socks5 server: %s", err)
	}
	if err := server.ListenAndServe("tcp", listenAddr); err != nil {
		log.Fatalf("[ERR] Start socks5 server: %s", err)
	}
}

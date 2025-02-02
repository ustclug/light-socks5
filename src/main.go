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
	"github.com/robfig/cron/v3"
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"path/filepath"
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
	Server           string
	AccountingServer string
	Secret           []byte
	NASIdentifier    string
	Cache            RadiusCache
}

type RadiusCache struct {
	Retention time.Duration
	GC        time.Duration
	Map       sync.Map
}

type RadiusCacheItem struct {
	Password string
	LastUsed time.Time
}

func (c *RadiusCache) isExpired(item *RadiusCacheItem) bool {
	return time.Since(item.LastUsed) >= c.Retention
}

func (r *RadiusCredentials) updateCache(username, password string) {
	r.Cache.Map.Store(username, RadiusCacheItem{
		Password: password,
		LastUsed: time.Now(),
	})
}

// RadiusCredentials.Valid implements the socks5.CredentialStore interface.
func (r *RadiusCredentials) Valid(username, password string) bool {
	if v, ok := r.Cache.Map.Load(username); ok {
		item := v.(RadiusCacheItem)
		if item.Password == password && !r.Cache.isExpired(&item) {
			r.updateCache(username, password)
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
		r.updateCache(username, password)
		return true
	}
	return false
}

// Clear expired cache entries at interval of GANTED_AUTH_CACHE_GC
func (r *RadiusCredentials) gcworker() {
	ticker := time.NewTicker(r.Cache.GC)
	defer ticker.Stop()
	for range ticker.C {
		r.Cache.Map.Range(func(key, value interface{}) bool {
			item := value.(RadiusCacheItem)
			if r.Cache.isExpired(&item) {
				r.Cache.Map.Delete(key)
			}
			return true
		})
	}
}

func (r *RadiusCredentials) StartGCWorker() {
	go r.gcworker()
}

func (r *RadiusCredentials) accountingCron(accessLogger, errorLogger *log.Logger) *cron.Cron {
	// hourly accounting cron job
	c := cron.New()
	_, err := c.AddFunc("@hourly", func() {
		// accounting
		err := r.accounting(accessLogger)
		if err != nil {
			errorLogger.Printf("Accounting error: %s\n", err)
		}
	})
	if err != nil {
		log.Fatalf("[ERR] Failed to add accounting cron job: %s", err)
	}
	c.Start()
	return c
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

func init() {
	// init dir GANTED_LOG_DIR
	gantedLogDir := getEnv("GANTED_LOG_DIR", "/var/log/ganted")
	if _, err := os.Stat(gantedLogDir); os.IsNotExist(err) {
		if err := os.Mkdir(gantedLogDir, 0755); err != nil {
			log.Fatalf("[ERR] Failed to create ganted log directory %s: %s", gantedLogDir, err)
		}
	}
}

func setFileLoggerOutput(logger *log.Logger, filePath string) error {
	if filePath == "" {
		return nil
	}
	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		log.Fatalf("[ERR] Failed to open file %s: %s", filePath, err)
	}
	prevWriter := logger.Writer()
	logger.SetOutput(file)
	if closer, ok := prevWriter.(io.Closer); ok {
		closer.Close()
	}
	return nil
}

func initFileLogger(filePath string) (*log.Logger, error) {
	logger := log.New(os.Stdout, "", log.LstdFlags)
	if err := setFileLoggerOutput(logger, filePath); err != nil {
		return nil, err
	}
	return logger, nil
}

func main() {
	listenAddr := getEnv("GANTED_LISTEN", "127.0.0.1:6626")
	radiusAddr := getEnv("RADIUS_SERVER", "127.0.0.1:1812")
	radiusSecret := getEnv("RADIUS_SECRET", "")
	radiusAccountingAddr := getEnv("RADIUS_ACCOUNTING_SERVER", "127.0.0.1:1813")
	nasIdentifier := getEnv("NAS_IDENTIFIER", "ganted")
	serverACL := &ACL{BasicNet: netallow.NewBasicNet()}
	err := serverACL.Set(getEnv("GANTED_ACL", ""))
	if err != nil {
		panic(err)
	}
	authCacheRetention, err := time.ParseDuration(getEnv("GANTED_AUTH_CACHE_RETENTION", "10m"))
	if err != nil {
		panic(err)
	}
	authCacheGC, err := time.ParseDuration(getEnv("GANTED_AUTH_CACHE_GC", "10m"))
	if err != nil {
		panic(err)
	}

	dialer := &net.Dialer{}
	bindAddr := getEnv("GANTED_BIND_OUTPUT", "")
	if bindAddr != "" {
		dialer.LocalAddr = &net.TCPAddr{IP: net.ParseIP(bindAddr)}
	}

	credentials := &RadiusCredentials{
		Server:           radiusAddr,
		AccountingServer: radiusAccountingAddr,
		Secret:           []byte(radiusSecret),
		NASIdentifier:    nasIdentifier,
		Cache: RadiusCache{
			Retention: authCacheRetention,
			GC:        authCacheGC,
		},
	}
	gantedLogDir := getEnv("GANTED_LOG_DIR", "/var/log/ganted")
	credentials.StartGCWorker()

	accessLogger, err := initFileLogger(filepath.Join(gantedLogDir, "access.log"))
	if err != nil {
		log.Fatalf("[ERR] Failed to init access log: %s", err)
	}
	errorLogger, err := initFileLogger(filepath.Join(gantedLogDir, "error.log"))
	if err != nil {
		log.Fatalf("[ERR] Failed to init error log: %s", err)
	}
	c := credentials.accountingCron(accessLogger, errorLogger)
	if c == nil {
		log.Fatalf("[ERR] Failed to start accounting cron job")
	} else {
		defer c.Stop()
	}
	server, err := socks5.New(&socks5.Config{
		Credentials:  credentials,
		Rules:        serverACL,
		Logger:       log.Default(),
		AccessLogger: accessLogger,
		ErrorLogger:  errorLogger,
		Dial:         dialer.DialContext,
	})
	if err != nil {
		log.Fatalf("[ERR] Create socks5 server: %s", err)
	}
	if err := server.ListenAndServe("tcp", listenAddr); err != nil {
		log.Fatalf("[ERR] Start socks5 server: %s", err)
	}
}

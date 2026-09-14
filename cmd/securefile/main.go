// Command securefile runs セキュファイル便.
//
// Everything it needs is in this one binary: templates, static assets, the
// HTTP server, and the expiry sweeper. Deployment is a file copy and a
// systemd restart.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/paps-jp/securefile/internal/httpd"
	"github.com/paps-jp/securefile/internal/service"
	"github.com/paps-jp/securefile/internal/store"
	"github.com/paps-jp/securefile/web"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "securefile: %v\n", err)
		os.Exit(1)
	}
}

// options are the runtime settings, each available as a flag and as an
// environment variable so the systemd unit can carry them in an EnvironmentFile.
type options struct {
	addr           string
	dataDir        string
	baseURL        string
	trustedProxies string
	realIPHeader   string
	adsenseClient  string
	adminUser      string
	adminPass      string
	reportDir      string
	gaID           string
	ipHashKeyFile  string
	maxTotalBytes  int64
	maxFiles       int
	maxDays        int
	maxDownloads   int
	diskQuota      int64
	sweepInterval  time.Duration
	enableHSTS     bool
	logLevel       string
}

func parseOptions() (*options, error) {
	o := &options{}
	flag.StringVar(&o.addr, "addr", env("SECUREFILE_ADDR", "127.0.0.1:8080"), "listen address")
	flag.StringVar(&o.dataDir, "data-dir", env("SECUREFILE_DATA_DIR", "/var/lib/securefile"), "directory for the database and encrypted blobs")
	flag.StringVar(&o.baseURL, "base-url", env("SECUREFILE_BASE_URL", "http://localhost:8080"), "public origin, used to build share links")
	flag.StringVar(&o.trustedProxies, "trusted-proxies", env("SECUREFILE_TRUSTED_PROXIES", ""), "comma-separated CIDRs whose X-Forwarded-For may be trusted")
	flag.StringVar(&o.realIPHeader, "real-ip-header", env("SECUREFILE_REAL_IP_HEADER", ""), "single-value header with the true client IP from a trusted peer (e.g. CF-Connecting-IP behind Cloudflare Tunnel)")
	flag.StringVar(&o.adsenseClient, "adsense-client", env("SECUREFILE_ADSENSE_CLIENT", ""), "Google AdSense publisher ID (ca-pub-...). Enables ads on non-secret pages only; empty disables ads")
	flag.StringVar(&o.adminUser, "admin-user", env("SECUREFILE_ADMIN_USER", ""), "username for the /admin dashboard (Basic auth); empty disables /admin")
	flag.StringVar(&o.adminPass, "admin-pass", env("SECUREFILE_ADMIN_PASSWORD", ""), "password for the /admin dashboard (Basic auth); empty disables /admin")
	flag.StringVar(&o.reportDir, "report-dir", env("SECUREFILE_REPORT_DIR", ""), "directory of public documents served read-only at /report/; empty disables the route")
	flag.StringVar(&o.gaID, "ga-id", env("SECUREFILE_GA_ID", ""), "Google Analytics 4 measurement ID (G-...); loaded on non-secret pages only. Empty disables analytics")
	flag.StringVar(&o.ipHashKeyFile, "ip-hash-key-file", env("SECUREFILE_IP_HASH_KEY_FILE", ""), "file holding the key used to hash uploader addresses (generated if absent)")
	flag.StringVar(&o.logLevel, "log-level", env("SECUREFILE_LOG_LEVEL", "info"), "debug, info, warn or error")
	flag.BoolVar(&o.enableHSTS, "hsts", envBool("SECUREFILE_HSTS", false), "send Strict-Transport-Security")

	flag.Int64Var(&o.maxTotalBytes, "max-total-bytes", envInt64("SECUREFILE_MAX_TOTAL_BYTES", 10<<30), "maximum combined size of one share")
	flag.IntVar(&o.maxFiles, "max-files", int(envInt64("SECUREFILE_MAX_FILES", 100)), "maximum files in one share")
	flag.IntVar(&o.maxDays, "max-days", int(envInt64("SECUREFILE_MAX_DAYS", 100)), "maximum retention in days")
	flag.IntVar(&o.maxDownloads, "max-downloads", int(envInt64("SECUREFILE_MAX_DOWNLOADS", 500)), "maximum download allowance")
	flag.Int64Var(&o.diskQuota, "disk-quota-bytes", envInt64("SECUREFILE_DISK_QUOTA_BYTES", 0), "storage budget; 0 disables the check")
	flag.DurationVar(&o.sweepInterval, "sweep-interval", envDuration("SECUREFILE_SWEEP_INTERVAL", 5*time.Minute), "how often expired shares are deleted")
	flag.Parse()

	if o.baseURL == "" {
		return nil, errors.New("base-url must be set")
	}
	return o, nil
}

func run() error {
	opt, err := parseOptions()
	if err != nil {
		return err
	}
	log := newLogger(opt.logLevel)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := os.MkdirAll(opt.dataDir, 0o700); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}

	st, err := store.Open(ctx, filepath.Join(opt.dataDir, "securefile.db"))
	if err != nil {
		return err
	}
	defer st.Close()

	cfg := service.DefaultConfig(filepath.Join(opt.dataDir, "blobs"))
	cfg.MaxTotalBytes = opt.maxTotalBytes
	cfg.MaxFiles = opt.maxFiles
	cfg.MaxDays = opt.maxDays
	cfg.MaxDownloads = opt.maxDownloads
	cfg.DiskQuotaBytes = opt.diskQuota

	svc, err := service.New(st, cfg)
	if err != nil {
		return err
	}

	ipKey, err := loadOrCreateKey(opt.ipHashKeyFile, opt.dataDir)
	if err != nil {
		return err
	}

	// Legacy shares (imported from the old server) share the same database and
	// live under their own blob directory. The subsystem is compiled in only in a
	// build tagged `legacy`; otherwise LegacyDB/LegacyDir are ignored and nothing
	// legacy is served. Passing them unconditionally keeps main.go free of the
	// legacy package.
	srv, err := httpd.New(svc, log, httpd.Options{
		BaseURL:         opt.baseURL,
		TrustedProxies:  splitList(opt.trustedProxies),
		RealIPHeader:    opt.realIPHeader,
		AdsenseClient:   opt.adsenseClient,
		AdminUser:       opt.adminUser,
		AdminPass:       opt.adminPass,
		ReportDir:       opt.reportDir,
		GAMeasurementID: opt.gaID,
		IPHashKey:       ipKey,
		EnableHSTS:      opt.enableHSTS,
		Assets:          web.Assets,
		LegacyDB:        st.DB(),
		LegacyDir:       filepath.Join(opt.dataDir, "legacy"),
	})
	if err != nil {
		return err
	}

	go sweepLoop(ctx, svc, srv, log, opt.sweepInterval)

	httpServer := &http.Server{
		Addr:    opt.addr,
		Handler: srv,
		// No write timeout: a legitimate download of several gigabytes over a
		// slow link would trip one. Read and idle timeouts still bound how
		// long a connection can sit doing nothing.
		ReadHeaderTimeout: 20 * time.Second,
		IdleTimeout:       2 * time.Minute,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}

	errs := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", opt.addr, "base_url", opt.baseURL, "data_dir", opt.dataDir)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errs <- err
		}
	}()

	select {
	case err := <-errs:
		return fmt.Errorf("listen: %w", err)
	case <-ctx.Done():
		log.Info("shutting down")
	}

	// Give transfers in flight a chance to finish rather than cutting them off.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	return nil
}

// sweepLoop deletes expired shares on a timer.
//
// Retention is a promise to the user, so it runs on a clock rather than only
// when someone happens to request an expired key: a share nobody ever opens
// still has to disappear on schedule.
func sweepLoop(ctx context.Context, svc *service.Service, srv *httpd.Server, log *slog.Logger, every time.Duration) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()

	for {
		res, err := svc.Sweep(ctx, log)
		if err != nil {
			log.Error("sweep failed", "err", err)
		} else if res.DropsDeleted > 0 || res.Errors > 0 {
			log.Info("swept",
				"deleted", res.DropsDeleted,
				"sessions_expired", res.SessionsExpired,
				"errors", res.Errors)
		}

		// Imported legacy shares expire on the same clock. In a build without the
		// legacy subsystem this is a no-op.
		if n, err := srv.SweepLegacy(ctx); err != nil {
			log.Error("legacy sweep failed", "err", err)
		} else if n > 0 {
			log.Info("legacy swept", "deleted", n)
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// loadOrCreateKey reads the uploader-hash key, generating one on first run.
//
// The key must survive restarts: if it changed, hashes recorded before and
// after would not compare, and the abuse-handling question it exists to answer
// — "is this the same uploader as that other share?" — could not be asked
// across the change.
func loadOrCreateKey(path, dataDir string) ([]byte, error) {
	if path == "" {
		path = filepath.Join(dataDir, "ip-hash.key")
	}

	raw, err := os.ReadFile(path)
	if err == nil {
		key, decErr := hex.DecodeString(strings.TrimSpace(string(raw)))
		if decErr != nil || len(key) < 32 {
			return nil, fmt.Errorf("ip hash key at %s is not 32+ bytes of hex", path)
		}
		return key, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read ip hash key: %w", err)
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate ip hash key: %w", err)
	}
	if err := os.WriteFile(path, []byte(hex.EncodeToString(key)+"\n"), 0o600); err != nil {
		return nil, fmt.Errorf("write ip hash key: %w", err)
	}
	return key, nil
}

func newLogger(level string) *slog.Logger {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		l = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: l}))
}

func splitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

func env(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return fallback
}

func envInt64(key string, fallback int64) int64 {
	v, ok := os.LookupEnv(key)
	if !ok {
		return fallback
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return fallback
	}
	return n
}

func envBool(key string, fallback bool) bool {
	v, ok := os.LookupEnv(key)
	if !ok {
		return fallback
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return fallback
	}
	return b
}

func envDuration(key string, fallback time.Duration) time.Duration {
	v, ok := os.LookupEnv(key)
	if !ok {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return fallback
	}
	return d
}

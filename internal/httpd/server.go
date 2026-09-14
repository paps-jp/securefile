// Package httpd is the HTTP transport for セキュファイル便.
package httpd

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/fnv"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/paps-jp/securefile/internal/i18n"
	"github.com/paps-jp/securefile/internal/service"
)

// langContextKey carries the request language through the middleware.
type langContextKey struct{}

// randomToken returns a 256-bit hex string, used for the admin CSRF token.
func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("httpd: random token: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// Options configures a Server.
type Options struct {
	// BaseURL is the public origin, used to build share links.
	BaseURL string
	// TrustedProxies are CIDRs whose X-Forwarded-For headers may be believed.
	TrustedProxies []string
	// RealIPHeader, if set, is a single-value header carrying the true client
	// address, read only from a trusted peer. Set to "CF-Connecting-IP" when
	// running behind a Cloudflare Tunnel.
	RealIPHeader string
	// IPHashKey keys the HMAC used to record uploaders without storing
	// addresses.
	IPHashKey []byte
	// EnableHSTS adds Strict-Transport-Security. Leave off when the service is
	// reachable over plain HTTP during a migration.
	EnableHSTS bool
	// Assets holds the static files and templates.
	Assets fs.FS
	// LegacyDB and LegacyDir enable serving imported old-format shares at their
	// original bare-key URLs during the migration window, but only in a build
	// tagged `legacy`. LegacyDB is the shared metadata database; LegacyDir is the
	// root for legacy blobs. Both empty (or a non-legacy build) disables the path.
	LegacyDB  *sql.DB
	LegacyDir string
	// AdsenseClient, if set (ca-pub-...), enables Google AdSense on non-secret
	// pages only (never on download pages, whose URL carries the share key).
	AdsenseClient string
	// AdminUser and AdminPass, if both set, enable the /admin dashboard behind
	// HTTP Basic auth. If either is empty the admin routes are not registered,
	// so the management surface is absent rather than merely password-protected.
	AdminUser string
	AdminPass string
	// ReportDir, if set, is a directory of public documents served read-only at
	// /report/. It restores the static files the old site published there (annual
	// reports, financial statements). Empty disables the route.
	ReportDir string
	// GAMeasurementID, if set (G-...), loads Google Analytics 4 — but only on
	// non-secret pages, never on a page whose URL or fragment can carry a share
	// key or password (download, manage, legacy). Empty disables analytics.
	GAMeasurementID string
}

// Server routes HTTP requests to the service.
type Server struct {
	svc *service.Service
	// legacy is the optional imported-shares subsystem. It is non-nil only in a
	// build tagged `legacy` with LegacyDB configured; otherwise it stays nil and
	// every legacy hook is a no-op. See legacy_runtime.go.
	legacy    legacyRuntime
	log       *slog.Logger
	opt       Options
	ip        *clientIPResolver
	tmpl      *template.Template
	assetV    string
	mux       *http.ServeMux
	i18n      *i18n.Catalog
	adminCSRF string
	limit     struct {
		unlock *limiter // password attempts
		start  *limiter // new uploads
		report *limiter // abuse reports
		admin  *limiter // admin login attempts
	}
}

// New builds a Server and its routes.
func New(svc *service.Service, log *slog.Logger, opt Options) (*Server, error) {
	ip, err := newClientIPResolver(opt.TrustedProxies, opt.RealIPHeader)
	if err != nil {
		return nil, fmt.Errorf("httpd: parse trusted proxies: %w", err)
	}
	tmpl, err := template.New("").Funcs(templateFuncs()).ParseFS(opt.Assets, "templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("httpd: parse templates: %w", err)
	}
	cat, err := i18n.Load(opt.Assets)
	if err != nil {
		return nil, fmt.Errorf("httpd: load i18n: %w", err)
	}

	s := &Server{
		svc: svc,
		log: log, opt: opt, ip: ip, tmpl: tmpl, assetV: assetVersion(opt.Assets),
		i18n: cat, mux: http.NewServeMux(),
	}
	// Password attempts are the expensive path (Argon2), so they get the
	// tightest budget. Starting uploads is cheap but allocates storage.
	s.limit.unlock = newLimiter(10, time.Minute)
	s.limit.start = newLimiter(30, time.Minute)
	// Reports block a share on sight, so a flood from one address is capped;
	// admin login attempts are capped against brute force.
	s.limit.report = newLimiter(6, time.Minute)
	s.limit.admin = newLimiter(10, time.Minute)

	csrf, err := randomToken()
	if err != nil {
		return nil, err
	}
	s.adminCSRF = csrf

	// Wire the imported-shares subsystem when this is a `legacy` build with a
	// database configured. In every other build initLegacy is a no-op and
	// s.legacy stays nil.
	if err := s.initLegacy(opt.LegacyDB, opt.LegacyDir); err != nil {
		return nil, fmt.Errorf("httpd: init legacy: %w", err)
	}

	s.routes()
	go s.sweepLimiters()
	return s, nil
}

func (s *Server) routes() {
	static, err := fs.Sub(s.opt.Assets, "static")
	if err != nil {
		panic(fmt.Sprintf("httpd: static assets: %v", err))
	}
	s.mux.Handle("GET /static/", http.StripPrefix("/static/", cacheStatic(http.FileServerFS(static))))

	// /report/ serves the public documents the old site published there. It is
	// registered only when a directory is configured.
	if s.opt.ReportDir != "" {
		s.mux.Handle("GET /report/", http.StripPrefix("/report/", s.reportFiles(s.opt.ReportDir)))
	}

	// Pages.
	s.mux.HandleFunc("GET /{$}", s.handleIndex)
	// Share links are bare keys at the root (up.paps.jp/<key>); visiting one
	// stashes the key in a cookie and redirects to the key-free /receive page,
	// which renders the download UI. /d/<key> is kept as a permanent redirect so
	// any link made during testing still resolves.
	s.mux.HandleFunc("GET /d/{key}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/"+r.PathValue("key"), http.StatusMovedPermanently)
	})
	s.mux.HandleFunc("GET /receive", s.handleReceive)
	// The previous site's pages are still indexed and ranking; redirect them to
	// the new equivalents so that search value is not lost to 404s.
	for from, to := range map[string]string{
		"/aboutus.php": "/about", "/qa.php": "/about",
		"/terms.php": "/terms", "/privacy.php": "/privacy",
	} {
		dest := to
		s.mux.HandleFunc("GET "+from, func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, dest, http.StatusMovedPermanently)
		})
	}

	s.mux.HandleFunc("GET /about", s.handleStatic("about.html", "about.title", "about.description"))
	s.mux.HandleFunc("GET /faq", s.handleFAQ)
	s.mux.HandleFunc("GET /guide", s.handleGuide)
	s.mux.HandleFunc("GET /privacy", s.handleStatic("privacy.html", "privacy.title", "privacy.description"))
	s.mux.HandleFunc("GET /terms", s.handleStatic("terms.html", "terms.title", "terms.description"))
	s.mux.HandleFunc("GET /abuse", s.handleAbuse)
	s.mux.HandleFunc("POST /abuse/report", s.handleReport)

	// Sender management link. The page carries no token (the script reads it from
	// the fragment); the API authorises by the X-Manage-Token header.
	s.mux.HandleFunc("GET /manage", s.handleManagePage)
	s.mux.HandleFunc("GET /api/manage", s.handleManageStatus)
	s.mux.HandleFunc("POST /api/manage/delete", s.handleManageDelete)

	// Per-language UI strings for the client scripts.
	s.mux.HandleFunc("GET /i18n.js", s.handleI18nJS)

	// SEO endpoints.
	s.mux.HandleFunc("GET /robots.txt", s.handleRobots)
	s.mux.HandleFunc("GET /sitemap.xml", s.handleSitemap)
	s.mux.HandleFunc("GET /manifest.webmanifest", s.handleManifest)

	// Admin dashboard, only in a build tagged `admin` and only when credentials
	// are configured. In the public build this is a no-op.
	s.registerAdmin()

	// Upload API.
	s.mux.HandleFunc("POST /api/uploads", s.handleStartUpload)
	s.mux.HandleFunc("GET /api/uploads/{sid}", s.handleUploadState)
	s.mux.HandleFunc("PATCH /api/uploads/{sid}/files/{fid}", s.handleWritePart)
	s.mux.HandleFunc("POST /api/uploads/{sid}/finish", s.handleFinishUpload)
	s.mux.HandleFunc("DELETE /api/uploads/{sid}", s.handleCancelUpload)

	// Download API.
	s.mux.HandleFunc("GET /api/drops/{key}", s.handlePeek)
	s.mux.HandleFunc("POST /api/drops/{key}/unlock", s.handleUnlock)
	s.mux.HandleFunc("GET /api/session/files", s.handleSessionFiles)
	s.mux.HandleFunc("POST /api/session/tickets", s.handleIssueTicket)
	s.mux.HandleFunc("DELETE /api/session", s.handleLock)
	s.mux.HandleFunc("POST /api/session/delete", s.handleSessionDelete)

	// Ticket-authorised transfers, reached by navigation rather than fetch.
	s.mux.HandleFunc("GET /dl/{ticket}", s.handleDownload)
	s.mux.HandleFunc("HEAD /dl/{ticket}", s.handleDownload)
	s.mux.HandleFunc("GET /zip/{ticket}", s.handleArchive)

	s.mux.HandleFunc("GET /api/status", s.handleStatus)
	s.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintln(w, "ok")
	})

	// Legacy (imported old shares). Registered only in a `legacy` build with the
	// subsystem enabled; a no-op otherwise. Self-contained, so the whole path can
	// be dropped once the last imported share has expired.
	s.registerLegacy()

	// Old-style bare-key URLs (up.paps.jp/<key>). This catch-all must be
	// registered last; Go's ServeMux gives the more specific patterns above
	// precedence, so this only sees paths nothing else claimed.
	s.mux.HandleFunc("GET /{key}", s.handleBareKey)
}

// dlCookie carries the share key from the bare-key URL to the key-free receive
// page, so the key never appears in the URL of the page that shows the files.
const dlCookie = "sf_dl"

// handleBareKey handles a share's bare-key URL (up.paps.jp/<key>). It does not
// render anything: it stashes the key in an HttpOnly cookie and redirects to the
// key-free /receive page. Moving the key out of the URL keeps it — and, once the
// script scrubs the fragment, the embedded password — out of the page URL that a
// third-party ad script on the receive page would otherwise read. The redirect
// is uniform for every key, so it discloses nothing about whether a key is live.
func (s *Server) handleBareKey(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	http.SetCookie(w, &http.Cookie{
		Name:     dlCookie,
		Value:    key,
		Path:     "/",
		MaxAge:   3600,
		HttpOnly: true,
		Secure:   s.opt.EnableHSTS, // set over HTTPS (behind the tunnel)
		SameSite: http.SameSiteLaxMode,
	})
	// Show the recipient the download page in their own language when we can
	// tell it from the browser; the footer switcher still lets them change it.
	http.Redirect(w, r, langPath(preferredLang(r.Header.Get("Accept-Language")), "/receive"), http.StatusFound)
}

// preferredLang picks the best supported language from an Accept-Language
// header, defaulting to Japanese. Only the primary subtag is compared
// (e.g. "zh-CN" -> "zh"), and quality values order the candidates.
func preferredLang(accept string) string {
	type cand struct {
		code string
		q    float64
	}
	var cands []cand
	for _, part := range strings.Split(accept, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		code, q := part, 1.0
		if i := strings.Index(part, ";"); i >= 0 {
			code = strings.TrimSpace(part[:i])
			if j := strings.Index(part[i:], "q="); j >= 0 {
				fmt.Sscanf(part[i+j+2:], "%f", &q)
			}
		}
		if k := strings.IndexByte(code, '-'); k >= 0 {
			code = code[:k]
		}
		cands = append(cands, cand{strings.ToLower(code), q})
	}
	sort.SliceStable(cands, func(i, j int) bool { return cands[i].q > cands[j].q })
	for _, c := range cands {
		if i18n.IsSupported(c.code) {
			return c.code
		}
	}
	return i18n.Default
}

// handleReceive renders the download page for the key held in the cookie. The
// URL carries no key, so ads may run here without exposing it. A live new share
// and an unknown key both render the download page (probing learns nothing); a
// legacy key renders the legacy page without ads.
func (s *Server) handleReceive(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(dlCookie)
	if err != nil || c.Value == "" {
		// No active pickup: send the visitor to the About page, the single
		// canonical page for what this service is.
		http.Redirect(w, r, langPath(s.lang(r), "/about"), http.StatusFound)
		return
	}
	key := c.Value
	w.Header().Set("Cache-Control", "no-store")

	if _, err := s.svc.Peek(r.Context(), key); err != nil && s.legacyLive(r, key) {
		s.legacyPage(w, r, key)
		return
	}
	s.allowAdsCSP(w)
	s.handleDownloadPage(w, r, key)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// A leading /<lang>/ selects a language and is stripped before routing, so
	// every handler and route pattern stays language-agnostic. Japanese is the
	// default and has no prefix; an explicit /ja/… redirects to the bare path.
	lang := i18n.Default
	if seg, rest, ok := splitLangPrefix(r.URL.Path); ok {
		if seg == i18n.Default {
			http.Redirect(w, r, rest, http.StatusMovedPermanently)
			return
		}
		lang = seg
		r.URL.Path = rest
	}
	r = r.WithContext(context.WithValue(r.Context(), langContextKey{}, lang))

	s.securityHeaders(w)
	s.mux.ServeHTTP(w, r)
}

// splitLangPrefix returns the language code and the remaining path when path
// begins with a supported /<lang> segment. "/en/about" -> ("en", "/about");
// "/en" -> ("en", "/"). Anything else returns ok=false.
func splitLangPrefix(path string) (lang, rest string, ok bool) {
	if len(path) < 2 || path[0] != '/' {
		return "", "", false
	}
	seg := path[1:]
	if i := strings.IndexByte(seg, '/'); i >= 0 {
		rest = seg[i:]
		seg = seg[:i]
	} else {
		rest = "/"
	}
	if !i18n.IsSupported(seg) {
		return "", "", false
	}
	return seg, rest, true
}

// lang reads the request language set by the middleware.
func (s *Server) lang(r *http.Request) string {
	if v, ok := r.Context().Value(langContextKey{}).(string); ok {
		return v
	}
	return i18n.Default
}

// langPath prefixes a site path with the language, matching the routing scheme
// (Japanese has no prefix). langPath("en", "/about") == "/en/about".
func langPath(lang, path string) string {
	if lang == i18n.Default || lang == "" {
		return path
	}
	if path == "/" {
		return "/" + lang
	}
	return "/" + lang + path
}

// securityHeaders applies a policy tight enough that the pages load no
// third-party code at all.
//
// The previous service pulled in jQuery, Google Analytics and AdSense, which
// meant three external parties observed every visit to a page whose whole
// point is confidentiality. Nothing here loads from another origin, and the
// CSP makes that a rule the browser enforces rather than a habit.
func (s *Server) securityHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Security-Policy", strings.Join([]string{
		"default-src 'none'",
		"script-src 'self'",
		"style-src 'self'",
		// blob: lets the download page preview an unlocked image or PDF from a
		// script-built object URL; the bytes are same-origin and already decrypted
		// for the recipient, so this exposes nothing a download would not.
		"img-src 'self' data: blob:",
		"object-src blob:",
		"font-src 'self'",
		"connect-src 'self'",
		"form-action 'self'",
		"frame-ancestors 'none'",
		"base-uri 'none'",
	}, "; "))
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	// Share links carry the secret half of the URL, so no page may leak one in
	// a Referer to anywhere, including our own origin.
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Permissions-Policy", "geolocation=(), camera=(), microphone=(), interest-cohort=()")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	if s.opt.EnableHSTS {
		h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	}
}

// allowAdsCSP replaces the strict CSP with one permitting Google AdSense, for
// the non-secret pages that carry ads. It is never applied to download or
// legacy pages, whose URL contains the share key: letting a third-party script
// run there would hand the key to Google. Ads fail closed — a wrong directive
// only stops an ad from rendering, never leaks anything.
func (s *Server) allowAdsCSP(w http.ResponseWriter) {
	if s.opt.AdsenseClient == "" && s.opt.GAMeasurementID == "" {
		return
	}
	w.Header().Set("Content-Security-Policy", strings.Join([]string{
		"default-src 'none'",
		"script-src 'self' https://pagead2.googlesyndication.com https://partner.googleadservices.com https://tpc.googlesyndication.com https://adservice.google.com https://*.googlesyndication.com https://www.googletagmanager.com",
		"style-src 'self' 'unsafe-inline'",
		"img-src 'self' data: blob: https:",
		"object-src blob:",
		"font-src 'self'",
		"connect-src 'self' https://pagead2.googlesyndication.com https://*.googlesyndication.com https://*.google.com https://*.doubleclick.net https://www.googletagmanager.com https://*.google-analytics.com https://*.analytics.google.com",
		"frame-src https://googleads.g.doubleclick.net https://tpc.googlesyndication.com https://www.google.com",
		"form-action 'self'",
		"frame-ancestors 'none'",
		"base-uri 'none'",
	}, "; "))
}

// assetVersion hashes the embedded static files into a short token appended to
// their URLs as ?v=. Because the HTML is never edge-cached (only the static
// files are), a new token after a deploy points browsers and the CDN at a URL
// they have not cached, so updated CSS/JS take effect immediately instead of
// waiting out the CDN's static TTL.
func assetVersion(assets fs.FS) string {
	h := fnv.New64a()
	_ = fs.WalkDir(assets, "static", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, rerr := fs.ReadFile(assets, p)
		if rerr != nil {
			return rerr
		}
		h.Write([]byte(p))
		h.Write(b)
		return nil
	})
	return strconv.FormatUint(h.Sum64(), 36)
}

// cacheStatic lets browsers hold assets, which are versioned by the build.
func cacheStatic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=60")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) clientIP(r *http.Request) netip.Addr { return s.ip.resolve(r) }

// sweepLimiters keeps the rate-limit maps from growing without bound.
func (s *Server) sweepLimiters() {
	for range time.Tick(5 * time.Minute) {
		s.limit.unlock.sweep()
		s.limit.start.sweep()
		s.limit.report.sweep()
		s.limit.admin.sweep()
	}
}

// statusFor maps a service error to an HTTP status and a message safe to show
// a stranger.
func statusFor(err error) (int, string) {
	switch {
	case errors.Is(err, service.ErrNotFound):
		return http.StatusNotFound, "見つかりません。URLが誤っているか、保存期間またはダウンロード回数の上限に達しています。"
	case errors.Is(err, service.ErrWrongPassword):
		return http.StatusUnauthorized, "パスワードが違います。"
	case errors.Is(err, service.ErrTooLarge):
		return http.StatusRequestEntityTooLarge, "上限を超えています。"
	case errors.Is(err, service.ErrInvalid):
		return http.StatusBadRequest, "リクエストが不正です。"
	default:
		return http.StatusInternalServerError, "サーバー側でエラーが発生しました。"
	}
}

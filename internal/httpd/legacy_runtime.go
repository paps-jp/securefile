package httpd

import (
	"context"
	"net/http"
)

// legacyRuntime is the server's hook into the optional imported-shares
// subsystem. Its only implementation lives in a build tagged `legacy`
// (legacy.go). In every other build s.legacy is nil and the helpers below are
// no-ops, so the legacy path — and with it the dependence on the old ZIP
// formats — is absent from the binary entirely.
type legacyRuntime interface {
	// live reports whether key names a live imported share.
	live(r *http.Request, key string) bool
	// page renders the download page for an old-style bare-key URL.
	page(w http.ResponseWriter, r *http.Request, key string)
	// register installs the legacy HTTP routes on the server's mux.
	register()
	// sweep removes expired imported shares (and stale in-memory sessions),
	// returning how many shares were deleted.
	sweep(ctx context.Context) (int, error)
}

// legacyLive reports whether key names a live imported share, safely when the
// subsystem is absent.
func (s *Server) legacyLive(r *http.Request, key string) bool {
	return s.legacy != nil && s.legacy.live(r, key)
}

// legacyPage renders the legacy download page. Only reached after legacyLive
// returned true, so s.legacy is non-nil here.
func (s *Server) legacyPage(w http.ResponseWriter, r *http.Request, key string) {
	s.legacy.page(w, r, key)
}

// registerLegacy installs the legacy routes when the subsystem is present.
func (s *Server) registerLegacy() {
	if s.legacy != nil {
		s.legacy.register()
	}
}

// SweepLegacy deletes expired imported shares. The sweep loop calls it on the
// same clock as the main sweep. It is a no-op (0, nil) when the legacy subsystem
// is not built in or not enabled.
func (s *Server) SweepLegacy(ctx context.Context) (int, error) {
	if s.legacy == nil {
		return 0, nil
	}
	return s.legacy.sweep(ctx)
}

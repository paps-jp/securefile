package httpd

import (
	"net/http"
)

// manageToken reads the sender's management secret. It travels in a header, set
// by the page's script from the URL fragment, so it never lands in the address
// bar, the access log, or a Referer.
func manageToken(r *http.Request) string {
	return r.Header.Get("X-Manage-Token")
}

// handleManagePage renders the sender's management page. The token is not in the
// URL — the page script reads it from the fragment and calls the API — so the
// page itself is the same for every visitor and carries no secret.
func (s *Server) handleManagePage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	d := s.basePage(r, "manage.title")
	d.NoIndex = true
	d.Canonical = d.BaseURL + langPath(d.Lang, "/")
	s.render(w, "manage.html", http.StatusOK, d)
}

// handleManageStatus reports a share's delivery state to the sender.
func (s *Server) handleManageStatus(w http.ResponseWriter, r *http.Request) {
	v, err := s.svc.ManageStatus(r.Context(), manageToken(r))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"key":          v.Key,
		"kind":         v.Kind,
		"createdAt":    v.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
		"expiresAt":    v.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z"),
		"maxDownloads": v.MaxDownloads,
		"downloads":    v.Downloads,
		"remaining":    v.Remaining,
		"totalSize":    v.TotalSize,
		"fileCount":    v.FileCount,
		"status":       v.Status,
		"blocked":      v.Blocked,
		"expired":      v.Expired,
		"exhausted":    v.Exhausted,
		"shareUrl":     s.shareURL(v.Key),
	})
}

// handleManageDelete deletes a share on the sender's request.
func (s *Server) handleManageDelete(w http.ResponseWriter, r *http.Request) {
	if err := s.svc.ManageDelete(r.Context(), manageToken(r)); err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

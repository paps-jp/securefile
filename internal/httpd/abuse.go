package httpd

import (
	"errors"
	"net/http"
	"strings"

	"github.com/paps-jp/securefile/internal/service"
)

// This file is the public rights-infringement report surface: a page anyone can
// reach and a POST that blocks the named share on sight. It is part of every
// build. The operator-facing admin dashboard that reviews these reports lives in
// admin.go, behind the `admin` build tag.

// handleAbuse renders the reporting page. A ?ok / ?err query set by the
// post-redirect after a submission drives the result notice.
func (s *Server) handleAbuse(w http.ResponseWriter, r *http.Request) {
	s.allowAdsCSP(w)
	d := s.basePage(r, "abuse.title")
	d.Description = d.T("abuse.description")
	d.GAID = s.opt.GAMeasurementID
	switch r.URL.Query().Get("r") {
	case "ok":
		d.Reported = true
	case "bad":
		d.ReportError = d.T("abuse.err_bad")
	case "rate":
		d.ReportError = d.T("abuse.err_rate")
	}
	s.render(w, "abuse.html", http.StatusOK, d)
}

// handleReport blocks the named share and records the report. It always
// redirects to a neutral result, so submitting a key never reveals whether it
// existed.
func (s *Server) handleReport(w http.ResponseWriter, r *http.Request) {
	abuse := langPath(s.lang(r), "/abuse")
	if !s.limit.report.allow(s.clientIP(r)) {
		http.Redirect(w, r, abuse+"?r=rate", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, abuse+"?r=bad", http.StatusSeeOther)
		return
	}
	url := strings.TrimSpace(r.PostFormValue("url"))
	if url == "" {
		http.Redirect(w, r, abuse+"?r=bad", http.StatusSeeOther)
		return
	}
	reason := strings.TrimSpace(r.PostFormValue("reason"))
	contact := strings.TrimSpace(r.PostFormValue("contact"))

	if err := s.svc.Report(r.Context(), url, reason, contact, s.clientIP(r).String()); err != nil {
		// The outcome is neutral either way; a malformed key just asks the
		// reporter to check the link. Real failures are logged for the operator.
		if !errors.Is(err, service.ErrInvalid) {
			s.log.Warn("report failed", "err", err)
		}
		http.Redirect(w, r, abuse+"?r=bad", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, abuse+"?r=ok", http.StatusSeeOther)
}

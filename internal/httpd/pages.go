package httpd

import (
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/paps-jp/securefile/internal/i18n"
	"github.com/paps-jp/securefile/internal/service"
)

// handleI18nJS serves the active language's UI strings as a JavaScript global,
// so the client scripts can localise the text they generate. The language comes
// from the path prefix stripped by the middleware.
func (s *Server) handleI18nJS(w http.ResponseWriter, r *http.Request) {
	lang := s.lang(r)
	dict := s.i18n.Prefixed(lang, "js.")
	b, err := json.Marshal(dict)
	if err != nil {
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=300")
	fmt.Fprintf(w, "window.I18N=%s;window.LANG=%q;", b, lang)
}

// pageData is the model every template renders against.
type pageData struct {
	Title         string
	Key           string
	Limits        limitsView
	Stats         statsView
	BaseURL       string
	Message       string
	NotFound      bool
	AdsenseClient string
	// GAID is the Google Analytics measurement ID, set only on pages with no
	// secret in the URL or fragment. Empty leaves analytics off the page.
	GAID   string
	AssetV string
	// SEO fields. Description is the meta description; Canonical is the page's
	// canonical absolute URL; OGImage is the absolute URL of the share image.
	// NoIndex asks search engines not to index the page — set on any page whose
	// URL carries a secret (download and legacy pages) and on error pages.
	// StructuredData holds JSON-LD, injected verbatim (built server-side).
	Description    string
	Canonical      string
	OGImage        string
	NoIndex        bool
	StructuredData template.HTML
	// i18n. Lang is the active language; Dir its text direction; CleanPath the
	// request path without the language prefix; LangLinks drives the switcher
	// and the hreflang tags. catalog is unexported; templates reach it only
	// through the T/Th/Tf methods.
	Lang      string
	Dir       string
	CleanPath string
	LangLinks []langLink
	catalog   *i18n.Catalog
	// Reported/ReportError drive the notice on the abuse page after a report.
	Reported    bool
	ReportError string
	// FAQ and Steps drive the content pages; the same items feed the visible
	// HTML and the FAQPage/HowTo structured data, so the two never diverge.
	FAQ   []faqItem
	Steps []howStep
	// HasFAQ/HasGuide report whether the current language has these content
	// pages translated yet, so the footer links to them only where they read in
	// the visitor's own language (they roll out language by language).
	HasFAQ   bool
	HasGuide bool
}

// faqItem is one question/answer, rendered as a disclosure and as a FAQPage
// entry.
type faqItem struct{ Q, A string }

// howStep is one step of the how-to guide, rendered in an ordered list and as a
// HowTo step.
type howStep struct{ Name, Text string }

// langLink is one entry in the language switcher / hreflang set.
type langLink struct {
	Code    string
	Name    string
	Dir     string
	Rel     string // language-prefixed path for the current page
	Abs     string // absolute URL, for hreflang
	Current bool
}

// T returns the translation of key in the page's language (plain text).
func (d pageData) T(key string) string { return d.catalog.T(d.Lang, key) }

// Th returns a translation trusted to contain inline markup (<strong>, <a>).
// Translations are authored by the project, not user input.
func (d pageData) Th(key string) template.HTML { return template.HTML(d.catalog.T(d.Lang, key)) }

// Tf formats a translation containing printf verbs with the given arguments.
func (d pageData) Tf(key string, a ...any) string {
	return fmt.Sprintf(d.catalog.T(d.Lang, key), a...)
}

// URL prefixes a site path with the active language (Japanese has no prefix).
func (d pageData) URL(path string) string { return langPath(d.Lang, path) }

type limitsView struct {
	MaxFiles      int
	MaxTotalBytes int64
	MaxTotalHuman string
	MaxDays       int
	MaxDownloads  int
	PartSize      int64
}

type statsView struct {
	Files      int64
	Bytes      int64
	BytesHuman string
	QuotaHuman string
	Percent    int
}

func (s *Server) shareURL(key string) string {
	return strings.TrimRight(s.opt.BaseURL, "/") + "/" + key
}

// basePage builds the model shared by every page. titleKey is a catalog key;
// its translation becomes the full <title>. The description defaults to the
// site description and is overridden per page.
func (s *Server) basePage(r *http.Request, titleKey string) pageData {
	cfg := s.svc.Config()
	base := strings.TrimRight(s.opt.BaseURL, "/")
	lang := s.lang(r)
	clean := r.URL.Path
	d := pageData{
		Title:         s.i18n.T(lang, titleKey),
		BaseURL:       base,
		AdsenseClient: s.opt.AdsenseClient,
		AssetV:        s.assetV,
		Description:   s.i18n.T(lang, "meta.description"),
		Canonical:     base + langPath(lang, clean),
		OGImage:       base + "/static/og.png",
		Lang:          lang,
		Dir:           i18n.DirOf(lang),
		CleanPath:     clean,
		LangLinks:     s.langLinks(base, clean, lang),
		catalog:       s.i18n,
		Limits: limitsView{
			MaxFiles:      cfg.MaxFiles,
			MaxTotalBytes: cfg.MaxTotalBytes,
			MaxTotalHuman: humanBytes(cfg.MaxTotalBytes),
			MaxDays:       cfg.MaxDays,
			MaxDownloads:  cfg.MaxDownloads,
			PartSize:      cfg.PartSize,
		},
	}
	if st, err := s.svc.Stats(r.Context()); err == nil {
		d.Stats = statsView{Files: st.Files, Bytes: st.Bytes, BytesHuman: humanBytes(st.Bytes)}
		if cfg.DiskQuotaBytes > 0 {
			d.Stats.QuotaHuman = humanBytes(cfg.DiskQuotaBytes)
			d.Stats.Percent = int(st.Bytes * 100 / cfg.DiskQuotaBytes)
		}
	}
	d.HasFAQ = s.i18n.Has(lang, "faq.h1")
	d.HasGuide = s.i18n.Has(lang, "guide.h1")
	return d
}

// langLinks builds the language switcher / hreflang entries for a page.
func (s *Server) langLinks(base, cleanPath, current string) []langLink {
	out := make([]langLink, 0, len(i18n.Langs))
	for _, l := range i18n.Langs {
		rel := langPath(l.Code, cleanPath)
		out = append(out, langLink{
			Code: l.Code, Name: l.Name, Dir: l.Dir,
			Rel: rel, Abs: base + rel, Current: l.Code == current,
		})
	}
	return out
}

func (s *Server) render(w http.ResponseWriter, name string, status int, data pageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := s.tmpl.ExecuteTemplate(w, name, data); err != nil {
		s.log.Error("render template", "template", name, "err", err)
	}
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	s.allowAdsCSP(w)
	d := s.basePage(r, "index.title")
	d.Description = d.T("index.description")
	d.GAID = s.opt.GAMeasurementID
	d.StructuredData = s.indexJSONLD(d.Lang)
	s.render(w, "index.html", http.StatusOK, d)
}

// indexJSONLD builds the JSON-LD structured data for the landing page. It is
// marshalled server-side (so values are escaped correctly) and injected as a
// data block; application/ld+json is not executed, so the strict CSP allows it.
func (s *Server) indexJSONLD(lang string) template.HTML {
	base := strings.TrimRight(s.opt.BaseURL, "/")
	graph := []map[string]any{
		{
			"@type":       "WebSite",
			"@id":         base + "/#website",
			"url":         base + "/",
			"name":        "セキュファイル便",
			"inLanguage":  lang,
			"description": s.i18n.T(lang, "meta.description"),
			"publisher":   map[string]any{"@id": base + "/#org"},
		},
		{
			"@type":         "Organization",
			"@id":           base + "/#org",
			"name":          "特定非営利活動法人ぱっぷす",
			"alternateName": "PAPS",
			"url":           "https://paps.jp",
		},
		{
			"@type":               "WebApplication",
			"name":                "セキュファイル便",
			"url":                 base + "/",
			"applicationCategory": "UtilitiesApplication",
			"operatingSystem":     "Web",
			"inLanguage":          lang,
			"screenshot":          base + "/static/og.png",
			"featureList":         s.featureList(lang),
			"offers":              map[string]any{"@type": "Offer", "price": "0", "priceCurrency": "JPY"},
			"provider":            map[string]any{"@id": base + "/#org"},
		},
	}
	return ldScript(map[string]any{"@context": "https://schema.org", "@graph": graph})
}

// featureList reads the numbered feature strings for the WebApplication schema.
func (s *Server) featureList(lang string) []string {
	var out []string
	for i := 1; ; i++ {
		k := fmt.Sprintf("feat.%d", i)
		if s.i18n.T(lang, k) == k { // no such key
			break
		}
		out = append(out, s.i18n.T(lang, k))
	}
	return out
}

// handleDownloadPage renders the recipient's page for the given share key.
//
// It is served for both live and unknown keys with identical markup and status,
// so probing for valid keys tells an attacker nothing; the page's script then
// asks the API what the key actually refers to.
func (s *Server) handleDownloadPage(w http.ResponseWriter, r *http.Request, key string) {
	d := s.basePage(r, "download.title")
	d.Key = key
	// The URL carries the share key, so it must never be indexed, and its
	// canonical must not echo the key to a crawler either.
	d.NoIndex = true
	d.Canonical = d.BaseURL + langPath(d.Lang, "/")
	s.render(w, "download.html", http.StatusOK, d)
}

func (s *Server) handleStatic(name, titleKey, descKey string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.allowAdsCSP(w)
		d := s.basePage(r, titleKey)
		if descKey != "" {
			d.Description = d.T(descKey)
		}
		d.GAID = s.opt.GAMeasurementID
		s.render(w, name, http.StatusOK, d)
	}
}

// failPage reports an error on a navigation request, where a JSON body would
// be shown to the user as raw text.
func (s *Server) failPage(w http.ResponseWriter, r *http.Request, err error) {
	status, msg := statusFor(err)
	if status >= 500 {
		s.log.Error("page failed", "path", r.URL.Path, "err", err)
	}
	d := s.basePage(r, "error.title")
	d.Message = msg
	d.NotFound = errors.Is(err, service.ErrNotFound)
	d.NoIndex = true
	s.render(w, "error.html", status, d)
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	cfg := s.svc.Config()
	st, err := s.svc.Stats(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"files":              st.Files,
		"bytes":              st.Bytes,
		"quotaBytes":         cfg.DiskQuotaBytes,
		"maxFiles":           cfg.MaxFiles,
		"maxTotalBytes":      cfg.MaxTotalBytes,
		"maxDays":            cfg.MaxDays,
		"maxDownloads":       cfg.MaxDownloads,
		"partSize":           cfg.PartSize,
		"sizeAtMinDays":      cfg.SizeAtMinDays,
		"sizeAtMaxDays":      cfg.SizeAtMaxDays,
		"sizeAtMinDownloads": cfg.SizeAtMinDownloads,
		"sizeAtMaxDownloads": cfg.SizeAtMaxDownloads,
	})
}

// humanBytes formats a size the way a person reads it.
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit && exp < 4; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTP"[exp])
}

// jst is the timezone the admin screen renders timestamps in. A fixed offset
// avoids depending on tzdata being present on the host.
var jst = time.FixedZone("JST", 9*3600)

func templateFuncs() template.FuncMap {
	return template.FuncMap{
		"humanBytes": humanBytes,
		"datetime": func(t time.Time) string {
			if t.IsZero() {
				return "—"
			}
			// The label removes any doubt that admin timestamps are Japan time.
			return t.In(jst).Format("2006-01-02 15:04") + " JST"
		},
	}
}

package httpd

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/paps-jp/securefile/internal/i18n"
)

// publicPaths are the pages that should be indexed and listed in the sitemap.
// Everything else — download and legacy pages (their URL carries the share
// key), the admin dashboard, and the API — is kept out of search results.
var publicPaths = []string{"/", "/about", "/faq", "/guide", "/privacy", "/terms", "/abuse"}

// gatedPaths map a path to the catalog key that marks it translated: the sitemap
// lists such a path (and its hreflang alternates) only for languages that have
// the translation, matching how the pages roll out language by language.
var gatedPaths = map[string]string{"/faq": "faq.h1", "/guide": "guide.h1"}

// handleRobots serves robots.txt. It keeps crawlers off the API and the
// key-bearing transfer paths, and points them at the sitemap. Individual
// download pages also carry a noindex tag, since they cannot be matched by a
// path rule.
func (s *Server) handleRobots(w http.ResponseWriter, r *http.Request) {
	base := strings.TrimRight(s.opt.BaseURL, "/")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	fmt.Fprint(w, "User-agent: *\n"+
		"Disallow: /admin\n"+
		"Disallow: /api/\n"+
		"Disallow: /dl/\n"+
		"Disallow: /zip/\n"+
		"Disallow: /ldl/\n"+
		"Disallow: /d/\n"+
		"\n"+
		"Sitemap: "+base+"/sitemap.xml\n")
}

// handleSitemap lists the public pages for search engines, once per language,
// each entry carrying the full set of hreflang alternates so crawlers serve the
// right language and treat the variants as one page.
func (s *Server) handleSitemap(w http.ResponseWriter, r *http.Request) {
	base := strings.TrimRight(s.opt.BaseURL, "/")
	today := time.Now().UTC().Format("2006-01-02")

	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	b.WriteString(`<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" xmlns:xhtml="http://www.w3.org/1999/xhtml">` + "\n")
	for _, p := range publicPaths {
		priority := "0.6"
		if p == "/" {
			priority = "1.0"
		}
		// A gated page is listed only in the languages that have it; an ungated
		// page in every language.
		langs := i18n.Langs
		xdefault := i18n.Default
		if key, gated := gatedPaths[p]; gated {
			langs = s.translatedLangs(key)
			if len(langs) == 0 {
				continue
			}
			xdefault = langs[0].Code
		}
		for _, l := range langs {
			fmt.Fprintf(&b, "  <url><loc>%s%s</loc>\n", base, langPath(l.Code, p))
			for _, alt := range langs {
				fmt.Fprintf(&b, "    <xhtml:link rel=\"alternate\" hreflang=\"%s\" href=\"%s%s\"/>\n",
					alt.Code, base, langPath(alt.Code, p))
			}
			fmt.Fprintf(&b, "    <xhtml:link rel=\"alternate\" hreflang=\"x-default\" href=\"%s%s\"/>\n", base, langPath(xdefault, p))
			fmt.Fprintf(&b, "    <lastmod>%s</lastmod><changefreq>weekly</changefreq><priority>%s</priority></url>\n", today, priority)
		}
	}
	b.WriteString("</urlset>\n")
	w.Write([]byte(b.String()))
}

// translatedLangs returns the languages that have a translation for key, in the
// canonical order, so a gated page appears only where it actually reads.
func (s *Server) translatedLangs(key string) []i18n.Lang {
	var out []i18n.Lang
	for _, l := range i18n.Langs {
		if s.i18n.Has(l.Code, key) {
			out = append(out, l)
		}
	}
	return out
}

// handleManifest serves a Web App Manifest so the site can be installed to a
// phone's home screen or the desktop. Name and description follow the active
// language, so an installed icon reads in the visitor's own language.
func (s *Server) handleManifest(w http.ResponseWriter, r *http.Request) {
	lang := s.lang(r)
	name := s.i18n.T(lang, "brand.name")
	desc := s.i18n.T(lang, "index.description")
	start := langPath(lang, "/") + "?src=pwa"

	w.Header().Set("Content-Type", "application/manifest+json; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	fmt.Fprintf(w, `{
  "name": %q,
  "short_name": %q,
  "description": %q,
  "lang": %q,
  "dir": %q,
  "start_url": %q,
  "scope": "/",
  "display": "standalone",
  "background_color": "#ffffff",
  "theme_color": "#0e9594",
  "icons": [
    {"src": "/static/icon-192.png", "sizes": "192x192", "type": "image/png", "purpose": "any maskable"},
    {"src": "/static/icon-512.png", "sizes": "512x512", "type": "image/png", "purpose": "any maskable"}
  ]
}`, name, name, desc, lang, i18n.DirOf(lang), start)
}

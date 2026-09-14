package httpd

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"strings"
)

// Content pages (FAQ, how-to guide) are SEO landing pages: they target the
// generic queries the tool itself cannot rank for, and each ships the matching
// structured data. They roll out language by language — a page is live in a
// language only once its text is translated, so nothing ever renders as a
// half-translated fallback.

// gatedContent prepares a content page, or redirects to the English version when
// the requested language has no translation yet. It returns ok=false when it has
// already written a redirect.
func (s *Server) gatedContent(w http.ResponseWriter, r *http.Request, sentinel, titleKey, descKey string) (pageData, bool) {
	lang := s.lang(r)
	if !s.i18n.Has(lang, sentinel) && lang != "en" {
		// r.URL.Path is already language-stripped by the middleware.
		http.Redirect(w, r, langPath("en", r.URL.Path), http.StatusFound)
		return pageData{}, false
	}
	s.allowAdsCSP(w)
	d := s.basePage(r, titleKey)
	d.Description = d.T(descKey)
	d.GAID = s.opt.GAMeasurementID
	// Only advertise language alternates that actually exist for this page.
	s.gateLangs(&d, sentinel)
	return d, true
}

// gateLangs trims the language alternates to those that have this page.
func (s *Server) gateLangs(d *pageData, sentinel string) {
	out := d.LangLinks[:0:0]
	for _, l := range d.LangLinks {
		if s.i18n.Has(l.Code, sentinel) {
			out = append(out, l)
		}
	}
	d.LangLinks = out
}

func (s *Server) handleFAQ(w http.ResponseWriter, r *http.Request) {
	d, ok := s.gatedContent(w, r, "faq.h1", "faq.title", "faq.description")
	if !ok {
		return
	}
	d.FAQ = s.faqItems(d.Lang)
	d.StructuredData = s.faqJSONLD(d.Lang, d.FAQ)
	s.render(w, "faq.html", http.StatusOK, d)
}

func (s *Server) handleGuide(w http.ResponseWriter, r *http.Request) {
	d, ok := s.gatedContent(w, r, "guide.h1", "guide.title", "guide.description")
	if !ok {
		return
	}
	d.Steps = s.howSteps(d.Lang)
	d.StructuredData = s.howToJSONLD(d.Lang, d.Steps)
	s.render(w, "guide.html", http.StatusOK, d)
}

// faqItems reads the numbered FAQ keys for a language until one is missing, so
// the count is data-driven rather than hard-coded.
func (s *Server) faqItems(lang string) []faqItem {
	var out []faqItem
	for i := 1; ; i++ {
		qk := fmt.Sprintf("faq.q%d", i)
		if !s.i18n.Has(lang, qk) {
			break
		}
		out = append(out, faqItem{Q: s.i18n.T(lang, qk), A: s.i18n.T(lang, fmt.Sprintf("faq.a%d", i))})
	}
	return out
}

// howSteps reads the numbered guide steps for a language.
func (s *Server) howSteps(lang string) []howStep {
	var out []howStep
	for i := 1; ; i++ {
		nk := fmt.Sprintf("guide.step%d_name", i)
		if !s.i18n.Has(lang, nk) {
			break
		}
		out = append(out, howStep{Name: s.i18n.T(lang, nk), Text: s.i18n.T(lang, fmt.Sprintf("guide.step%d_text", i))})
	}
	return out
}

// breadcrumb builds a two-level BreadcrumbList (home → page) node.
func (s *Server) breadcrumb(lang, path, name string) map[string]any {
	base := strings.TrimRight(s.opt.BaseURL, "/")
	return map[string]any{
		"@type": "BreadcrumbList",
		"itemListElement": []map[string]any{
			{"@type": "ListItem", "position": 1, "name": s.i18n.T(lang, "brand.name"), "item": base + langPath(lang, "/")},
			{"@type": "ListItem", "position": 2, "name": name, "item": base + langPath(lang, path)},
		},
	}
}

// faqJSONLD emits FAQPage + BreadcrumbList built from the same items shown on the
// page, so the structured data always matches the visible text.
func (s *Server) faqJSONLD(lang string, items []faqItem) template.HTML {
	base := strings.TrimRight(s.opt.BaseURL, "/")
	ents := make([]map[string]any, 0, len(items))
	for _, it := range items {
		ents = append(ents, map[string]any{
			"@type":          "Question",
			"name":           it.Q,
			"acceptedAnswer": map[string]any{"@type": "Answer", "text": it.A},
		})
	}
	graph := []map[string]any{
		{"@type": "FAQPage", "@id": base + langPath(lang, "/faq") + "#faq", "inLanguage": lang, "mainEntity": ents},
		s.breadcrumb(lang, "/faq", s.i18n.T(lang, "faq.h1")),
	}
	return ldScript(map[string]any{"@context": "https://schema.org", "@graph": graph})
}

// howToJSONLD emits HowTo + BreadcrumbList for the guide.
func (s *Server) howToJSONLD(lang string, steps []howStep) template.HTML {
	base := strings.TrimRight(s.opt.BaseURL, "/")
	stepNodes := make([]map[string]any, 0, len(steps))
	for i, st := range steps {
		stepNodes = append(stepNodes, map[string]any{
			"@type": "HowToStep", "position": i + 1, "name": st.Name, "text": st.Text,
		})
	}
	graph := []map[string]any{
		{
			"@type":      "HowTo",
			"@id":        base + langPath(lang, "/guide") + "#howto",
			"name":       s.i18n.T(lang, "guide.h1"),
			"inLanguage": lang,
			"step":       stepNodes,
		},
		s.breadcrumb(lang, "/guide", s.i18n.T(lang, "guide.h1")),
	}
	return ldScript(map[string]any{"@context": "https://schema.org", "@graph": graph})
}

// ldScript marshals a JSON-LD document into a script tag. application/ld+json is
// data, not executable, so the strict CSP allows it.
func ldScript(doc any) template.HTML {
	b, err := json.Marshal(doc)
	if err != nil {
		return ""
	}
	return template.HTML(`<script type="application/ld+json">` + string(b) + `</script>`)
}

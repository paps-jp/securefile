// Package i18n holds the message catalog and language metadata for the site.
//
// Japanese is the source language and the default (served at the site root);
// the other languages live behind a path prefix (/en, /ko, …), matching the
// scheme used across paps.jp properties. A missing translation falls back to
// Japanese, then to the raw key, so a page never renders blank while a
// translation is being filled in.
package i18n

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"strings"
)

// Lang describes a supported language.
type Lang struct {
	Code string // BCP-47-ish code and URL prefix (e.g. "en"); "ja" is the default
	Name string // endonym, for the language switcher
	Dir  string // "ltr" or "rtl"
}

// Langs are the supported languages. Japanese is first (the default); the rest
// follow the order used in the shared language switcher.
var Langs = []Lang{
	{"ja", "日本語", "ltr"},
	{"en", "English", "ltr"},
	{"ko", "한국어", "ltr"},
	{"zh", "中文", "ltr"},
	{"ru", "Русский", "ltr"},
	{"ar", "العربية", "rtl"},
	{"hi", "हिन्दी", "ltr"},
	{"es", "Español", "ltr"},
	{"bn", "বাংলা", "ltr"},
	{"pt", "Português", "ltr"},
	{"id", "Indonesia", "ltr"},
}

// Default is the source language and the one served without a path prefix.
const Default = "ja"

// IsSupported reports whether code is one of the supported languages.
func IsSupported(code string) bool {
	for _, l := range Langs {
		if l.Code == code {
			return true
		}
	}
	return false
}

// DirOf returns the text direction for a language code.
func DirOf(code string) string {
	for _, l := range Langs {
		if l.Code == code {
			return l.Dir
		}
	}
	return "ltr"
}

// Catalog holds translations: language code -> message key -> text.
type Catalog struct {
	m map[string]map[string]string
}

// Load reads i18n/<code>.json for every supported language from fsys.
func Load(fsys fs.FS) (*Catalog, error) {
	c := &Catalog{m: make(map[string]map[string]string)}
	for _, l := range Langs {
		b, err := fs.ReadFile(fsys, "i18n/"+l.Code+".json")
		if err != nil {
			return nil, fmt.Errorf("i18n: read %s: %w", l.Code, err)
		}
		var msgs map[string]string
		if err := json.Unmarshal(b, &msgs); err != nil {
			return nil, fmt.Errorf("i18n: parse %s: %w", l.Code, err)
		}
		c.m[l.Code] = msgs
	}
	return c, nil
}

// T returns the translation of key in lang, falling back to Japanese and then
// to the key itself.
func (c *Catalog) T(lang, key string) string {
	// A key present in the language wins even when its value is empty: some
	// strings (e.g. a counter suffix) are intentionally blank in some languages.
	// Only a key absent from the language falls back to Japanese.
	if m, ok := c.m[lang]; ok {
		if v, ok := m[key]; ok {
			return v
		}
	}
	if m, ok := c.m[Default]; ok {
		if v, ok := m[key]; ok {
			return v
		}
	}
	return key
}

// Prefixed returns every message whose key starts with prefix, translated into
// lang, with the prefix stripped from the returned keys. Keys are enumerated
// from the source language so the set is complete regardless of what lang has
// filled in. Used to hand the browser its JavaScript strings.
func (c *Catalog) Prefixed(lang, prefix string) map[string]string {
	out := make(map[string]string)
	for k := range c.m[Default] {
		if strings.HasPrefix(k, prefix) {
			out[strings.TrimPrefix(k, prefix)] = c.T(lang, k)
		}
	}
	return out
}

// Has reports whether lang has a non-empty translation for key.
func (c *Catalog) Has(lang, key string) bool {
	m, ok := c.m[lang]
	if !ok {
		return false
	}
	v, ok := m[key]
	return ok && v != ""
}

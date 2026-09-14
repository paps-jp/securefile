#include "common.h"
#include "resource.h"
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>

// --- growable byte buffer --------------------------------------------------

void buf_init(buf_t *b) { b->data = NULL; b->len = 0; b->cap = 0; }

void buf_free(buf_t *b) {
    free(b->data);
    b->data = NULL; b->len = 0; b->cap = 0;
}

static int buf_reserve(buf_t *b, size_t extra) {
    if (b->len + extra + 1 <= b->cap) return 1;
    size_t ncap = b->cap ? b->cap : 256;
    while (b->len + extra + 1 > ncap) ncap *= 2;
    char *nd = (char *)realloc(b->data, ncap);
    if (!nd) return 0;
    b->data = nd; b->cap = ncap;
    return 1;
}

int buf_append(buf_t *b, const void *p, size_t n) {
    if (!buf_reserve(b, n)) return 0;
    memcpy(b->data + b->len, p, n);
    b->len += n;
    b->data[b->len] = '\0';
    return 1;
}

int buf_appends(buf_t *b, const char *s) { return buf_append(b, s, strlen(s)); }

int buf_appendf(buf_t *b, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int need = _vscprintf(fmt, ap);
    va_end(ap);
    if (need < 0) return 0;
    if (!buf_reserve(b, (size_t)need)) return 0;
    va_start(ap, fmt);
    vsnprintf(b->data + b->len, b->cap - b->len, fmt, ap);
    va_end(ap);
    b->len += (size_t)need;
    b->data[b->len] = '\0';
    return 1;
}

int buf_append_json_escaped(buf_t *b, const char *s) {
    static const char *hex = "0123456789abcdef";
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        unsigned char c = *p;
        switch (c) {
            case '"':  if (!buf_appends(b, "\\\"")) return 0; break;
            case '\\': if (!buf_appends(b, "\\\\")) return 0; break;
            case '\n': if (!buf_appends(b, "\\n")) return 0; break;
            case '\r': if (!buf_appends(b, "\\r")) return 0; break;
            case '\t': if (!buf_appends(b, "\\t")) return 0; break;
            default:
                if (c < 0x20) {
                    char esc[7] = { '\\','u','0','0', hex[(c>>4)&0xf], hex[c&0xf], 0 };
                    if (!buf_appends(b, esc)) return 0;
                } else {
                    if (!buf_append(b, &c, 1)) return 0; // UTF-8 bytes pass through
                }
        }
    }
    return 1;
}

// --- text conversion -------------------------------------------------------

wchar_t *utf8_to_wide(const char *s, int len) {
    int n = MultiByteToWideChar(CP_UTF8, 0, s, len, NULL, 0);
    if (n <= 0) { wchar_t *e = (wchar_t *)malloc(sizeof(wchar_t)); if (e) e[0]=0; return e; }
    wchar_t *w = (wchar_t *)malloc((size_t)(n + 1) * sizeof(wchar_t));
    if (!w) return NULL;
    MultiByteToWideChar(CP_UTF8, 0, s, len, w, n);
    w[n] = 0;
    return w;
}

char *wide_to_utf8(const wchar_t *w, int len) {
    int n = WideCharToMultiByte(CP_UTF8, 0, w, len, NULL, 0, NULL, NULL);
    if (n <= 0) { char *e = (char *)malloc(1); if (e) e[0]=0; return e; }
    char *s = (char *)malloc((size_t)n + 1);
    if (!s) return NULL;
    WideCharToMultiByte(CP_UTF8, 0, w, len, s, n, NULL, NULL);
    s[n] = 0;
    return s;
}

// --- minimal JSON reads ----------------------------------------------------
//
// These are not a general JSON parser; they scan for "key" and read the value
// that follows. That is safe here because every JSON they read is produced by
// this project (the service's API, or this client's own page), where the keys
// they look for appear before any array of user-controlled strings.

static const char *find_key(const char *json, const char *key) {
    size_t klen = strlen(key);
    char needle[128];
    if (klen + 3 >= sizeof(needle)) return NULL;
    needle[0] = '"';
    memcpy(needle + 1, key, klen);
    needle[1 + klen] = '"';
    needle[2 + klen] = '\0';
    const char *p = strstr(json, needle);
    if (!p) return NULL;
    p += klen + 2;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    if (*p != ':') return NULL;
    p++;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    return p;
}

int json_find_string(const char *json, const char *key, char *out, size_t outsz) {
    const char *p = find_key(json, key);
    if (!p || *p != '"') return 0;
    p++;
    size_t o = 0;
    while (*p && *p != '"') {
        char c = *p++;
        if (c == '\\' && *p) {
            char e = *p++;
            switch (e) {
                case 'n': c = '\n'; break;
                case 'r': c = '\r'; break;
                case 't': c = '\t'; break;
                case 'u': {
                    // Decode \uXXXX into UTF-8 (enough for the values we read).
                    if (p[0] && p[1] && p[2] && p[3]) {
                        int v = 0;
                        for (int i = 0; i < 4; i++) {
                            char h = p[i]; v <<= 4;
                            if (h >= '0' && h <= '9') v |= h - '0';
                            else if (h >= 'a' && h <= 'f') v |= h - 'a' + 10;
                            else if (h >= 'A' && h <= 'F') v |= h - 'A' + 10;
                        }
                        p += 4;
                        if (v < 0x80) { if (o+1 < outsz) out[o++] = (char)v; }
                        else if (v < 0x800) {
                            if (o+2 < outsz) { out[o++] = (char)(0xC0 | (v>>6)); out[o++] = (char)(0x80 | (v&0x3F)); }
                        } else {
                            if (o+3 < outsz) { out[o++] = (char)(0xE0 | (v>>12)); out[o++] = (char)(0x80 | ((v>>6)&0x3F)); out[o++] = (char)(0x80 | (v&0x3F)); }
                        }
                        continue;
                    }
                    c = e;
                    break;
                }
                default: c = e; break;
            }
        }
        if (o + 1 < outsz) out[o++] = c;
    }
    out[o] = '\0';
    return 1;
}

int json_find_int64(const char *json, const char *key, long long *out) {
    const char *p = find_key(json, key);
    if (!p) return 0;
    char *end = NULL;
    long long v = _strtoi64(p, &end, 10);
    if (end == p) return 0;
    *out = v;
    return 1;
}

int json_find_bool(const char *json, const char *key, int *out) {
    const char *p = find_key(json, key);
    if (!p) return 0;
    if (strncmp(p, "true", 4) == 0) { *out = 1; return 1; }
    if (strncmp(p, "false", 5) == 0) { *out = 0; return 1; }
    return 0;
}

// --- embedded assets -------------------------------------------------------

int asset_lookup(const char *path, const void **data, DWORD *len, const char **ctype) {
    struct { const char *path; int id; const char *ctype; } table[] = {
        { "/",          IDR_SEND_HTML, "text/html; charset=utf-8" },
        { "/index.html",IDR_SEND_HTML, "text/html; charset=utf-8" },
        { "/app.css",   IDR_APP_CSS,   "text/css; charset=utf-8" },
        { "/send.js",   IDR_SEND_JS,   "text/javascript; charset=utf-8" },
        { "/qrcode.js", IDR_QRCODE_JS, "text/javascript; charset=utf-8" },
        { "/logo.svg",  IDR_LOGO_SVG,  "image/svg+xml" },
    };
    for (size_t i = 0; i < sizeof(table)/sizeof(table[0]); i++) {
        if (strcmp(path, table[i].path) == 0) {
            HRSRC r = FindResourceW(NULL, MAKEINTRESOURCEW(table[i].id), RT_RCDATA);
            if (!r) return 0;
            HGLOBAL h = LoadResource(NULL, r);
            if (!h) return 0;
            *data = LockResource(h);
            *len  = SizeofResource(NULL, r);
            *ctype = table[i].ctype;
            return 1;
        }
    }
    return 0;
}

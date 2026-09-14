// A tiny loopback HTTP server: it serves the embedded page to the browser and
// exposes two endpoints the page calls back on — /api/files (what to send) and
// /api/send (do it, streaming progress). It binds 127.0.0.1 on an ephemeral
// port and every /api call must carry the one-time token the helper put in the
// page URL, so nothing else on the machine can drive it.
#include "common.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#pragma comment(lib, "ws2_32.lib")

#define IDLE_EXIT_MS 300000   // exit after 5 min with no activity
#define HDR_MAX      16384

static volatile LONG      g_sending = 0;
static volatile ULONGLONG g_last_activity = 0;

static void touch(void) { g_last_activity = GetTickCount64(); }

static int send_all(SOCKET s, const char *p, int n) {
    while (n > 0) {
        int w = send(s, p, n, 0);
        if (w <= 0) return 0;
        p += w; n -= w;
    }
    return 1;
}

static void send_simple(SOCKET s, int code, const char *status, const char *ctype, const char *body, int blen) {
    char hdr[512];
    int h = _snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %d\r\n"
        "Cache-Control: no-store\r\nConnection: close\r\n\r\n",
        code, status, ctype, blen);
    send_all(s, hdr, h);
    if (body && blen > 0) send_all(s, body, blen);
}

// Write one HTTP chunk (for Transfer-Encoding: chunked).
static int send_chunk(SOCKET s, const char *p, int n) {
    char h[16];
    int hn = _snprintf(h, sizeof(h), "%x\r\n", n);
    if (!send_all(s, h, hn)) return 0;
    if (n > 0 && !send_all(s, p, n)) return 0;
    return send_all(s, "\r\n", 2);
}

// --- query / body helpers --------------------------------------------------

// Extract the value of query parameter name from a raw query string.
static int query_get(const char *query, const char *name, char *out, size_t outsz) {
    size_t nl = strlen(name);
    const char *p = query;
    while (p && *p) {
        const char *amp = strchr(p, '&');
        const char *eq = strchr(p, '=');
        if (eq && (!amp || eq < amp) && (size_t)(eq - p) == nl && strncmp(p, name, nl) == 0) {
            const char *v = eq + 1;
            const char *end = amp ? amp : v + strlen(v);
            size_t o = 0;
            while (v < end && o + 1 < outsz) {
                if (*v == '%' && v + 2 < end) {
                    int hi = v[1], lo = v[2];
                    #define HEX(c) ((c)>='0'&&(c)<='9'?(c)-'0':((c)|32)>='a'&&((c)|32)<='f'?((c)|32)-'a'+10:-1)
                    int a = HEX(hi), b = HEX(lo);
                    if (a >= 0 && b >= 0) { out[o++] = (char)(a * 16 + b); v += 3; continue; }
                    #undef HEX
                }
                out[o++] = (*v == '+') ? ' ' : *v;
                v++;
            }
            out[o] = 0;
            return 1;
        }
        p = amp ? amp + 1 : NULL;
    }
    return 0;
}

static int token_ok(const server_ctx_t *ctx, const char *query) {
    char t[256];
    if (!query_get(query, "t", t, sizeof(t))) return 0;
    return strcmp(t, ctx->token) == 0;
}

// Parse "indices":[a,b,c] into out (up to max). Returns count.
static int parse_indices(const char *body, int *out, int max) {
    const char *p = strstr(body, "\"indices\"");
    if (!p) return 0;
    p = strchr(p, '[');
    if (!p) return 0;
    p++;
    int n = 0;
    while (n < max) {
        while (*p == ' ' || *p == ',' || *p == '\t' || *p == '\r' || *p == '\n') p++;
        if (*p == ']' || *p == 0) break;
        char *e;
        long v = strtol(p, &e, 10);
        if (e == p) break;
        out[n++] = (int)v;
        p = e;
    }
    return n;
}

// --- /api/send -------------------------------------------------------------

typedef struct { SOCKET s; ULONGLONG last_paint; int aborted; long long total; } sendstate_t;

static int on_progress(void *ud, long long sent, long long total) {
    sendstate_t *st = (sendstate_t *)ud;
    ULONGLONG now = GetTickCount64();
    // Throttle: paint at most ~6x/sec, but always let the final 100% through.
    if (sent < total && now - st->last_paint < 150) return 0;
    st->last_paint = now;
    char line[128];
    int n = _snprintf(line, sizeof(line), "{\"type\":\"progress\",\"sent\":%lld,\"total\":%lld}\n", sent, total);
    if (!send_chunk(st->s, line, n)) { st->aborted = 1; return 1; }
    return 0;
}

static void handle_send(const server_ctx_t *ctx, SOCKET s, const char *body) {
    // Options from the page.
    long long days = 7, maxdl = 5;
    int allow = 0;
    char password[256] = {0};
    json_find_int64(body, "days", &days);
    json_find_int64(body, "maxDownloads", &maxdl);
    json_find_bool(body, "allowDelete", &allow);
    json_find_string(body, "password", password, sizeof(password));

    int idx[256];
    int nidx = parse_indices(body, idx, 256);

    // Resolve indices to files.
    upfile_t sel[256];
    int nsel = 0;
    for (int i = 0; i < nidx; i++) {
        if (idx[i] >= 0 && idx[i] < ctx->nfiles) sel[nsel++] = ctx->files[idx[i]];
    }
    if (nsel == 0) { send_simple(s, 400, "Bad Request", "text/plain", "no files", 8); return; }

    InterlockedExchange(&g_sending, 1);

    // Start a chunked response; every progress line and the final result is a chunk.
    const char *head =
        "HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson; charset=utf-8\r\n"
        "Cache-Control: no-store\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n";
    send_all(s, head, (int)strlen(head));

    sendstate_t st = { s, 0, 0, 0 };
    upresult_t res;
    char err[256] = {0};
    int rc = upload_run(ctx->backend, sel, nsel, (int)days, (int)maxdl, password, allow,
                        on_progress, &st, &res, err, sizeof(err));

    if (!st.aborted) {
        buf_t line; buf_init(&line);
        if (rc == 0) {
            buf_appendf(&line, "{\"type\":\"done\",\"shareUrl\":\"");
            buf_append_json_escaped(&line, res.share_url);
            buf_appends(&line, "\",\"key\":\"");
            buf_append_json_escaped(&line, res.key);
            buf_appends(&line, "\",\"expiresAt\":\"");
            buf_append_json_escaped(&line, res.expires_at);
            buf_appends(&line, "\"}\n");
        } else {
            buf_appends(&line, "{\"type\":\"error\",\"message\":\"");
            buf_append_json_escaped(&line, err[0] ? err : "アップロードに失敗しました。");
            buf_appends(&line, "\"}\n");
        }
        send_chunk(s, line.data, (int)line.len);
        buf_free(&line);
    }
    send_all(s, "0\r\n\r\n", 5); // terminating chunk

    InterlockedExchange(&g_sending, 0);
    touch();
}

// --- /api/files ------------------------------------------------------------

static void handle_files(const server_ctx_t *ctx, SOCKET s) {
    buf_t b; buf_init(&b);
    buf_appends(&b, "{\"files\":[");
    for (int i = 0; i < ctx->nfiles; i++) {
        if (i) buf_appends(&b, ",");
        buf_appends(&b, "{\"name\":\"");
        buf_append_json_escaped(&b, ctx->files[i].name);
        buf_appendf(&b, "\",\"size\":%lld}", ctx->files[i].size);
    }
    buf_appends(&b, "],\"limits\":");
    buf_appends(&b, ctx->limits_json && ctx->limits_json[0] ? ctx->limits_json : "null");
    buf_appends(&b, "}");
    send_simple(s, 200, "OK", "application/json; charset=utf-8", b.data, (int)b.len);
    buf_free(&b);
}

// --- connection ------------------------------------------------------------

typedef struct { const server_ctx_t *ctx; SOCKET s; } conn_t;

static DWORD WINAPI handle_conn(LPVOID arg) {
    conn_t *c = (conn_t *)arg;
    SOCKET s = c->s;
    const server_ctx_t *ctx = c->ctx;
    free(c);
    touch();

    char *buf = (char *)malloc(HDR_MAX + 1);
    if (!buf) { closesocket(s); return 0; }
    int total = 0, header_end = -1;
    // Read until end of headers.
    while (total < HDR_MAX) {
        int r = recv(s, buf + total, HDR_MAX - total, 0);
        if (r <= 0) break;
        total += r;
        buf[total] = 0;
        char *p = strstr(buf, "\r\n\r\n");
        if (p) { header_end = (int)(p - buf) + 4; break; }
    }
    if (header_end < 0) { free(buf); closesocket(s); return 0; }

    // Request line: METHOD SP PATH SP HTTP/x
    char method[8] = {0}, rawpath[2048] = {0};
    sscanf(buf, "%7s %2047s", method, rawpath);
    char *query = strchr(rawpath, '?');
    if (query) { *query = 0; query++; } else { query = ""; }

    // Content-Length (case-insensitive search on the header block).
    long clen = 0;
    for (char *h = buf; h < buf + header_end; h++) {
        if ((h[0] == 'C' || h[0] == 'c') && _strnicmp(h, "Content-Length:", 15) == 0) {
            clen = strtol(h + 15, NULL, 10);
            break;
        }
    }

    // Read the body (POST). Whatever came after the header terminator counts.
    buf_t body; buf_init(&body);
    if (clen > 0) {
        int have = total - header_end;
        if (have > 0) buf_append(&body, buf + header_end, have);
        while ((long)body.len < clen) {
            char tmp[8192];
            int r = recv(s, tmp, sizeof(tmp), 0);
            if (r <= 0) break;
            buf_append(&body, tmp, r);
        }
    }

    // Route.
    if (strcmp(method, "GET") == 0) {
        const void *data; DWORD len; const char *ctype;
        if (strcmp(rawpath, "/api/files") == 0) {
            if (token_ok(ctx, query)) handle_files(ctx, s);
            else send_simple(s, 403, "Forbidden", "text/plain", "no", 2);
        } else if (asset_lookup(rawpath, &data, &len, &ctype)) {
            char hdr[512];
            int h = _snprintf(hdr, sizeof(hdr),
                "HTTP/1.1 200 OK\r\nContent-Type: %s\r\nContent-Length: %lu\r\n"
                "Cache-Control: no-store\r\nConnection: close\r\n\r\n", ctype, len);
            send_all(s, hdr, h);
            send_all(s, (const char *)data, (int)len);
        } else {
            send_simple(s, 404, "Not Found", "text/plain", "not found", 9);
        }
    } else if (strcmp(method, "POST") == 0) {
        if (strcmp(rawpath, "/api/send") == 0) {
            if (token_ok(ctx, query)) handle_send(ctx, s, body.data ? body.data : "");
            else send_simple(s, 403, "Forbidden", "text/plain", "no", 2);
        } else if (strcmp(rawpath, "/api/quit") == 0) {
            if (token_ok(ctx, query)) { send_simple(s, 204, "No Content", "text/plain", "", 0); ExitProcess(0); }
            else send_simple(s, 403, "Forbidden", "text/plain", "no", 2);
        } else {
            send_simple(s, 404, "Not Found", "text/plain", "not found", 9);
        }
    } else {
        send_simple(s, 405, "Method Not Allowed", "text/plain", "no", 2);
    }

    buf_free(&body);
    free(buf);
    shutdown(s, SD_SEND);
    closesocket(s);
    return 0;
}

static SOCKET g_listen = INVALID_SOCKET;

int server_listen(server_ctx_t *ctx) {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return 0;

    SOCKET ls = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (ls == INVALID_SOCKET) return 0;

    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK); // 127.0.0.1 only
    a.sin_port = 0;                             // ephemeral
    if (bind(ls, (struct sockaddr *)&a, sizeof(a)) != 0) { closesocket(ls); return 0; }
    if (listen(ls, 32) != 0) { closesocket(ls); return 0; }

    int alen = sizeof(a);
    getsockname(ls, (struct sockaddr *)&a, &alen);
    ctx->port = ntohs(a.sin_port);
    g_listen = ls;
    return 1;
}

void server_serve(server_ctx_t *ctx) {
    SOCKET ls = g_listen;
    touch();
    for (;;) {
        fd_set rf; FD_ZERO(&rf); FD_SET(ls, &rf);
        struct timeval tv = { 30, 0 };
        int r = select(0, &rf, NULL, NULL, &tv);
        if (r > 0 && FD_ISSET(ls, &rf)) {
            SOCKET cs = accept(ls, NULL, NULL);
            if (cs == INVALID_SOCKET) continue;
            conn_t *c = (conn_t *)malloc(sizeof(conn_t));
            if (!c) { closesocket(cs); continue; }
            c->ctx = ctx; c->s = cs;
            HANDLE th = CreateThread(NULL, 0, handle_conn, c, 0, NULL);
            if (th) CloseHandle(th); else { closesocket(cs); free(c); }
        } else if (r == 0) {
            if (!g_sending && GetTickCount64() - g_last_activity > IDLE_EXIT_MS) break;
        }
    }
    closesocket(ls);
    WSACleanup();
}

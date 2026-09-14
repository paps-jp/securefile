// Uploads to the securefile service over the same public API the website uses.
//
// Because the service encrypts server-side (the browser sends plaintext parts
// and the password in the start request), this client needs no cryptography of
// its own: it starts a session, streams each file in parts, and finishes.
#include "common.h"
#include <winhttp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#pragma comment(lib, "winhttp.lib")

#define MAX_ATTEMPTS 6
#define BASE_BACKOFF_MS 800

int backend_parse(const wchar_t *url, backend_t *b) {
    memset(b, 0, sizeof(*b));
    URL_COMPONENTS uc;
    memset(&uc, 0, sizeof(uc));
    uc.dwStructSize = sizeof(uc);
    wchar_t host[256], path[256];
    uc.lpszHostName = host; uc.dwHostNameLength = 256;
    uc.lpszUrlPath = path; uc.dwUrlPathLength = 256;
    if (!WinHttpCrackUrl(url, 0, 0, &uc)) return 0;
    lstrcpynW(b->host, host, 256);
    b->port = uc.nPort;
    b->https = (uc.nScheme == INTERNET_SCHEME_HTTPS);
    // A trailing slash-only path is treated as no prefix.
    if (uc.dwUrlPathLength > 0 && !(uc.dwUrlPathLength == 1 && path[0] == L'/'))
        lstrcpynW(b->prefix, path, 256);
    else
        b->prefix[0] = 0;
    return 1;
}

// --- persistent connection -------------------------------------------------

typedef struct {
    HINTERNET session;
    HINTERNET connect;
    const backend_t *b;
} httpc_t;

static int httpc_open(httpc_t *c, const backend_t *b) {
    memset(c, 0, sizeof(*c));
    c->b = b;
    c->session = WinHttpOpen(SFS_USER_AGENT, WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                             WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!c->session) return 0;
    WinHttpSetTimeouts(c->session, 20000, 20000, 600000, 600000);
    c->connect = WinHttpConnect(c->session, b->host, b->port, 0);
    if (!c->connect) { WinHttpCloseHandle(c->session); c->session = NULL; return 0; }
    return 1;
}

static void httpc_close(httpc_t *c) {
    if (c->connect) WinHttpCloseHandle(c->connect);
    if (c->session) WinHttpCloseHandle(c->session);
    c->connect = c->session = NULL;
}

// Perform one request on the pooled connection. status is set to the HTTP status
// (0 on a transport failure). Optional response body and one response header are
// returned. Returns 1 if a response was received, 0 on transport failure.
static int httpc_request(httpc_t *c, const wchar_t *verb, const wchar_t *path,
                         const wchar_t *headers, const void *body, DWORD bodylen,
                         DWORD *status, buf_t *respBody,
                         const wchar_t *wantHeader, wchar_t *headerVal, DWORD headerValChars) {
    *status = 0;
    DWORD flags = c->b->https ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET req = WinHttpOpenRequest(c->connect, verb, path, NULL,
                                       WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!req) return 0;

    int ok = 0;
    DWORD hlen = (headers && headers[0]) ? (DWORD)-1 : 0;
    if (!WinHttpSendRequest(req,
                            hlen ? headers : WINHTTP_NO_ADDITIONAL_HEADERS, hlen,
                            (LPVOID)body, bodylen, bodylen, 0))
        goto done;
    if (!WinHttpReceiveResponse(req, NULL)) goto done;

    DWORD code = 0, sz = sizeof(code);
    if (!WinHttpQueryHeaders(req, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                             WINHTTP_HEADER_NAME_BY_INDEX, &code, &sz, WINHTTP_NO_HEADER_INDEX))
        goto done;
    *status = code;

    if (wantHeader && headerVal && headerValChars) {
        headerVal[0] = 0;
        DWORD vch = headerValChars * sizeof(wchar_t);
        WinHttpQueryHeaders(req, WINHTTP_QUERY_CUSTOM, wantHeader, headerVal, &vch, WINHTTP_NO_HEADER_INDEX);
    }

    if (respBody) {
        for (;;) {
            DWORD avail = 0;
            if (!WinHttpQueryDataAvailable(req, &avail)) break;
            if (avail == 0) break;
            char *tmp = (char *)malloc(avail);
            if (!tmp) break;
            DWORD got = 0;
            if (WinHttpReadData(req, tmp, avail, &got) && got > 0)
                buf_append(respBody, tmp, got);
            free(tmp);
            if (got == 0) break;
        }
    }
    ok = 1;

done:
    WinHttpCloseHandle(req);
    return ok;
}

static int is_transient(DWORD status) {
    return status == 0 || status == 408 || status >= 500;
}

int backend_status(const backend_t *b, buf_t *out) {
    httpc_t c;
    if (!httpc_open(&c, b)) return 0;
    wchar_t path[300];
    swprintf(path, 300, L"%s/api/status", b->prefix);
    DWORD status = 0;
    int ok = httpc_request(&c, L"GET", path, NULL, NULL, 0, &status, out, NULL, NULL, 0);
    httpc_close(&c);
    return ok && status == 200;
}

static int parse_file_ids(const char *json, long long *ids, int max) {
    const char *p = strstr(json, "\"files\"");
    if (!p) return 0;
    p = strchr(p, '[');
    if (!p) return 0;
    const char *end = strchr(p, ']');
    int n = 0;
    const char *q = p;
    while (n < max) {
        const char *idp = strstr(q, "\"id\"");
        if (!idp || (end && idp > end)) break;
        idp += 4;
        while (*idp == ' ' || *idp == ':' || *idp == '\t') idp++;
        char *e;
        long long v = _strtoi64(idp, &e, 10);
        if (e == idp) break;
        ids[n++] = v;
        q = e;
    }
    return n;
}

int upload_run(const backend_t *b,
               const upfile_t *files, int nfiles,
               int days, int max_downloads, const char *password, int allow_delete,
               progress_cb prog, void *ud,
               upresult_t *res, char *errmsg, size_t errmsg_sz) {
    httpc_t c;
    memset(res, 0, sizeof(*res));
    if (errmsg && errmsg_sz) errmsg[0] = 0;
    if (!httpc_open(&c, b)) {
        if (errmsg) strncpy(errmsg, "サーバーに接続できませんでした。", errmsg_sz - 1);
        return 1;
    }

    // --- start session ------------------------------------------------------
    buf_t start; buf_init(&start);
    buf_appends(&start, "{\"files\":[");
    long long grand = 0;
    for (int i = 0; i < nfiles; i++) {
        if (i) buf_appends(&start, ",");
        buf_appends(&start, "{\"name\":\"");
        buf_append_json_escaped(&start, files[i].name);
        buf_appendf(&start, "\",\"size\":%lld}", files[i].size);
        grand += files[i].size;
    }
    buf_appendf(&start, "],\"days\":%d,\"maxDownloads\":%d,\"password\":\"", days, max_downloads);
    buf_append_json_escaped(&start, password);
    buf_appendf(&start, "\",\"allowDelete\":%s}", allow_delete ? "true" : "false");

    wchar_t path[400];
    swprintf(path, 400, L"%s/api/uploads", b->prefix);
    DWORD status = 0;
    buf_t resp; buf_init(&resp);
    int got = httpc_request(&c, L"POST", path, L"Content-Type: application/json",
                            start.data, (DWORD)start.len, &status, &resp, NULL, NULL, 0);
    buf_free(&start);
    if (!got || status != 201) {
        if (errmsg) {
            char msg[256] = {0};
            if (resp.data && json_find_string(resp.data, "error", msg, sizeof(msg)))
                strncpy(errmsg, msg, errmsg_sz - 1);
            else
                _snprintf(errmsg, errmsg_sz - 1, "アップロードを開始できませんでした (%lu)。", status);
        }
        buf_free(&resp); httpc_close(&c); return 1;
    }

    char sid[128] = {0}, token[256] = {0};
    long long partSize = 8 << 20;
    json_find_string(resp.data, "sessionId", sid, sizeof(sid));
    json_find_string(resp.data, "token", token, sizeof(token));
    json_find_int64(resp.data, "partSize", &partSize);
    long long *ids = (long long *)calloc(nfiles > 0 ? nfiles : 1, sizeof(long long));
    int nids = parse_file_ids(resp.data, ids, nfiles);
    buf_free(&resp);
    if (!sid[0] || !token[0] || nids != nfiles || partSize <= 0) {
        if (errmsg) strncpy(errmsg, "サーバー応答が不正です。", errmsg_sz - 1);
        free(ids); httpc_close(&c); return 1;
    }

    wchar_t *wtoken = utf8_to_wide(token, -1);
    char *part = (char *)malloc((size_t)partSize);
    if (!part || !wtoken) {
        if (errmsg) strncpy(errmsg, "メモリを確保できませんでした。", errmsg_sz - 1);
        free(part); free(wtoken); free(ids); httpc_close(&c); return 1;
    }

    // --- send each file in parts -------------------------------------------
    long long completed = 0;
    int failed = 0;
    for (int i = 0; i < nfiles && !failed; i++) {
        HANDLE fh = CreateFileW(files[i].path, GENERIC_READ, FILE_SHARE_READ, NULL,
                                OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
        if (fh == INVALID_HANDLE_VALUE) {
            if (errmsg) _snprintf(errmsg, errmsg_sz - 1, "ファイルを開けませんでした：%s", files[i].name);
            failed = 1; break;
        }

        long long offset = 0;
        int attempts = 0;
        while (offset < files[i].size) {
            LARGE_INTEGER li; li.QuadPart = offset;
            SetFilePointerEx(fh, li, NULL, FILE_BEGIN);
            DWORD want = (DWORD)((files[i].size - offset < partSize) ? (files[i].size - offset) : partSize);
            DWORD nread = 0;
            if (!ReadFile(fh, part, want, &nread, NULL) || nread == 0) {
                if (errmsg) _snprintf(errmsg, errmsg_sz - 1, "ファイルを読み取れませんでした：%s", files[i].name);
                failed = 1; break;
            }

            wchar_t hdr[512];
            swprintf(hdr, 512,
                     L"Authorization: Bearer %s\r\nUpload-Offset: %lld\r\nContent-Type: application/octet-stream",
                     wtoken, offset);
            wchar_t ppath[400];
            swprintf(ppath, 400, L"%s/api/uploads/%S/files/%lld", b->prefix, sid, ids[i]);

            wchar_t hval[64] = {0};
            DWORD st = 0;
            int ok = httpc_request(&c, L"PATCH", ppath, hdr, part, nread, &st,
                                   NULL, L"Upload-Offset", hval, 64);

            long long newOffset = offset;
            if (ok && (st == 200 || st == 409)) {
                newOffset = _wtoi64(hval);
                attempts = 0;
            } else if (is_transient(st)) {
                if (++attempts >= MAX_ATTEMPTS) {
                    if (errmsg) strncpy(errmsg, "通信が安定せず、アップロードに失敗しました。", errmsg_sz - 1);
                    failed = 1; break;
                }
                Sleep(BASE_BACKOFF_MS << (attempts - 1));
                continue; // retry the same offset
            } else {
                if (errmsg) _snprintf(errmsg, errmsg_sz - 1, "サーバーに拒否されました (%lu)。", st);
                failed = 1; break;
            }

            if (newOffset <= offset) {
                // No forward progress even after a resync: give up rather than spin.
                if (++attempts >= MAX_ATTEMPTS) {
                    if (errmsg) strncpy(errmsg, "サーバーとの同期に失敗しました。", errmsg_sz - 1);
                    failed = 1; break;
                }
            } else {
                attempts = 0;
            }
            offset = newOffset;
            if (prog && prog(ud, completed + offset, grand)) {
                if (errmsg) strncpy(errmsg, "中止しました。", errmsg_sz - 1);
                failed = 1; break;
            }
        }
        CloseHandle(fh);
        completed += files[i].size;
        if (prog && !failed) prog(ud, completed, grand);
    }

    free(part);
    free(ids);
    free(wtoken);

    if (failed) {
        // Best-effort cancel so the half-written share does not linger.
        wchar_t dpath[400];
        swprintf(dpath, 400, L"%s/api/uploads/%S", b->prefix, sid);
        wchar_t dhdr[320];
        swprintf(dhdr, 320, L"Authorization: Bearer %S", token);
        DWORD st = 0;
        httpc_request(&c, L"DELETE", dpath, dhdr, NULL, 0, &st, NULL, NULL, NULL, 0);
        httpc_close(&c);
        return 1;
    }

    // --- finish -------------------------------------------------------------
    wchar_t fpath[400];
    swprintf(fpath, 400, L"%s/api/uploads/%S/finish", b->prefix, sid);
    wchar_t fhdr[320];
    swprintf(fhdr, 320, L"Authorization: Bearer %S", token);
    buf_t fresp; buf_init(&fresp);
    status = 0;
    got = httpc_request(&c, L"POST", fpath, fhdr, NULL, 0, &status, &fresp, NULL, NULL, 0);
    if (!got || status != 200) {
        if (errmsg) {
            char msg[256] = {0};
            if (fresp.data && json_find_string(fresp.data, "error", msg, sizeof(msg)))
                strncpy(errmsg, msg, errmsg_sz - 1);
            else
                _snprintf(errmsg, errmsg_sz - 1, "最終処理に失敗しました (%lu)。", status);
        }
        buf_free(&fresp); httpc_close(&c); return 1;
    }
    json_find_string(fresp.data, "key", res->key, sizeof(res->key));
    json_find_string(fresp.data, "shareUrl", res->share_url, sizeof(res->share_url));
    json_find_string(fresp.data, "expiresAt", res->expires_at, sizeof(res->expires_at));
    buf_free(&fresp);
    httpc_close(&c);
    return 0;
}

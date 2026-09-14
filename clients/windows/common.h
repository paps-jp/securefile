// Shared declarations for the securefile_send Windows client.
//
// The client is a small native helper with no runtime dependency: it links only
// against system libraries and the static CRT. It has three jobs — register a
// right-click menu entry, collect the file(s) a click selected, and open the
// default browser on a local page that drives the upload to up.paps.jp using the
// service's ordinary public API.
#ifndef SECUREFILE_COMMON_H
#define SECUREFILE_COMMON_H

#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <stdint.h>
#include <stddef.h>

// The fixed loopback port used only to coalesce a multi-file selection: Windows
// launches this .exe once per selected file, and the first instance to bind the
// port collects the paths the others hand it before opening one browser window.
#define SFS_COORD_PORT 47159
#define SFS_COORD_MAGIC "SFS1"

// Default backend, overridable at install time (-backend) and stored in the
// registry under HKCU\Software\SecureFileSend.
#define SFS_DEFAULT_BACKEND L"https://up.paps.jp"

// A browser-like User-Agent: the edge (Cloudflare) blocks obvious script
// clients, and this helper is acting on the user's behalf.
#define SFS_USER_AGENT L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) SecureFileSend/1.0"

// --- growable byte buffer --------------------------------------------------

typedef struct {
    char  *data;
    size_t len;
    size_t cap;
} buf_t;

void buf_init(buf_t *b);
void buf_free(buf_t *b);
int  buf_append(buf_t *b, const void *p, size_t n);   // 1 ok, 0 oom
int  buf_appends(buf_t *b, const char *s);
int  buf_appendf(buf_t *b, const char *fmt, ...);
int  buf_append_json_escaped(buf_t *b, const char *s); // appends escaped chars, no quotes

// --- text conversion (all malloc'd; caller frees) --------------------------

wchar_t *utf8_to_wide(const char *s, int len);   // len<0: nul-terminated
char    *wide_to_utf8(const wchar_t *w, int len); // len<0: nul-terminated

// --- minimal JSON reads (for our own well-formed responses) ----------------

// Find "key": "..." and copy the unescaped value into out. Returns 1 on hit.
int json_find_string(const char *json, const char *key, char *out, size_t outsz);
// Find "key": <number>. Returns 1 on hit.
int json_find_int64(const char *json, const char *key, long long *out);
// Find "key": true|false. Returns 1 on hit (value in *out).
int json_find_bool(const char *json, const char *key, int *out);

// --- embedded assets -------------------------------------------------------

// Look up an embedded UI file by its request path (e.g. "/app.css"). On hit,
// sets *data/*len (pointer into the resource, do not free) and *ctype.
int asset_lookup(const char *path, const void **data, DWORD *len, const char **ctype);

// --- upload (uploader.c) ---------------------------------------------------

typedef struct {
    wchar_t    *path;   // full path on disk
    char       *name;   // base name, UTF-8, for the server
    long long   size;   // bytes
} upfile_t;

typedef struct {
    wchar_t host[256];
    unsigned short port;
    int https;
    wchar_t prefix[256]; // path prefix, usually empty
} backend_t;

int backend_parse(const wchar_t *url, backend_t *b);

// Progress callback: sent/total bytes so far. Return 0 to continue, non-zero to
// abort the transfer.
typedef int (*progress_cb)(void *ud, long long sent, long long total);

typedef struct {
    char key[128];
    char share_url[512];
    char expires_at[64];
} upresult_t;

// Fetch the backend's /api/status JSON (limits) into out. 1 on success.
int backend_status(const backend_t *b, buf_t *out);

// Perform the whole upload: start session, send every file in parts, finish.
// Returns 0 on success and fills *res; on failure returns non-zero and writes a
// UTF-8 message into errmsg.
int upload_run(const backend_t *b,
               const upfile_t *files, int nfiles,
               int days, int max_downloads, const char *password, int allow_delete,
               progress_cb prog, void *ud,
               upresult_t *res, char *errmsg, size_t errmsg_sz);

// --- local HTTP server (httpserver.c) --------------------------------------

typedef struct {
    const upfile_t *files;
    int             nfiles;
    const char     *limits_json; // raw /api/status body, or "null"
    const backend_t*backend;
    const char     *token;       // required on every /api call
    int             port;        // filled in by server_start
} server_ctx_t;

// Bind 127.0.0.1 on an ephemeral port and start listening; fills ctx->port.
// Returns 1 on success.
int server_listen(server_ctx_t *ctx);
// Accept and serve connections until the server has been idle. Blocks. Call
// after server_listen (and after opening the browser at ctx->port).
void server_serve(server_ctx_t *ctx);

// --- registry (registry.c) -------------------------------------------------

int  registry_install(const wchar_t *backend);   // copies self, writes keys
int  registry_uninstall(void);
int  registry_read_backend(wchar_t *out, size_t out_chars); // 1 if found

// --- shared (main.c) -------------------------------------------------------

// Resolve the backend URL: SFS_BACKEND env, else registry, else the default.
void resolve_backend_url(wchar_t *out, size_t chars);

// --- tray app (tray.c) -----------------------------------------------------

// Run the resident system-tray application (no file arguments were given).
// Blocks on a message loop until the user quits. Returns a process exit code.
int run_tray(void);

#endif

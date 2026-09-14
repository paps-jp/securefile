// securefile_send — the Windows right-click client for セキュファイル便.
//
// Flow: Explorer runs this once per selected file (with the path as %1). The
// first instance to claim a fixed loopback port becomes the owner; the others
// hand it their path and exit. The owner then opens the default browser on a
// local page that shows the files and drives the upload.
#include "common.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <bcrypt.h>
#include <shellapi.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "shell32.lib")

#define MAX_FILES     256
#define DEBOUNCE_MS   500

// Collected file paths (wide), guarded by a lock while siblings hand them over.
static wchar_t        *g_paths[MAX_FILES];
static int             g_npaths = 0;
static CRITICAL_SECTION g_lock;

static void add_path(const wchar_t *p) {
    if (!p || !p[0]) return;
    EnterCriticalSection(&g_lock);
    if (g_npaths < MAX_FILES) {
        int dup = 0;
        for (int i = 0; i < g_npaths; i++) if (_wcsicmp(g_paths[i], p) == 0) { dup = 1; break; }
        if (!dup) g_paths[g_npaths++] = _wcsdup(p);
    }
    LeaveCriticalSection(&g_lock);
}

// --- coalescing over the coordination port ---------------------------------

// Sibling: hand our paths to the owner already listening on the coord port.
// Returns 1 if delivered.
static int handoff(wchar_t **paths, int n) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return 0;
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons(SFS_COORD_PORT);
    if (connect(s, (struct sockaddr *)&a, sizeof(a)) != 0) { closesocket(s); return 0; }
    send(s, SFS_COORD_MAGIC "\n", (int)strlen(SFS_COORD_MAGIC) + 1, 0);
    for (int i = 0; i < n; i++) {
        char *u = wide_to_utf8(paths[i], -1);
        if (u) { send(s, u, (int)strlen(u), 0); send(s, "\n", 1, 0); free(u); }
    }
    shutdown(s, SD_SEND);
    char junk[64];
    while (recv(s, junk, sizeof(junk), 0) > 0) {}
    closesocket(s);
    return 1;
}

// Owner: read one sibling connection to EOF and add the paths it sent.
static void read_sibling(SOCKET cs) {
    buf_t b; buf_init(&b);
    char tmp[4096];
    int r;
    while ((r = recv(cs, tmp, sizeof(tmp), 0)) > 0) buf_append(&b, tmp, r);
    closesocket(cs);
    if (!b.data) { buf_free(&b); return; }
    // First line must be the magic; the rest are UTF-8 paths.
    char *save = NULL;
    char *line = strtok_s(b.data, "\n", &save);
    if (!line || strcmp(line, SFS_COORD_MAGIC) != 0) { buf_free(&b); return; }
    while ((line = strtok_s(NULL, "\n", &save)) != NULL) {
        if (!line[0]) continue;
        wchar_t *w = utf8_to_wide(line, -1);
        if (w) { add_path(w); free(w); }
    }
    buf_free(&b);
}

// Try to become the owner by binding the coord port. On success, collect
// siblings until things go quiet, then return 1 with the listen socket closed.
// On failure (someone else owns it), return 0.
static int own_and_collect(SOCKET *outUnused) {
    (void)outUnused;
    SOCKET ls = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (ls == INVALID_SOCKET) return 0;
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons(SFS_COORD_PORT);
    if (bind(ls, (struct sockaddr *)&a, sizeof(a)) != 0) { closesocket(ls); return 0; }
    if (listen(ls, 32) != 0) { closesocket(ls); return 0; }

    ULONGLONG last = GetTickCount64();
    for (;;) {
        ULONGLONG now = GetTickCount64();
        long remaining = DEBOUNCE_MS - (long)(now - last);
        if (remaining <= 0) break;
        fd_set rf; FD_ZERO(&rf); FD_SET(ls, &rf);
        struct timeval tv = { remaining / 1000, (remaining % 1000) * 1000 };
        int r = select(0, &rf, NULL, NULL, &tv);
        if (r > 0 && FD_ISSET(ls, &rf)) {
            SOCKET cs = accept(ls, NULL, NULL);
            if (cs != INVALID_SOCKET) { read_sibling(cs); last = GetTickCount64(); }
        }
    }
    closesocket(ls);
    return 1;
}

// --- token -----------------------------------------------------------------

static void make_token(char *out, int hexchars) {
    int nbytes = hexchars / 2;
    unsigned char *raw = (unsigned char *)malloc(nbytes);
    if (!raw || BCryptGenRandom(NULL, raw, nbytes, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
        // Fallback: still better than a constant, though rarely reached.
        for (int i = 0; i < nbytes; i++) raw[i] = (unsigned char)(GetTickCount() >> (i % 24));
    }
    static const char *hex = "0123456789abcdef";
    for (int i = 0; i < nbytes; i++) {
        out[i * 2]     = hex[raw[i] >> 4];
        out[i * 2 + 1] = hex[raw[i] & 0xf];
    }
    out[nbytes * 2] = 0;
    free(raw);
}

// --- helpers ---------------------------------------------------------------

static const wchar_t *base_name(const wchar_t *path) {
    const wchar_t *b = path;
    for (const wchar_t *p = path; *p; p++) if (*p == L'\\' || *p == L'/') b = p + 1;
    return b;
}

// resolve_backend_url picks the backend: SFS_BACKEND env override, then the
// value stored at install time, then the built-in default.
void resolve_backend_url(wchar_t *out, size_t chars) {
    wchar_t *envback = _wgetenv(L"SFS_BACKEND");
    if (envback && envback[0]) { lstrcpynW(out, envback, (int)chars); return; }
    if (registry_read_backend(out, chars)) return;
    lstrcpynW(out, SFS_DEFAULT_BACKEND, (int)chars);
}

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE hPrev, PWSTR cmdline, int show) {
    (void)hInst; (void)hPrev; (void)cmdline; (void)show;
    InitializeCriticalSection(&g_lock);

    int argc = 0;
    wchar_t **argv = CommandLineToArgvW(GetCommandLineW(), &argc);

    // --- install / uninstall ---
    if (argc >= 2 && _wcsicmp(argv[1], L"-install") == 0) {
        const wchar_t *backend = SFS_DEFAULT_BACKEND;
        for (int i = 2; i + 1 < argc; i++)
            if (_wcsicmp(argv[i], L"-backend") == 0) backend = argv[i + 1];
        return registry_install(backend) ? 0 : 1;
    }
    if (argc >= 2 && _wcsicmp(argv[1], L"-uninstall") == 0) {
        return registry_uninstall() ? 0 : 1;
    }

    // --- gather file arguments ---
    int nargs = 0;
    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == L'-') continue; // skip flags
        g_paths[g_npaths++] = _wcsdup(argv[i]);
        nargs++;
        if (g_npaths >= MAX_FILES) break;
    }
    // Launched with no file (double-clicked, or from the Start menu): run the
    // resident tray app, which offers file selection and drag-and-drop.
    if (nargs == 0) {
        DeleteCriticalSection(&g_lock);
        return run_tray();
    }

    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    // Become the owner, or hand our paths to the existing one and exit.
    SOCKET unused;
    if (!own_and_collect(&unused)) {
        // Retry briefly in case the owner has not finished binding yet.
        int delivered = 0;
        for (int attempt = 0; attempt < 40 && !delivered; attempt++) {
            EnterCriticalSection(&g_lock);
            int n = g_npaths;
            wchar_t *snapshot[MAX_FILES];
            for (int i = 0; i < n; i++) snapshot[i] = g_paths[i];
            LeaveCriticalSection(&g_lock);
            if (handoff(snapshot, n)) { delivered = 1; break; }
            Sleep(25);
        }
        if (delivered) { WSACleanup(); return 0; }
        // The owner vanished (e.g. it already moved on). Fall through and open
        // our own window rather than dropping the file.
        own_and_collect(&unused);
    }

    // --- build the file list (size + base name), skipping folders ---
    static upfile_t files[MAX_FILES];
    int nfiles = 0;
    for (int i = 0; i < g_npaths && nfiles < MAX_FILES; i++) {
        WIN32_FILE_ATTRIBUTE_DATA fa;
        if (!GetFileAttributesExW(g_paths[i], GetFileExInfoStandard, &fa)) continue;
        if (fa.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue; // folders unsupported
        LARGE_INTEGER sz; sz.HighPart = fa.nFileSizeHigh; sz.LowPart = fa.nFileSizeLow;
        files[nfiles].path = _wcsdup(g_paths[i]);
        files[nfiles].name = wide_to_utf8(base_name(g_paths[i]), -1);
        files[nfiles].size = sz.QuadPart;
        nfiles++;
    }
    if (nfiles == 0) {
        MessageBoxW(NULL, L"送信できるファイルがありませんでした。\n（フォルダーは未対応です）",
                    L"セキュファイル便", MB_ICONWARNING);
        WSACleanup(); return 0;
    }

    // --- backend + limits ---
    static backend_t backend;
    wchar_t burl[512];
    resolve_backend_url(burl, 512);
    if (!backend_parse(burl, &backend)) {
        MessageBoxW(NULL, L"送信先URLが不正です。-install をやり直してください。",
                    L"セキュファイル便", MB_ICONERROR);
        WSACleanup(); return 1;
    }
    static buf_t limits; buf_init(&limits);
    if (!backend_status(&backend, &limits)) { buf_free(&limits); buf_init(&limits); buf_appends(&limits, "null"); }

    // --- token + local server ---
    static char token[33];
    make_token(token, 32);

    static server_ctx_t ctx;
    ctx.files = files; ctx.nfiles = nfiles;
    ctx.limits_json = limits.data ? limits.data : "null";
    ctx.backend = &backend;
    ctx.token = token;
    ctx.port = 0;

    if (!server_listen(&ctx)) {
        MessageBoxW(NULL, L"ローカルサーバーを起動できませんでした。",
                    L"セキュファイル便", MB_ICONERROR);
        WSACleanup(); return 1;
    }

    // --- open the browser on the local page ---
    wchar_t url[128];
    _snwprintf(url, 128, L"http://127.0.0.1:%d/?t=%S", ctx.port, token);
    // Debug hook: if SFS_URL_FILE is set, write the URL there and do not launch
    // a browser (used for scripted testing). Normal use just opens the browser.
    wchar_t *urlfile = _wgetenv(L"SFS_URL_FILE");
    if (urlfile && urlfile[0]) {
        HANDLE h = CreateFileW(urlfile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (h != INVALID_HANDLE_VALUE) {
            char *u = wide_to_utf8(url, -1);
            DWORD wr = 0;
            if (u) { WriteFile(h, u, (DWORD)strlen(u), &wr, NULL); free(u); }
            CloseHandle(h);
        }
    } else {
        ShellExecuteW(NULL, L"open", url, NULL, NULL, SW_SHOWNORMAL);
    }

    server_serve(&ctx); // blocks until idle, then the process exits
    WSACleanup();
    return 0;
}

// Resident system-tray application.
//
// Launched with no file argument (double-clicked, or from the Start menu), the
// client sits in the notification area with the app icon. From there the user
// can pick files with a native dialog or open the drag-and-drop uploader. The
// right-click context-menu entry on a file still runs the one-shot upload flow
// in main.c; this process only offers the always-available entry points.
#include "common.h"
#include "resource.h"
#include <shellapi.h>
#include <commdlg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "shell32.lib")

#define WM_TRAYICON (WM_APP + 1)

#define IDM_PICK      1001
#define IDM_DND       1002
#define IDM_INSTALL   1003
#define IDM_UNINSTALL 1004
#define IDM_QUIT      1005

static NOTIFYICONDATAW g_nid;
static HWND            g_hwnd;

// open_website launches the default browser on the backend's upload page, which
// offers both drag-and-drop and a file picker.
static void open_website(void) {
    wchar_t url[512];
    resolve_backend_url(url, 512);
    ShellExecuteW(NULL, L"open", url, NULL, NULL, SW_SHOWNORMAL);
}

// spawn_send starts a one-shot upload of the given paths by launching this same
// executable with them as arguments (the main.c flow), so the tray process
// stays responsive.
static void spawn_send(wchar_t **paths, int n) {
    wchar_t self[MAX_PATH];
    if (!GetModuleFileNameW(NULL, self, MAX_PATH)) return;

    // "self" path1 path2 ...  — sized for many long paths.
    size_t cap = 64 * 1024;
    wchar_t *cmd = (wchar_t *)malloc(cap * sizeof(wchar_t));
    if (!cmd) return;
    int len = _snwprintf(cmd, cap, L"\"%s\"", self);
    for (int i = 0; i < n && len > 0; i++) {
        int add = _snwprintf(cmd + len, cap - len, L" \"%s\"", paths[i]);
        if (add < 0) break;
        len += add;
    }

    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    if (CreateProcessW(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
    free(cmd);
}

// pick_and_send shows the native multi-select file dialog and sends whatever the
// user chose.
static void pick_and_send(void) {
    static wchar_t buf[32768];
    buf[0] = 0;
    OPENFILENAMEW ofn;
    memset(&ofn, 0, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = g_hwnd;
    ofn.lpstrFile = buf;
    ofn.nMaxFile = 32768;
    ofn.lpstrTitle = L"送信するファイルを選択";
    ofn.lpstrFilter = L"すべてのファイル\0*.*\0\0";
    ofn.Flags = OFN_EXPLORER | OFN_ALLOWMULTISELECT | OFN_FILEMUSTEXIST |
                OFN_HIDEREADONLY | OFN_NOCHANGEDIR;
    if (!GetOpenFileNameW(&ofn)) return; // cancelled

    // The result is a set of NUL-separated strings. A single selection is one
    // full path; a multi-selection is a directory followed by bare file names.
    wchar_t *p = buf;
    wchar_t dir[MAX_PATH];
    lstrcpynW(dir, p, MAX_PATH);
    p += lstrlenW(p) + 1;

    wchar_t *paths[256];
    int n = 0;
    if (*p == 0) {
        paths[n++] = dir; // single selection: dir holds the whole path
    } else {
        while (*p && n < 256) {
            size_t need = (size_t)lstrlenW(dir) + 1 + lstrlenW(p) + 1;
            wchar_t *full = (wchar_t *)malloc(need * sizeof(wchar_t));
            if (!full) break;
            _snwprintf(full, need, L"%s\\%s", dir, p);
            paths[n++] = full;
            p += lstrlenW(p) + 1;
        }
    }
    if (n > 0) spawn_send(paths, n);

    if (*buf && paths[0] != dir) {
        for (int i = 0; i < n; i++) free(paths[i]);
    }
}

static void show_menu(void) {
    HMENU m = CreatePopupMenu();
    AppendMenuW(m, MF_STRING, IDM_PICK, L"ファイルを選択して送る…");
    AppendMenuW(m, MF_STRING, IDM_DND, L"ドラッグ＆ドロップで送る（ブラウザ）");
    AppendMenuW(m, MF_SEPARATOR, 0, NULL);
    AppendMenuW(m, MF_STRING, IDM_INSTALL, L"右クリックメニューを登録");
    AppendMenuW(m, MF_STRING, IDM_UNINSTALL, L"右クリックメニューを解除");
    AppendMenuW(m, MF_SEPARATOR, 0, NULL);
    AppendMenuW(m, MF_STRING, IDM_QUIT, L"終了");

    POINT pt;
    GetCursorPos(&pt);
    // Required so the menu closes when the user clicks elsewhere.
    SetForegroundWindow(g_hwnd);
    TrackPopupMenu(m, TPM_RIGHTBUTTON | TPM_BOTTOMALIGN, pt.x, pt.y, 0, g_hwnd, NULL);
    PostMessageW(g_hwnd, WM_NULL, 0, 0);
    DestroyMenu(m);
}

static LRESULT CALLBACK wndproc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_TRAYICON:
        if (LOWORD(lp) == WM_LBUTTONUP || LOWORD(lp) == WM_RBUTTONUP ||
            LOWORD(lp) == WM_CONTEXTMENU || LOWORD(lp) == WM_LBUTTONDBLCLK) {
            show_menu();
        }
        return 0;
    case WM_COMMAND:
        switch (LOWORD(wp)) {
        case IDM_PICK: pick_and_send(); return 0;
        case IDM_DND: open_website(); return 0;
        case IDM_INSTALL: {
            wchar_t url[512];
            resolve_backend_url(url, 512);
            registry_install(url);
            return 0;
        }
        case IDM_UNINSTALL: registry_uninstall(); return 0;
        case IDM_QUIT: DestroyWindow(hwnd); return 0;
        }
        return 0;
    case WM_DESTROY:
        Shell_NotifyIconW(NIM_DELETE, &g_nid);
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

int run_tray(void) {
    // One tray instance is enough; a second launch just opens the uploader.
    HANDLE mtx = CreateMutexW(NULL, FALSE, L"Local\\SecureFileSendTray");
    if (mtx && GetLastError() == ERROR_ALREADY_EXISTS) {
        open_website();
        return 0;
    }

    HINSTANCE inst = GetModuleHandleW(NULL);
    HICON bigIcon = LoadIconW(inst, MAKEINTRESOURCEW(IDI_APPICON));

    WNDCLASSW wc;
    memset(&wc, 0, sizeof(wc));
    wc.lpfnWndProc = wndproc;
    wc.hInstance = inst;
    wc.hIcon = bigIcon;
    wc.lpszClassName = L"SFSTrayWnd";
    RegisterClassW(&wc);

    // A message-only-style hidden window: created but never shown.
    g_hwnd = CreateWindowExW(0, L"SFSTrayWnd", L"セキュファイル便", 0,
                             0, 0, 0, 0, HWND_MESSAGE, NULL, inst, NULL);
    if (!g_hwnd) return 1;

    memset(&g_nid, 0, sizeof(g_nid));
    g_nid.cbSize = sizeof(g_nid);
    g_nid.hWnd = g_hwnd;
    g_nid.uID = 1;
    g_nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    g_nid.uCallbackMessage = WM_TRAYICON;
    g_nid.hIcon = LoadImageW(inst, MAKEINTRESOURCEW(IDI_APPICON), IMAGE_ICON,
                             GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON),
                             LR_DEFAULTCOLOR);
    if (!g_nid.hIcon) g_nid.hIcon = bigIcon;
    lstrcpynW(g_nid.szTip, L"セキュファイル便 — ファイルを安全に送る", 128);
    Shell_NotifyIconW(NIM_ADD, &g_nid);

    // A one-time hint so the icon is noticed.
    g_nid.uFlags = NIF_INFO;
    lstrcpynW(g_nid.szInfoTitle, L"セキュファイル便", 64);
    lstrcpynW(g_nid.szInfo,
              L"通知領域に常駐しました。アイコンをクリックして、ファイルを送れます。", 256);
    g_nid.dwInfoFlags = NIIF_INFO;
    Shell_NotifyIconW(NIM_MODIFY, &g_nid);

    // Launching the app opens the uploader right away (drag-and-drop / picker).
    open_website();

    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    if (mtx) CloseHandle(mtx);
    return 0;
}

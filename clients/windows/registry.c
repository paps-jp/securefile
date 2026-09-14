// Registers (and removes) the right-click menu entry, under HKCU so no admin
// rights are needed. Install copies the running .exe to a stable location and
// points the menu command at that copy, so the menu keeps working after the
// build directory is gone.
#include "common.h"
#include <shlobj.h>
#include <stdio.h>
#include <stdlib.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")

#define MENU_LABEL   L"セキュファイル便で送る"
#define VERB_KEY     L"Software\\Classes\\*\\shell\\SecureFileSend"
#define CONFIG_KEY   L"Software\\SecureFileSend"

static int set_sz(HKEY key, const wchar_t *name, const wchar_t *val) {
    DWORD bytes = (DWORD)((lstrlenW(val) + 1) * sizeof(wchar_t));
    return RegSetValueExW(key, name, 0, REG_SZ, (const BYTE *)val, bytes) == ERROR_SUCCESS;
}

static int install_exe_path(wchar_t *out, size_t chars) {
    const wchar_t *base = _wgetenv(L"LOCALAPPDATA");
    if (!base || !base[0]) return 0;
    wchar_t dir[MAX_PATH];
    _snwprintf(dir, MAX_PATH, L"%s\\SecureFileSend", base);
    CreateDirectoryW(dir, NULL); // ok if it already exists
    _snwprintf(out, chars, L"%s\\securefile_send.exe", dir);
    return 1;
}

int registry_install(const wchar_t *backend) {
    wchar_t self[MAX_PATH];
    if (!GetModuleFileNameW(NULL, self, MAX_PATH)) return 0;

    wchar_t target[MAX_PATH];
    if (!install_exe_path(target, MAX_PATH)) return 0;

    // Copy ourselves to the stable location (unless we are already it).
    if (_wcsicmp(self, target) != 0) {
        if (!CopyFileW(self, target, FALSE)) {
            wchar_t msg[512];
            _snwprintf(msg, 512, L"実行ファイルをコピーできませんでした:\n%s", target);
            MessageBoxW(NULL, msg, L"セキュファイル便", MB_ICONERROR);
            return 0;
        }
    }

    // Store the backend URL.
    HKEY ck;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, CONFIG_KEY, 0, NULL, 0, KEY_WRITE, NULL, &ck, NULL) == ERROR_SUCCESS) {
        set_sz(ck, L"Backend", backend && backend[0] ? backend : SFS_DEFAULT_BACKEND);
        RegCloseKey(ck);
    }

    // The verb key.
    HKEY vk;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, VERB_KEY, 0, NULL, 0, KEY_WRITE, NULL, &vk, NULL) != ERROR_SUCCESS)
        return 0;
    set_sz(vk, NULL, MENU_LABEL);
    set_sz(vk, L"Icon", target);
    // Document => the verb stays available for a multi-file selection and the
    // command is invoked once per file; the helper coalesces those into one send.
    set_sz(vk, L"MultiSelectModel", L"Document");

    HKEY cmdk;
    if (RegCreateKeyExW(vk, L"command", 0, NULL, 0, KEY_WRITE, NULL, &cmdk, NULL) == ERROR_SUCCESS) {
        wchar_t cmd[MAX_PATH + 16];
        _snwprintf(cmd, MAX_PATH + 16, L"\"%s\" \"%%1\"", target);
        set_sz(cmdk, NULL, cmd);
        RegCloseKey(cmdk);
    }
    RegCloseKey(vk);

    SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, NULL, NULL);
    MessageBoxW(NULL,
        L"右クリックメニュー「セキュファイル便で送る」を追加しました。\n"
        L"ファイルを右クリックしてお試しください。",
        L"セキュファイル便", MB_ICONINFORMATION);
    return 1;
}

int registry_uninstall(void) {
    RegDeleteTreeW(HKEY_CURRENT_USER, VERB_KEY);
    RegDeleteTreeW(HKEY_CURRENT_USER, CONFIG_KEY);
    SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, NULL, NULL);
    MessageBoxW(NULL,
        L"右クリックメニューを削除しました。\n"
        L"（%LOCALAPPDATA%\\SecureFileSend の実行ファイルは手動で削除できます）",
        L"セキュファイル便", MB_ICONINFORMATION);
    return 1;
}

int registry_read_backend(wchar_t *out, size_t out_chars) {
    HKEY ck;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, CONFIG_KEY, 0, KEY_READ, &ck) != ERROR_SUCCESS)
        return 0;
    DWORD type = 0, bytes = (DWORD)(out_chars * sizeof(wchar_t));
    LONG r = RegQueryValueExW(ck, L"Backend", NULL, &type, (BYTE *)out, &bytes);
    RegCloseKey(ck);
    if (r != ERROR_SUCCESS || type != REG_SZ) return 0;
    out[out_chars - 1] = 0;
    return 1;
}

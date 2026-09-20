// language: C++, file: src/injector.cpp
#include "injector.h"
#include "nt.h"

#ifdef _WIN64
#define CUR_ARCH IMAGE_FILE_MACHINE_AMD64
#else
#define CUR_ARCH IMAGE_FILE_MACHINE_I386
#endif

static bool wpm(HANDLE p, PVOID a, PVOID b, SIZE_T n) {
    SIZE_T w;
    return g_nt.NtWriteVirtualMemory(p, a, b, n, &w) >= 0;
}
static bool rpm(HANDLE p, PVOID a, PVOID b, SIZE_T n) {
    SIZE_T r;
    return g_nt.NtReadVirtualMemory(p, a, b, n, &r) >= 0;
}
static PVOID valloc(HANDLE p, SIZE_T n, ULONG prot) {
    PVOID base = nullptr; SIZE_T sz = n;
    if (g_nt.NtAllocateVirtualMemory(p, &base, 0, &sz, MEM_COMMIT | MEM_RESERVE, prot) < 0)
        return nullptr;
    return base;
}
static bool vprot(HANDLE p, PVOID a, SIZE_T n, ULONG prot, PULONG old = nullptr) {
    PVOID base = a; SIZE_T sz = n;
    return g_nt.NtProtectVirtualMemory(p, &base, &sz, prot, old) >= 0;
}
static void vfree(HANDLE p, PVOID a) {
    SIZE_T sz = 0;
    g_nt.NtAllocateVirtualMemory(p, &a, 0, &sz, MEM_RELEASE, PAGE_NOACCESS);
}

bool runstub(HANDLE proc, BYTE* src, SIZE_T size, bool clear_hdr, bool clear_sections,
             bool adjust_prot, bool seh, DWORD reason, LPVOID reserved) {
    auto dos = (IMAGE_DOS_HEADER*)src;
    if (dos->e_magic != 0x5A4D) return false;
    auto nt = (IMAGE_NT_HEADERS*)(src + dos->e_lfanew);
    auto opt = &nt->OptionalHeader;
    auto fh  = &nt->FileHeader;
    if (fh->Machine != CUR_ARCH) return false;

    BYTE* base = (BYTE*)valloc(proc, opt->SizeOfImage, PAGE_READWRITE);
    if (!base) return false;
    DWORD oldp = 0;
    vprot(proc, base, opt->SizeOfImage, PAGE_EXECUTE_READWRITE, &oldp);

    MMDATA data{ 0 };
    data.pLoadLibraryA = LoadLibraryA;
    data.pGetProcAddress = GetProcAddress;
#ifdef _WIN64
    data.pRtlAddFunctionTable = (f_RtlAddFunctionTable)RtlAddFunctionTable;
#else
    seh = false;
#endif
    data.pbase = base;
    data.fdwReason = reason;
    data.reserved = reserved;
    data.seh = seh;

    if (!wpm(proc, base, src, 0x1000)) { vfree(proc, base); return false; }

    auto sec = IMAGE_FIRST_SECTION(nt);
    for (UINT i = 0; i < fh->NumberOfSections; i++, sec++) {
        if (sec->SizeOfRawData) {
            if (!wpm(proc, base + sec->VirtualAddress, src + sec->PointerToRawData, sec->SizeOfRawData)) {
                vfree(proc, base); return false;
            }
        }
    }

    BYTE* mdata = (BYTE*)valloc(proc, sizeof(MMDATA), PAGE_READWRITE);
    if (!mdata) { vfree(proc, base); return false; }
    if (!wpm(proc, mdata, &data, sizeof(MMDATA))) { vfree(proc, base); vfree(proc, mdata); return false; }

    void* shell = valloc(proc, 0x1000, PAGE_EXECUTE_READWRITE);
    if (!shell) { vfree(proc, base); vfree(proc, mdata); return false; }
    if (!wpm(proc, shell, Shellcode, 0x1000)) { vfree(proc, base); vfree(proc, mdata); vfree(proc, shell); return false; }

    HANDLE th = nullptr;
    g_nt.NtCreateThreadEx(&th, THREAD_ALL_ACCESS, nullptr, proc, shell, mdata, 0, 0, 0, 0, nullptr);
    if (!th) { vfree(proc, base); vfree(proc, mdata); vfree(proc, shell); return false; }
    g_nt.NtClose(th);

    HINSTANCE hCheck = nullptr;
    while (!hCheck) {
        DWORD ec = 0;
        GetExitCodeProcess(proc, &ec);
        if (ec != STILL_ACTIVE) return false;
        MMDATA d{ 0 };
        rpm(proc, mdata, &d, sizeof(d));
        hCheck = d.hMod;
        if (hCheck == (HINSTANCE)0x404040) {
            vfree(proc, base); vfree(proc, mdata); vfree(proc, shell); return false;
        }
        Sleep(10);
    }

    BYTE* empty = (BYTE*)malloc(1024 * 1024 * 20);
    if (!empty) return false;
    memset(empty, 0, 1024 * 1024 * 20);

    if (clear_hdr) wpm(proc, base, empty, 0x1000);

    if (clear_sections) {
        sec = IMAGE_FIRST_SECTION(nt);
        for (UINT i = 0; i < fh->NumberOfSections; i++, sec++) {
            if (sec->Misc.VirtualSize) {
                if ((!seh && strcmp((char*)sec->Name, ".pdata") == 0) ||
                    strcmp((char*)sec->Name, ".rsrc") == 0 ||
                    strcmp((char*)sec->Name, ".reloc") == 0) {
                    wpm(proc, base + sec->VirtualAddress, empty, sec->Misc.VirtualSize);
                }
            }
        }
    }

    if (adjust_prot) {
        sec = IMAGE_FIRST_SECTION(nt);
        for (UINT i = 0; i < fh->NumberOfSections; i++, sec++) {
            if (sec->Misc.VirtualSize) {
                DWORD o = 0, np = PAGE_READONLY;
                if (sec->Characteristics & IMAGE_SCN_MEM_WRITE)   np = PAGE_READWRITE;
                else if (sec->Characteristics & IMAGE_SCN_MEM_EXECUTE) np = PAGE_EXECUTE_READ;
                vprot(proc, base + sec->VirtualAddress, sec->Misc.VirtualSize, np, &o);
            }
        }
        DWORD o = 0;
        vprot(proc, base, IMAGE_FIRST_SECTION(nt)->VirtualAddress, PAGE_READONLY, &o);
    }

    wpm(proc, shell, empty, 0x1000);
    vfree(proc, shell);
    vfree(proc, mdata);
    free(empty);
    return true;
}

#define RF32(x) ((x >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)
#define RF64(x) ((x >> 0x0C) == IMAGE_REL_BASED_DIR64)
#ifdef _WIN64
#define RF(x) RF64(x)
#else
#define RF(x) RF32(x)
#endif

#pragma runtime_checks("", off)
#pragma optimize("", off)
void __stdcall Shellcode(MMDATA* pData) {
    if (!pData) { pData->hMod = (HINSTANCE)0x404040; return; }
    BYTE* base = pData->pbase;
    auto opt = &((IMAGE_NT_HEADERS*)(base + ((IMAGE_DOS_HEADER*)base)->e_lfanew))->OptionalHeader;
    auto _LLA = pData->pLoadLibraryA;
    auto _GPA = pData->pGetProcAddress;
#ifdef _WIN64
    auto _RAFT = pData->pRtlAddFunctionTable;
#endif
    auto _DllMain = (f_DllEntryPoint)(base + opt->AddressOfEntryPoint);

    BYTE* delta = base - opt->ImageBase;
    if (delta) {
        if (opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
            auto rel = (IMAGE_BASE_RELOCATION*)(base + opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
            auto end = (IMAGE_BASE_RELOCATION*)((uintptr_t)rel + opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);
            while (rel < end && rel->SizeOfBlock) {
                UINT n = (rel->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                WORD* ri = (WORD*)(rel + 1);
                for (UINT i = 0; i != n; ++i, ++ri) {
                    if (RF(*ri)) {
                        UINT_PTR* patch = (UINT_PTR*)(base + rel->VirtualAddress + ((*ri) & 0xFFF));
                        *patch += (UINT_PTR)delta;
                    }
                }
                rel = (IMAGE_BASE_RELOCATION*)((BYTE*)rel + rel->SizeOfBlock);
            }
        }
    }

    if (opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
        auto imp = (IMAGE_IMPORT_DESCRIPTOR*)(base + opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        while (imp->Name) {
            char* mod = (char*)(base + imp->Name);
            HINSTANCE h = _LLA(mod);
            ULONG_PTR* t = (ULONG_PTR*)(base + imp->OriginalFirstThunk);
            ULONG_PTR* f = (ULONG_PTR*)(base + imp->FirstThunk);
            if (!t) t = f;
            for (; *t; ++t, ++f) {
                if (IMAGE_SNAP_BY_ORDINAL(*t))
                    *f = (ULONG_PTR)_GPA(h, (LPCSTR)(*t & 0xFFFF));
                else {
                    auto ib = (IMAGE_IMPORT_BY_NAME*)(base + (*t));
                    *f = (ULONG_PTR)_GPA(h, ib->Name);
                }
            }
            ++imp;
        }
    }

    if (opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
        auto tls = (IMAGE_TLS_DIRECTORY*)(base + opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
        auto cb = (PIMAGE_TLS_CALLBACK*)(tls->AddressOfCallBacks);
        for (; cb && *cb; ++cb) (*cb)(base, DLL_PROCESS_ATTACH, nullptr);
    }

    bool seh_fail = false;
#ifdef _WIN64
    if (pData->seh) {
        auto ex = opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        if (ex.Size) {
            if (!_RAFT((IMAGE_RUNTIME_FUNCTION_ENTRY*)(base + ex.VirtualAddress),
                       ex.Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY), (DWORD64)base))
                seh_fail = true;
        }
    }
#endif
    _DllMain(base, pData->fdwReason, pData->reserved);
    if (seh_fail) pData->hMod = (HINSTANCE)0x505050;
    else pData->hMod = (HINSTANCE)base;
}
#pragma optimize("", on)
#pragma runtime_checks("", restore)

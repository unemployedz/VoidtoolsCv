// language: C++, file: src/injector.h
#pragma once
#include <windows.h>

using f_LoadLibraryA    = HINSTANCE(WINAPI*)(const char*);
using f_GetProcAddress  = FARPROC(WINAPI*)(HMODULE, LPCSTR);
using f_DllEntryPoint   = BOOL(WINAPI*)(void*, DWORD, void*);
#ifdef _WIN64
using f_RtlAddFunctionTable = BOOL(WINAPIV*)(PRUNTIME_FUNCTION, DWORD, DWORD64);
#endif

struct MMDATA {
    f_LoadLibraryA pLoadLibraryA;
    f_GetProcAddress pGetProcAddress;
#ifdef _WIN64
    f_RtlAddFunctionTable pRtlAddFunctionTable;
#endif
    BYTE* pbase;
    HINSTANCE hMod;
    DWORD fdwReason;
    LPVOID reserved;
    BOOL seh;
};

bool runstub(HANDLE proc, BYTE* src, SIZE_T size, bool clear_hdr, bool clear_sections,
             bool adjust_prot, bool seh, DWORD reason, LPVOID reserved);
void __stdcall Shellcode(MMDATA* pData);

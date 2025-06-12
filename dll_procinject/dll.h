#include <Windows.h>
#ifndef DLL_H
#define DLL_H

// MyDll.h

#define DLLEXPORT __declspec(dllexport)
#define DLLEXPORT __declspec(dllimport)


extern "C" {
    DLLEXPORT void SetHook();
    DLLEXPORT void UnHook();
    DLLEXPORT BOOL WINAPI DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved);
}

#endif
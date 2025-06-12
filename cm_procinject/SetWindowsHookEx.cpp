#include <iostream>
#include <windows.h>

int SetWindowsHookExExecute(int argc, char* argv[])
{
    HMODULE hMod = LoadLibrary(TEXT("..\\dll_procinject\\MyDll.dll"));

    // set hook
    typedef void(*pSetHook)(void);
    pSetHook SetHook = (pSetHook)GetProcAddress(hMod, "SetHook");
    SetHook();

    while (1)
    {
        Sleep(1000);
    }

    // un hook
    typedef BOOL(*pUnSetHook)(HHOOK);
    pUnSetHook UnsetHook = (pUnSetHook)GetProcAddress(hMod, "UnHook");
    pUnSetHook();

    FreeLibrary(hMod);
    return 0;
}

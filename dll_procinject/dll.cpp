#include "dll.h"
#include <windows.h>

// �򵥵ĵ�������
extern "C" __declspec(dllexport) int GetTestValue() {
    return 12345;
}

extern "C" __declspec(dllexport) void TestPrint() {
    MessageBoxA(NULL, "DLL Function Called!", "Test", MB_OK);
}

// DLL��ڵ�
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    return TRUE;
}
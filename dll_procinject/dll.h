#ifndef DLL_H
#define DLL_H

extern "C" {
    __declspec(dllexport) int GetTestValue();
    __declspec(dllexport) void TestPrint();
}

#endif
#include <Windows.h>

BOOL IsHeapPtr(LPVOID ptr);

PCHAR GetNameByPid1(DWORD pid);

BOOL IsCodePtrEx(HANDLE hp, LPVOID ptr);

PWCHAR addr2sym(HANDLE hp, LPVOID addr);

PCHAR pid2name(DWORD pid);
DWORD name2pid(LPCSTR ImageName);

BOOL SetPrivilege(PCHAR szPrivilege, BOOL bEnable);
#include <Windows.h>


BOOL IsHeapPtr(LPVOID ptr);

PCHAR GetNameByPid1(DWORD pid);

BOOL IsCodePtrEx(HANDLE hp, LPVOID ptr);

PWCHAR addr2sym(HANDLE hp, LPVOID addr);

PWCHAR pid2name(DWORD pid);
DWORD name2pid(LPWSTR ImageName);

BOOL SetPrivilege(PWCHAR szPrivilege, BOOL bEnable);

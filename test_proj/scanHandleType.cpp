#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <tlhelp32.h>
#include <ctype.h>

/* 扫描就只能扫出来这些，其他的用
{
    "3": "Directory",
    "5": "Token",
    "6": "Job",
    "7": "Process",
    "8": "Thread",
    "11": "IoCompletionReserve",
    "16": "Event",
    "17": "Mutant",
    "19": "Semaphore",
    "20": "Timer",
    "21": "IRTimer",
    "24": "WindowStation",
    "25": "Desktop",
    "30": "TpWorkerFactory",
    "35": "IoCompletion",
    "36": "WaitCompletionPacket",
    "37": "File",
    "42": "Section",
    "44": "Key",
    "46": "ALPC Port"
}

explorer.exe
{
    "3": "Directory",
    "5": "Token",
    "7": "Process",
    "8": "Thread",
    "11": "IoCompletionReserve",
    "16": "Event",
    "17": "Mutant",
    "19": "Semaphore",
    "20": "Timer",
    "21": "IRTimer",
    "24": "WindowStation",
    "25": "Desktop",
    "30": "TpWorkerFactory",
    "35": "IoCompletion",
    "36": "WaitCompletionPacket",
    "37": "File",
    "42": "Section",
    "44": "Key",
    "46": "ALPC Port",
    "49": "WmiGuid",
    "67": "DxgkCompositionObject"
}
*/


// 定义Native API结构体和函数
typedef LONG NTSTATUS;
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemHandleInformation = 16
} SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_HANDLE_ENTRY {
    ULONG OwnerPid;
    BYTE ObjectType;
    BYTE HandleFlags;
    USHORT HandleValue;
    PVOID ObjectPointer;
    ULONG AccessMask;
} SYSTEM_HANDLE_ENTRY, * PSYSTEM_HANDLE_ENTRY;

typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG Count;
    SYSTEM_HANDLE_ENTRY Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

typedef enum _OBJECT_INFORMATION_CLASS {
    ObjectBasicInformation = 0,
    ObjectNameInformation = 1,
    ObjectTypeInformation = 2
} OBJECT_INFORMATION_CLASS;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

/*
typedef struct _GENERIC_MAPPING1 {
    ACCESS_MASK GenericRead;
    ACCESS_MASK GenericWrite;
    ACCESS_MASK GenericExecute;
    ACCESS_MASK GenericAll;
} GENERIC_MAPPING, * PGENERIC_MAPPING;
*/

typedef struct _OBJECT_TYPE_INFORMATION {
    UNICODE_STRING TypeName;
    ULONG TotalNumberOfHandles;
    ULONG TotalNumberOfObjects;
    ULONG Unused[4];
    ULONG HighWaterNumberOfHandles;
    ULONG HighWaterNumberOfObjects;
    ULONG Unused2[4];
    ACCESS_MASK InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ACCESS_MASK ValidAccessMask;
    BOOLEAN SecurityRequired;
    BOOLEAN MaintainHandleCount;
    UCHAR TypeIndex;
    CHAR ReservedByte;
    ULONG PoolType;
    ULONG DefaultPagedPoolCharge;
    ULONG DefaultNonPagedPoolCharge;
} OBJECT_TYPE_INFORMATION, * POBJECT_TYPE_INFORMATION;

// 声明Native API函数
typedef NTSTATUS(WINAPI* PFN_NT_QUERY_SYSTEM_INFORMATION)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );

typedef NTSTATUS(WINAPI* PFN_NT_QUERY_OBJECT)(
    HANDLE Handle,
    OBJECT_INFORMATION_CLASS ObjectInformationClass,
    PVOID ObjectInformation,
    ULONG ObjectInformationLength,
    PULONG ReturnLength
    );

typedef NTSTATUS(WINAPI* PFN_NT_DUPLICATE_OBJECT)(
    HANDLE SourceProcessHandle,
    HANDLE SourceHandle,
    HANDLE TargetProcessHandle,
    PHANDLE TargetHandle,
    ACCESS_MASK DesiredAccess,
    ULONG HandleAttributes,
    ULONG Options
    );

// 全局函数指针
PFN_NT_QUERY_SYSTEM_INFORMATION NtQuerySystemInformation = NULL;
PFN_NT_QUERY_OBJECT NtQueryObject = NULL;
PFN_NT_DUPLICATE_OBJECT NtDuplicateObject = NULL;

// 初始化Native API函数
BOOL InitializeNativeAPI() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        printf("Failed to get ntdll.dll handle\n");
        return FALSE;
    }

    NtQuerySystemInformation = (PFN_NT_QUERY_SYSTEM_INFORMATION)
        GetProcAddress(hNtdll, "NtQuerySystemInformation");
    NtQueryObject = (PFN_NT_QUERY_OBJECT)
        GetProcAddress(hNtdll, "NtQueryObject");
    NtDuplicateObject = (PFN_NT_DUPLICATE_OBJECT)
        GetProcAddress(hNtdll, "NtDuplicateObject");

    if (!NtQuerySystemInformation || !NtQueryObject || !NtDuplicateObject) {
        printf("Failed to get Native API functions\n");
        return FALSE;
    }

    return TRUE;
}

// 获取句柄类型名称
BOOL GetHandleTypeName(HANDLE hProcess, HANDLE hHandle, WCHAR* typeName, DWORD typeNameSize) {
    HANDLE hDuplicate = NULL;
    NTSTATUS status;

    // 复制句柄到当前进程
    status = NtDuplicateObject(
        hProcess,           // 源进程
        hHandle,           // 源句柄
        GetCurrentProcess(), // 目标进程
        &hDuplicate,       // 目标句柄
        0,                 // 访问权限
        0,                 // 句柄属性
        0                  // 选项
    );

    if (!NT_SUCCESS(status)) {
        return FALSE;
    }

    // 查询对象类型信息
    ULONG returnLength;
    BYTE buffer[1024];
    POBJECT_TYPE_INFORMATION pTypeInfo = (POBJECT_TYPE_INFORMATION)buffer;
    DWORD test_TypeIndex = 0;

    status = NtQueryObject(
        hDuplicate,
        ObjectTypeInformation,
        pTypeInfo,
        sizeof(buffer),
        &returnLength
    );

    if (NT_SUCCESS(status)) {
        // 复制类型名称
        if (pTypeInfo->TypeName.Buffer && 
            pTypeInfo->TypeName.Length > 0) 
        {
            DWORD copyLength = min(pTypeInfo->TypeName.Length / sizeof(WCHAR), typeNameSize - 1);
            wcsncpy_s(typeName, typeNameSize, pTypeInfo->TypeName.Buffer, copyLength);
            typeName[copyLength] = L'\0';

        }
        else {
            wcscpy_s(typeName, typeNameSize, L"<Unknown>");
        }

        CloseHandle(hDuplicate);
        return TRUE;
    }

    CloseHandle(hDuplicate);
    return FALSE;
}

// 扫描指定进程的所有句柄
BOOL ScanProcessHandles(DWORD processId) {
    ULONG bufferSize = 0x10000;
    PSYSTEM_HANDLE_INFORMATION pHandleInfo;
    NTSTATUS status;

    printf("扫描进程 PID: %lu 的句柄信息...\n\n", processId);

    // 分配缓冲区
    pHandleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(bufferSize);
    if (!pHandleInfo) {
        printf("内存分配失败\n");
        return FALSE;
    }

    // 查询系统句柄信息
    while (TRUE) {
        status = NtQuerySystemInformation(
            SystemHandleInformation,
            pHandleInfo,
            bufferSize,
            NULL
        );

        if (NT_SUCCESS(status)) {
            break;
        }
        else if (status == 0xC0000004) { // STATUS_INFO_LENGTH_MISMATCH
            free(pHandleInfo);
            bufferSize *= 2;
            pHandleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(bufferSize);
            if (!pHandleInfo) {
                printf("内存分配失败\n");
                return FALSE;
            }
        }
        else {
            printf("查询系统句柄信息失败，错误码: 0x%08X\n", status);
            free(pHandleInfo);
            return FALSE;
        }
    }

    // 打开目标进程
    HANDLE hProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, processId);
    if (!hProcess) {
        printf("无法打开进程 PID: %lu，错误码: %lu\n", processId, GetLastError());
        free(pHandleInfo);
        return FALSE;
    }

    printf("句柄值\t类型名称\t\t访问权限\n");
    printf("------\t--------\t\t--------\n");

    DWORD handleCount = 0;

    // 遍历所有句柄
    for (ULONG i = 0; i < pHandleInfo->Count; i++) 
    {
        PSYSTEM_HANDLE_ENTRY pHandle = &pHandleInfo->Handles[i];

        // 过滤指定进程的句柄
        if (pHandle->OwnerPid != processId) {
            continue;
        }

        handleCount++;
        WCHAR typeName[256] = L"Unknown";

        // 获取句柄类型名称
        if (!GetHandleTypeName(hProcess, (HANDLE)(ULONG_PTR)pHandle->HandleValue, typeName, 256)) {
            wcscpy_s(typeName, 256, L"<无法获取>");
            continue;
        }

        /*
        // 打印句柄信息
        printf("0x%04X\t%-5d -> %-20ws\t0x%08X\n",
            pHandle->HandleValue,
            pHandle->ObjectType,
            typeName,
            pHandle->AccessMask);
        */
        printf("%d -> %ws\n", pHandle->ObjectType, typeName);
    }

    printf("\n总共找到 %lu 个句柄\n", handleCount);

    CloseHandle(hProcess);
    free(pHandleInfo);
    return TRUE;
}

// 根据进程名查找PID
DWORD FindProcessByName(const char* processName) {
    HANDLE hSnapshot;
    PROCESSENTRY32 pe32;
    DWORD pid = 0;

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (_stricmp(pe32.szExeFile, processName) == 0) {
                pid = pe32.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return pid;
}


int ScanHandleTypemain(PCHAR procName) 
{
    printf("Windows 进程句柄的类型扫描器\n");
    printf("===================\n\n");

    // 初始化Native API
    if (!InitializeNativeAPI()) {
        printf("初始化Native API失败\n");
        return 1;
    }

    DWORD processId = FindProcessByName(procName);

    // 扫描句柄
    if (!ScanProcessHandles(processId)) {
        printf("扫描句柄失败\n");
        return 1;
    }

    return 0;
}
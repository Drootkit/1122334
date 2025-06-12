#include "dll.h"

#include <iostream>
#include <TlHelp32.h>
#include <windows.h>
#include <tchar.h>

// 指定全局变量
HHOOK global_Hook;

// 判断是否是需要注入的进程
BOOL GetFristModuleName(DWORD Pid, LPCTSTR ExeName)
{
    MODULEENTRY32 me32 = { 0 };
    me32.dwSize = sizeof(MODULEENTRY32);
    HANDLE hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, Pid);

    if (INVALID_HANDLE_VALUE != hModuleSnap)
    {
        // 先拿到自身进程名称
        BOOL bRet = Module32First(hModuleSnap, &me32);

        // 对比如果是需要注入进程,则返回真
        if (!_tcsicmp(ExeName, (LPCTSTR)me32.szModule))
        {
            CloseHandle(hModuleSnap);
            return TRUE;
        }
        CloseHandle(hModuleSnap);
        return FALSE;
    }
    CloseHandle(hModuleSnap);
    return FALSE;
}

// 获取自身DLL名称
char* GetMyDllName()
{
    char szFileFullPath[MAX_PATH], szProcessName[MAX_PATH];

    // 获取文件路径
    GetModuleFileNameA(NULL, szFileFullPath, MAX_PATH);

    int length = strlen(szFileFullPath);

    // 从路径后面开始找\，即倒着找右斜杠
    for (int i = length - 1; i >= 0; i--)
    {
        // 找到第一个\就可以马上获取进程名称了
        if (szFileFullPath[i] == '\\')
        {
            i++;
            // 结束符\0不能少 即i=length
            for (int j = 0; i <= length; j++)
            {
                szProcessName[j] = szFileFullPath[i++];
            }
            break;
        }
    }
    return szProcessName;
}

// 设置全局消息回调函数
LRESULT CALLBACK MyProc(int nCode, WPARAM wParam, LPARAM lParam)
{
    return CallNextHookEx(global_Hook, nCode, wParam, lParam);
}

// 安装全局钩子 此处的 GetMyDllName()函数 可以是外部其他DLL,可将任意DLL进行注入
void SetHook()
{
    global_Hook = SetWindowsHookEx(WH_CBT, MyProc, GetModuleHandleA(GetMyDllName()), 0);
}

// 卸载全局钩子
void UnHook()
{
    if (global_Hook)
    {
        UnhookWindowsHookEx(global_Hook);
    }
}

// DLL 主函数
BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        MessageBoxW(NULL, L"set windows hook inject dll succeed", L"FromDll", NULL);
        /*
        // 当DLL被加载时触发,判断当前自身父进程是否为 lyshark.exe 
        BOOL flag = GetFristModuleName(GetCurrentProcessId(), TEXT("lyshark.exe"));
        if (flag == TRUE)
        {
            MessageBoxA(0, "hello lyshark", 0, 0);
        }
        */
        break;
    }
    case DLL_THREAD_ATTACH:
    {
        break;
    }
    case DLL_THREAD_DETACH:
    {
        break;
    }
    case DLL_PROCESS_DETACH:
    {
        // DLL卸载时自动清理
        UnHook();
        break;
    }
    default:
        break;
    }
    return TRUE;
}

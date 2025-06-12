#include "dll.h"

#include <iostream>
#include <TlHelp32.h>
#include <windows.h>
#include <tchar.h>

// ָ��ȫ�ֱ���
HHOOK global_Hook;

// �ж��Ƿ�����Ҫע��Ľ���
BOOL GetFristModuleName(DWORD Pid, LPCTSTR ExeName)
{
    MODULEENTRY32 me32 = { 0 };
    me32.dwSize = sizeof(MODULEENTRY32);
    HANDLE hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, Pid);

    if (INVALID_HANDLE_VALUE != hModuleSnap)
    {
        // ���õ������������
        BOOL bRet = Module32First(hModuleSnap, &me32);

        // �Ա��������Ҫע�����,�򷵻���
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

// ��ȡ����DLL����
char* GetMyDllName()
{
    char szFileFullPath[MAX_PATH], szProcessName[MAX_PATH];

    // ��ȡ�ļ�·��
    GetModuleFileNameA(NULL, szFileFullPath, MAX_PATH);

    int length = strlen(szFileFullPath);

    // ��·�����濪ʼ��\������������б��
    for (int i = length - 1; i >= 0; i--)
    {
        // �ҵ���һ��\�Ϳ������ϻ�ȡ����������
        if (szFileFullPath[i] == '\\')
        {
            i++;
            // ������\0������ ��i=length
            for (int j = 0; i <= length; j++)
            {
                szProcessName[j] = szFileFullPath[i++];
            }
            break;
        }
    }
    return szProcessName;
}

// ����ȫ����Ϣ�ص�����
LRESULT CALLBACK MyProc(int nCode, WPARAM wParam, LPARAM lParam)
{
    return CallNextHookEx(global_Hook, nCode, wParam, lParam);
}

// ��װȫ�ֹ��� �˴��� GetMyDllName()���� �������ⲿ����DLL,�ɽ�����DLL����ע��
void SetHook()
{
    global_Hook = SetWindowsHookEx(WH_CBT, MyProc, GetModuleHandleA(GetMyDllName()), 0);
}

// ж��ȫ�ֹ���
void UnHook()
{
    if (global_Hook)
    {
        UnhookWindowsHookEx(global_Hook);
    }
}

// DLL ������
BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        MessageBoxW(NULL, L"set windows hook inject dll succeed", L"FromDll", NULL);
        /*
        // ��DLL������ʱ����,�жϵ�ǰ���������Ƿ�Ϊ lyshark.exe 
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
        // DLLж��ʱ�Զ�����
        UnHook();
        break;
    }
    default:
        break;
    }
    return TRUE;
}

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "test.h"

// ��ȡ��������Ϣ���������
BOOL CheckWindowConditions(HWND hwnd) 
{
    WNDCLASSEX wc = { 0 };
    char className[256] = { 0 };
    ATOM classAtom;
    LONG_PTR windowData;

    // ��ȡ����
    if (GetClassNameA(hwnd, className, sizeof(className)) == 0) {
        return FALSE;
    }

    // ��ȡ���ԭ��ֵ
    classAtom = (ATOM)GetClassLongPtrA(hwnd, GCW_ATOM);
    if (classAtom == 0) {
        return FALSE;
    }

    // ͨ��ԭ��ֵ��ȡ�����Ĵ�������Ϣ
    wc.cbSize = sizeof(WNDCLASSEX);
    if (!GetClassInfoExA(GetModuleHandleA(NULL), (LPCSTR)(ULONG_PTR)classAtom, &wc)) {
        // ����ӵ�ǰģ���ȡʧ�ܣ����ԴӴ��ڵ�ʵ����ȡ
        HINSTANCE hInst = (HINSTANCE)GetWindowLongPtrA(hwnd, GWLP_HINSTANCE);
        if (hInst && !GetClassInfoExA(hInst, className, &wc)) {
            // �����ֱ����������ȡ
            if (!GetClassInfoExA(NULL, className, &wc)) {
                return FALSE;
            }
        }
    }

    // �������ʽ�Ƿ����CS_DBLCLKS
    if (!(wc.style & CS_DBLCLKS)) {
        return FALSE;
    }

    // ��鴰���ֽ�ƫ��0λ���Ƿ�������
    windowData = GetWindowLongPtrA(hwnd, 0);
    if (windowData == 0) 
    {
        return FALSE;
    }

    return TRUE;
}

// ��ӡ������ϸ��Ϣ
void PrintWindowDetails(HWND hwnd) {
    char className[256] = { 0 };
    char windowText[256] = { 0 };
    WNDCLASSEX wc = { 0 };
    RECT rect;
    ATOM classAtom;
    LONG_PTR windowData;
    DWORD processId, threadId;

    // ��ȡ������Ϣ
    GetClassNameA(hwnd, className, sizeof(className));
    GetWindowTextA(hwnd, windowText, sizeof(windowText));
    GetWindowRect(hwnd, &rect);

    // ��ȡ���̺��߳�ID
    threadId = GetWindowThreadProcessId(hwnd, &processId);

    // ��ȡ��������
    windowData = GetWindowLongPtrA(hwnd, 0);

    // ��ȡ����Ϣ
    wc.cbSize = sizeof(WNDCLASSEX);
    classAtom = (ATOM)GetClassLongPtrA(hwnd, GCW_ATOM);

    // ���Զ��ַ�ʽ��ȡ����Ϣ
    BOOL classInfoObtained = FALSE;
    if (classAtom != 0) {
        if (GetClassInfoExA(GetModuleHandleA(NULL), (LPCSTR)(ULONG_PTR)classAtom, &wc)) {
            classInfoObtained = TRUE;
        }
    }

    if (!classInfoObtained) {
        HINSTANCE hInst = (HINSTANCE)GetWindowLongPtrA(hwnd, GWLP_HINSTANCE);
        if (hInst && GetClassInfoExA(hInst, className, &wc)) {
            classInfoObtained = TRUE;
        }
        else if (GetClassInfoExA(NULL, className, &wc)) {
            classInfoObtained = TRUE;
        }
    }

    printf("========================================\n");
    printf("���ھ��: 0x%p\n", hwnd);
    printf("����: %s\n", className);
    printf("���ڱ���: %s\n", windowText[0] ? windowText : "(�ޱ���)");
    printf("����ID: %lu, �߳�ID: %lu\n", processId, threadId);
    printf("λ��: (%d, %d), ��С: %dx%d\n",
        rect.left, rect.top, rect.right - rect.left, rect.bottom - rect.top);

    if (classInfoObtained) {
        printf("����ʽ: 0x%08X", wc.style);

        // ��������ʽ��־
        printf(" (");
        BOOL first = TRUE;
        if (wc.style & CS_VREDRAW) {
            printf("%sCS_VREDRAW", first ? "" : " | "); first = FALSE;
        }
        if (wc.style & CS_HREDRAW) {
            printf("%sCS_HREDRAW", first ? "" : " | "); first = FALSE;
        }
        if (wc.style & CS_DBLCLKS) {
            printf("%sCS_DBLCLKS", first ? "" : " | "); first = FALSE;
        }
        if (wc.style & CS_OWNDC) {
            printf("%sCS_OWNDC", first ? "" : " | "); first = FALSE;
        }
        if (wc.style & CS_CLASSDC) {
            printf("%sCS_CLASSDC", first ? "" : " | "); first = FALSE;
        }
        if (wc.style & CS_PARENTDC) {
            printf("%sCS_PARENTDC", first ? "" : " | "); first = FALSE;
        }
        if (wc.style & CS_NOCLOSE) {
            printf("%sCS_NOCLOSE", first ? "" : " | "); first = FALSE;
        }
        if (wc.style & CS_SAVEBITS) {
            printf("%sCS_SAVEBITS", first ? "" : " | "); first = FALSE;
        }
        if (wc.style & CS_BYTEALIGNCLIENT) {
            printf("%sCS_BYTEALIGNCLIENT", first ? "" : " | "); first = FALSE;
        }
        if (wc.style & CS_BYTEALIGNWINDOW) {
            printf("%sCS_BYTEALIGNWINDOW", first ? "" : " | "); first = FALSE;
        }
        if (wc.style & CS_GLOBALCLASS) {
            printf("%sCS_GLOBALCLASS", first ? "" : " | "); first = FALSE;
        }
        if (wc.style & CS_DROPSHADOW) {
            printf("%sCS_DROPSHADOW", first ? "" : " | "); first = FALSE;
        }
        printf(")\n");

        printf("������ֽ�: %d\n", wc.cbClsExtra);
        printf("���ڶ����ֽ�: %d\n", wc.cbWndExtra);
        printf("ʵ�����: 0x%p\n", wc.hInstance);
        printf("ͼ����: 0x%p\n", wc.hIcon);
        printf("�����: 0x%p\n", wc.hCursor);
        printf("������ˢ: 0x%p\n", wc.hbrBackground);
        printf("�˵���: %s\n", wc.lpszMenuName ? wc.lpszMenuName : "(��)");
    }
    else {
        printf("����ʽ: (�޷���ȡ����Ϣ)\n");
    }

    printf("����ƫ��0����: 0x%p (%lld)\n", (void*)windowData, (long long)windowData);
    printf("������ʽ: 0x%08X\n", GetWindowLongA(hwnd, GWL_STYLE));
    printf("��չ��ʽ: 0x%08X\n", GetWindowLongA(hwnd, GWL_EXSTYLE));
    printf("�Ƿ�ɼ�: %s\n", IsWindowVisible(hwnd) ? "��" : "��");
    printf("�Ƿ�����: %s\n", IsWindowEnabled(hwnd) ? "��" : "��");
    printf("������: 0x%p\n", GetParent(hwnd));
}

// ö�ٴ��ڻص�����
BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam) {
    if (CheckWindowConditions(hwnd)) 
    {
        int* count = (int*)lParam;
        (*count)++;

        printf("\n�ҵ����������Ĵ��� #%d:\n", *count);
        PrintWindowDetails(hwnd);
    }

    return TRUE; // ����ö��
}

// ö���Ӵ��ڵĻص�����
BOOL CALLBACK EnumChildProc(HWND hwnd, LPARAM lParam) {
    if (CheckWindowConditions(hwnd)) {
        int* count = (int*)lParam;
        (*count)++;

        printf("\n�ҵ������������Ӵ��� #%d:\n", *count);
        PrintWindowDetails(hwnd);
    }

    return TRUE; // ����ö��
}

int main() {
    int count = 0;

    printf("��ʼ����Windows�е����д���...\n");
    printf("����������\n");
    printf("1. ��������ʽ����CS_DBLCLKS (0x%08X)\n", CS_DBLCLKS);
    printf("2. �����ֽ�ƫ��0λ�������ݣ�����ֵ��\n");
    printf("========================================\n");

    // ���ÿ���̨�������
    SetConsoleOutputCP(CP_UTF8);

    // ö�����ж�������
    printf("\n����ö�ٶ�������...\n");
    EnumWindows(EnumWindowsProc, (LPARAM)&count);

    // ö�����洰�ڵ��Ӵ���
    printf("\n����ö�������Ӵ���...\n");
    HWND hDesktop = GetDesktopWindow();
    EnumChildWindows(hDesktop, EnumChildProc, (LPARAM)&count);

    printf("\n========================================\n");
    printf("ö����ɣ����ҵ� %d �����������Ĵ��ڡ�\n", count);

    if (count == 0) {
        printf("\n��ʾ��\n");
        printf("- CS_DBLCLKS��ʽ��������˫����Ϣ\n");
        printf("- ����ƫ��0λ��ͨ���洢�����ض�������ָ��\n");
        printf("- ĳЩϵͳ���ڻ�ؼ����ܷ�����Щ����\n");
    }

    printf("\n��Enter���˳�...");
    getchar();

    return 0;
}
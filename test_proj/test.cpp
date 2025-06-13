#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "test.h"

// 获取窗口类信息并检查条件
BOOL CheckWindowConditions(HWND hwnd) 
{
    WNDCLASSEX wc = { 0 };
    char className[256] = { 0 };
    ATOM classAtom;
    LONG_PTR windowData;

    // 获取类名
    if (GetClassNameA(hwnd, className, sizeof(className)) == 0) {
        return FALSE;
    }

    // 获取类的原子值
    classAtom = (ATOM)GetClassLongPtrA(hwnd, GCW_ATOM);
    if (classAtom == 0) {
        return FALSE;
    }

    // 通过原子值获取完整的窗口类信息
    wc.cbSize = sizeof(WNDCLASSEX);
    if (!GetClassInfoExA(GetModuleHandleA(NULL), (LPCSTR)(ULONG_PTR)classAtom, &wc)) {
        // 如果从当前模块获取失败，尝试从窗口的实例获取
        HINSTANCE hInst = (HINSTANCE)GetWindowLongPtrA(hwnd, GWLP_HINSTANCE);
        if (hInst && !GetClassInfoExA(hInst, className, &wc)) {
            // 最后尝试直接用类名获取
            if (!GetClassInfoExA(NULL, className, &wc)) {
                return FALSE;
            }
        }
    }

    // 检查类样式是否包含CS_DBLCLKS
    if (!(wc.style & CS_DBLCLKS)) {
        return FALSE;
    }

    // 检查窗口字节偏移0位置是否有数据
    windowData = GetWindowLongPtrA(hwnd, 0);
    if (windowData == 0) 
    {
        return FALSE;
    }

    return TRUE;
}

// 打印窗口详细信息
void PrintWindowDetails(HWND hwnd) {
    char className[256] = { 0 };
    char windowText[256] = { 0 };
    WNDCLASSEX wc = { 0 };
    RECT rect;
    ATOM classAtom;
    LONG_PTR windowData;
    DWORD processId, threadId;

    // 获取基本信息
    GetClassNameA(hwnd, className, sizeof(className));
    GetWindowTextA(hwnd, windowText, sizeof(windowText));
    GetWindowRect(hwnd, &rect);

    // 获取进程和线程ID
    threadId = GetWindowThreadProcessId(hwnd, &processId);

    // 获取窗口数据
    windowData = GetWindowLongPtrA(hwnd, 0);

    // 获取类信息
    wc.cbSize = sizeof(WNDCLASSEX);
    classAtom = (ATOM)GetClassLongPtrA(hwnd, GCW_ATOM);

    // 尝试多种方式获取类信息
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
    printf("窗口句柄: 0x%p\n", hwnd);
    printf("类名: %s\n", className);
    printf("窗口标题: %s\n", windowText[0] ? windowText : "(无标题)");
    printf("进程ID: %lu, 线程ID: %lu\n", processId, threadId);
    printf("位置: (%d, %d), 大小: %dx%d\n",
        rect.left, rect.top, rect.right - rect.left, rect.bottom - rect.top);

    if (classInfoObtained) {
        printf("类样式: 0x%08X", wc.style);

        // 解析类样式标志
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

        printf("类额外字节: %d\n", wc.cbClsExtra);
        printf("窗口额外字节: %d\n", wc.cbWndExtra);
        printf("实例句柄: 0x%p\n", wc.hInstance);
        printf("图标句柄: 0x%p\n", wc.hIcon);
        printf("光标句柄: 0x%p\n", wc.hCursor);
        printf("背景画刷: 0x%p\n", wc.hbrBackground);
        printf("菜单名: %s\n", wc.lpszMenuName ? wc.lpszMenuName : "(无)");
    }
    else {
        printf("类样式: (无法获取类信息)\n");
    }

    printf("窗口偏移0数据: 0x%p (%lld)\n", (void*)windowData, (long long)windowData);
    printf("窗口样式: 0x%08X\n", GetWindowLongA(hwnd, GWL_STYLE));
    printf("扩展样式: 0x%08X\n", GetWindowLongA(hwnd, GWL_EXSTYLE));
    printf("是否可见: %s\n", IsWindowVisible(hwnd) ? "是" : "否");
    printf("是否启用: %s\n", IsWindowEnabled(hwnd) ? "是" : "否");
    printf("父窗口: 0x%p\n", GetParent(hwnd));
}

// 枚举窗口回调函数
BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam) {
    if (CheckWindowConditions(hwnd)) 
    {
        int* count = (int*)lParam;
        (*count)++;

        printf("\n找到符合条件的窗口 #%d:\n", *count);
        PrintWindowDetails(hwnd);
    }

    return TRUE; // 继续枚举
}

// 枚举子窗口的回调函数
BOOL CALLBACK EnumChildProc(HWND hwnd, LPARAM lParam) {
    if (CheckWindowConditions(hwnd)) {
        int* count = (int*)lParam;
        (*count)++;

        printf("\n找到符合条件的子窗口 #%d:\n", *count);
        PrintWindowDetails(hwnd);
    }

    return TRUE; // 继续枚举
}

int main() {
    int count = 0;

    printf("开始遍历Windows中的所有窗口...\n");
    printf("查找条件：\n");
    printf("1. 窗口类样式包含CS_DBLCLKS (0x%08X)\n", CS_DBLCLKS);
    printf("2. 窗口字节偏移0位置有数据（非零值）\n");
    printf("========================================\n");

    // 设置控制台输出编码
    SetConsoleOutputCP(CP_UTF8);

    // 枚举所有顶级窗口
    printf("\n正在枚举顶级窗口...\n");
    EnumWindows(EnumWindowsProc, (LPARAM)&count);

    // 枚举桌面窗口的子窗口
    printf("\n正在枚举桌面子窗口...\n");
    HWND hDesktop = GetDesktopWindow();
    EnumChildWindows(hDesktop, EnumChildProc, (LPARAM)&count);

    printf("\n========================================\n");
    printf("枚举完成！共找到 %d 个符合条件的窗口。\n", count);

    if (count == 0) {
        printf("\n提示：\n");
        printf("- CS_DBLCLKS样式用于启用双击消息\n");
        printf("- 窗口偏移0位置通常存储窗口特定的数据指针\n");
        printf("- 某些系统窗口或控件可能符合这些条件\n");
    }

    printf("\n按Enter键退出...");
    getchar();

    return 0;
}
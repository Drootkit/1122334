#include <Windows.h>
#include <stdio.h>

/*  扫了一下win10，会有这些作为 knowndlls
wow64cpu.dll
wowarmhw.dll
xtajit.dll
advapi32.dll
clbcatq.dll
combase.dll
COMDLG32.dll
coml2.dll
difxapi.dll
gdi32.dll
gdiplus.dll
IMAGEHLP.dll
IMM32.dll
kernel32.dll
MSCTF.dll
MSVCRT.dll
NORMALIZ.dll
NSI.dll
ole32.dll
OLEAUT32.dll
PSAPI.DLL
rpcrt4.dll
sechost.dll
Setupapi.dll
SHCORE.dll
SHELL32.dll
SHLWAPI.dll
user32.dll
WLDAP32.dll
wow64.dll
wow64win.dll
WS2_32.dll
*/


// list KnownDLLs
void knowndll_list() 
{
    HKEY  hk;
    DWORD err, namelen, sublen, idx;
    WCHAR name[MAX_PATH], subkey[MAX_PATH];

    err = RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs",
        0, KEY_READ | KEY_QUERY_VALUE, &hk);

    if (err == ERROR_SUCCESS) 
    {
        for (idx = 0; ;idx++) 
        {
            sublen = MAX_PATH;
            namelen = MAX_PATH;

            err = RegEnumValueW(
                hk, idx, subkey, &sublen,
                NULL, NULL, (PBYTE)name, &namelen);

            if (err != ERROR_SUCCESS) break;
            printf("%ws\n", name);
        }
        RegCloseKey(hk);
    }
}
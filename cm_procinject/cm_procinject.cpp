#include <Windows.h>
#include <iostream>

#include "ntStructs.h"

#include "Early Cascade APC Injection.h"
#include "atombombing.h"
#include "processHypnosis.h"
#include "ewmi.h"
#include "suspendinject.h"
#include "kctcallback.h"
#include "clipbrdwndclass.h"
#include "propagate.h"
#include "ListPlanting.h"
#include "eminject.h"
#include "wnfcallback.h"
#include "ctrlinject.h"
#include "alpccallback.h"
#include "dnscallback.h"
#include "conhostinject.h"
#include "knowndlls.h"
#include "svcIDEinject.h"

_NtQueryInformationProcess NtQueryInformationProcess = NULL;
_NtDuplicateObject NtDuplicateObject = NULL;
_NtUpdateWnfStateData NtUpdateWnfStateData = NULL;
_NtQuerySystemInformation NtQuerySystemInformation = NULL;
_NtQueryObject NtQueryObject = NULL;
_RtlInitUnicodeString RtlInitUnicodeString = NULL;
_NtConnectPort NtConnectPort = NULL;

_NtCreateDirectoryObject NtCreateDirectoryObject = NULL;
_RtlDosPathNameToNtPathName RtlDosPathNameToNtPathName = NULL;
_NtOpenFile NtOpenFile = NULL;
_NtCreateSection NtCreateSection = NULL;
_NtSuspendProcess NtSuspendProcess = NULL;
_NtResumeProcess NtResumeProcess = NULL;



/*
* 根据手法
* 去掉：13种手法重复、过时POC，剩余：20 POC
* modify thread
T1055.002 Remote Thread Injection（经典的wpm和远程线程创建）
T1055.003 Suspend-Inject-Resume 【THREAD EXECUTION HIJACKING 】（经典的挂起、恢复进程）
T1055.004 APC Injection	（经典的利用APC注入的方式）
T1055.004 EarlyBird-APC-Injection（利用了进程启动过程中nttestalert来执行apc，对于检测来说缺少了apc的执行原语）
T1055.004 Early Cascade APC Injection（缺少了apc的插入过程，第一段shellcode负责在进程中自插入apc，第二段shellcode就是apc要执行的内容）
ThreadPool injection （及其常用 针对threadpool的注入）
进程休眠poc：https://github.com/CarlosG13/Process-Hypnosis-Debugger-assisted-control-flow-hijack（）

>>bh议题，但是过于冷门，而且需要目标进程中有fiber： fiber : FLS Callback Injection
>>bh议题，但是过于冷门，而且需要目标进程中有fiber： Remote Dormant Fiber Injection
## 仅限于自己进程，没有用，并且和后面的两个方法重复 T1055.002 Windows Fibers Injection


* Windows Class
## （一般用于hook注入）SetwindowshookEx 但是es认为常用
窗口子类化 PROPagate Injection
窗口类 CLIPBRDWNDCLASS Injection
窗口类 eminject
窗口类 Console-Window-Host Injection
Tooltip or Common Controls （tooltips_class32 窗口注入）

## （和Console-Window-Host Injection、tooltips_class32基本相似）T1055.011 窗口类 SetWindowLong （EWMI）Injection

* modify callback
EDR-Preloading Injection（篡改进程中的AvrfpAPILookupCallbackRoutine回调，指向shellcode，利用得当也可阻断edr的客户端dll）
T1574.013 KCT(kernel call table) Injection（修改kct表中的回调，涉及到写PEB，可以保留）
Service Control Injection（修改内部调度条目里的回调，执行shellcode）
Exception-Dispatching injection（VEH、SEH）
ctrl Injection（修改目标进程中的handlerlist的指针，修改对应的处理函数，使其指向shellcoce）
DNS Client API Callback（利用unt路径处理回调实现注入）
T1055.005 Thread Local Storage Injection
RICHEDIT Controls Injection（通过发消息实现，实现一个控件的即可）

## 3.17 增：DLL加载回调注入（篡改进程中dll加载回调结构中的指针，来执行shellcode）
## 找、改、发请求，无非是位置不同，请求的API不同 ALPC Callback
## 找、改、发请求，无非是位置不同，请求的API不同  WNF Callback
## 思路和callback重复，而且无法主动触发 Instrumentation Callback（需要目标进程自己触发syscall执行）
## 需要目标进程处于"兼容模式"，才能实现这个回调 Shim Engine Injection
## 确实存在回调函数，但是是在64位上执行32位的回调，现在已经很冷门了 WOW64 Callback Table (FinFisher)
## 2017年被微软默认禁用 - Breaking BaDDEr
## 要篡改的指针在win10中消失，该手法失去意义 MPR DLL and Shell Notifications
## visa之后就过时了，Winsock Helper Functions (WSHX) Injection

* other
Stackbombing	 ROP
Atombombing

## 和上面的都是全局原子表类型，重复了。tagcls injection
## 不产生新线程的都叫ThreadLess，这个手法就是inline hook ThreadLess Injection


* （一般可选参数）根据 写原语 几个特殊的
1、wpm（default）
2、map（-m）需要特定地址的不行，拿不到句柄的不行

* （一般可选参数）DLL注入
1、默认情况下注入的是内置的shellcode，通过 -f 可以选择外部shellcode文件
2、通过 -d 参数选择是否注入dll，后面需要跟dll路径

* 示例：
*	cm_procinject.exe <POC num> -f shellcode.bin
*	cm_procinject.exe <POC num> -d <dll path>
*	cm_procinject.exe <POC num> -m
*	cm_procinject.exe <POC num> -f shellcode.bin -m
*	……
*/

BOOL InitNtApi()
{
	HMODULE lib = LoadLibraryW(L"ntdll.dll");
	if (lib == NULL) {
		return FALSE;
	}
	NtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(lib, "NtQueryInformationProcess");
	if (NtQueryInformationProcess == NULL) {
		return FALSE;
	}

	NtUpdateWnfStateData = (_NtUpdateWnfStateData)GetProcAddress(lib, "NtUpdateWnfStateData");
	if (NtUpdateWnfStateData == NULL) {
		return FALSE;
	}

	NtDuplicateObject = (_NtDuplicateObject)GetProcAddress(lib, "NtDuplicateObject");
	if (NtDuplicateObject == NULL) {
		return FALSE;
	}

	NtQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddress(lib, "NtQuerySystemInformation");
	if (NtQuerySystemInformation == NULL) {
		return FALSE;
	}

	NtQueryObject = (_NtQueryObject)GetProcAddress(lib, "NtQueryObject");
	if (NtQueryObject == NULL) {
		return FALSE;
	}

	RtlInitUnicodeString = (_RtlInitUnicodeString)GetProcAddress(lib, "RtlInitUnicodeString");
	if (RtlInitUnicodeString == NULL) {
		return FALSE;
	}NtConnectPort;

	NtConnectPort = (_NtConnectPort)GetProcAddress(lib, "NtConnectPort");
	if (NtConnectPort == NULL) {
		return FALSE;
	}

	NtCreateDirectoryObject = (_NtCreateDirectoryObject)GetProcAddress(lib, "NtCreateDirectoryObject");
	if (NtCreateDirectoryObject == NULL) {
		return FALSE;
	}

	RtlDosPathNameToNtPathName = (_RtlDosPathNameToNtPathName)GetProcAddress(lib, "RtlDosPathNameToNtPathName_U_WithStatus");
	if (RtlDosPathNameToNtPathName == NULL) {
		return FALSE;
	}

	NtOpenFile = (_NtOpenFile)GetProcAddress(lib, "NtOpenFile");
	if (NtOpenFile == NULL) {
		return FALSE;
	}

	NtCreateSection = (_NtCreateSection)GetProcAddress(lib, "NtCreateSection");
	if (NtCreateSection == NULL) {
		return FALSE;
	}

	NtResumeProcess = (_NtResumeProcess)GetProcAddress(lib, "NtResumeProcess");
	if (NtResumeProcess == NULL) {
		return FALSE;
	}

	NtSuspendProcess = (_NtSuspendProcess)GetProcAddress(lib, "NtSuspendProcess");
	if (NtSuspendProcess == NULL) {
		return FALSE;
	}


	return TRUE;
}


INT wmain(INT argc, PWCHAR argv[])
{

	wprintf_s(
		L"  ____                                     ___          _              _    _               \n"
		L" |  _ \\  _ __  ___    ___  ___  ___  ___  |_ _| _ __   (_)  ___   ___ | |_ (_)  ___   _ __  \n"
		L" | |_) || '__|/ _ \\  / __|/ _ \\/ __|/ __|  | | | '_ \\  | | / _ \\ / __|| __|| | / _ \\ | '_ \\ \n"
		L" |  __/ | |  | (_) || (__|  __/\\__ \\\\__ \\  | | | | | | | ||  __/| (__ | |_ | || (_) || | | |\n"
		L" |_|    |_|   \\___/  \\___|\\___||___/|___/ |___||_| |_|_/ | \\___| \\___| \\__||_| \\___/ |_| |_|\n"
		L"                                                     |__/                                   \n"
	);

	wprintf_s(
		L"\nExecute Shellcode By Modify Thread \n\n"
		L"	<1> Remote Thread Injection\n\n"
		L"	<2> Suspend Process Injection\n\n"
		L"	<3> APC Injection\n\n"
		L"	<4> EarlyBird APC Injection\n\n"
		L"	<5> Early Cascade APC Injection\n\n"
		L"	<6> Fiber Local Storage Injection\n\n"
		L"	<7> Remote Dormant Fiber Injection\n\n"


		L"\nExecute Shellcode By Modify CallBack \n"
		L"\nExecute Shellcode By Windows Class \n"
		L"\nExecute Shellcode By Other way\n"

	);

	if (!InitNtApi())
	{
		printf("init nt api ponit failed\n");
		return 1;
	}

	/*
	* 本周核心：添加threadpool注入
	*
	* 0616 周一 ： 预计添加alpc callback ×
	*			   预计添加instrumentation callback injction ×
	*			   添加9种新手法 √
	*
	* https://github.com/itaymigdal/awesome-injection  今天不实现，但是记录一下
	* - 将shellcode按照section的方式map过去
	* - 任何直接利用rwx内存方式的注入都是扯淡，因为压根找不到（Mocking jay Injection  嘲笑松鸦注射）
	* - https://github.com/Dec0ne/DllNotificationInjection 2年前的。
	* - https://github.com/TheD1rkMtr/D1rkInject 2年前的（可能是未收集）
	* - https://github.com/maziland/StackBombing
	* - https://github.com/S3cur3Th1sSh1t/Caro-Kann 2年前的（可能是未收集）像一种绕过方式
	* - https://github.com/woldann/GhostInjector ghost Injector  3week ago 一种dll注入方式
	* - Ghost Writing1 7年前，2针对x86，意义不大
	* - https://github.com/OtterHacker/SetProcessInjection 2年前的（可能是未收集）SetProcessInjection
	* - https://github.com/hasherezade/thread_namecalling 几个月前的，利用线程名称进行注入
	* - https://github.com/hasherezade/waiting_thread_hijacking 几周前的，利用覆盖掉等待线程的返回地址实现注入
	* - https://github.com/Friends-Security/RedirectThread 几周前，新时代的线程劫持注入
	* -
	* - IFEO劫持：17年首次出现，需要管理员权限改注册表，意义不大
	*
	* 0617 周二 ： 预计将modexp的所有poc迁移过来
	*			   将已有代码进行归纳格式化
	*/

	//testmain();


	/*
	* 线程操控
	*/
	// RemoteThreadInjectExecute();
	// suspandthreat_injection_main1();
	// 
	// APC1_injection_main();
	// APCearlybrid_injection();
	// apccascadeExecute();
	// 
	// processHypnosisExecute();


	/*
	* Windows窗口类
	*/
	// EWMIExecute();
	// PropagateExecute();
	// ListPlantingExecute();
	// clipbrdwndclassExecute();
	// eminjectExecute();
	// SetWindowsHookExExecute();

	/*
	* callback
	*/
	//wnfcallbackExecute();
	//kctcallbackExecute();
	//ctrlinjectExecute();

	//AlpcCallbackExecute();
	//dnscallbackExecute();  // 找到了，但是指针是0，没有意义,手法疑似失效
	//ConhostInjectExecute();


	/*
	* 其他手法
	*/
	//AtombombingExecute();
	//knowndllsExecute();

	return 0;
}

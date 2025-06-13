#include <Windows.h>
#include "ntStructs.h"

typedef NTSTATUS(NTAPI* _NtQueryInformationProcess)(
	_In_ HANDLE ProcessHandle,
	_In_ PROCESSINFOCLASS ProcessInformationClass,
	_Out_writes_bytes_(ProcessInformationLength) PVOID ProcessInformation,
	_In_ ULONG ProcessInformationLength,
	_Out_opt_ PULONG ReturnLength
	);
extern _NtQueryInformationProcess NtQueryInformationProcess;
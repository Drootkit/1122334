
#include <windows.h>


#define GDI_HANDLE_BUFFER_SIZE32 34
#define GDI_HANDLE_BUFFER_SIZE64 60

#ifndef _WIN64
#define GDI_HANDLE_BUFFER_SIZE GDI_HANDLE_BUFFER_SIZE32
#else
#define GDI_HANDLE_BUFFER_SIZE GDI_HANDLE_BUFFER_SIZE64
#endif

#define RTL_MAX_DRIVE_LETTERS 32
#define RTL_DRIVE_LETTER_VALID (USHORT)0x0001

#define RVA2VA(type, base, rva) (type)((ULONG_PTR) base + rva)


typedef enum _PROCESSINFOCLASS {
    ProcessBasicInformation = 0,
    ProcessQuotaLimits = 1,
    ProcessIoCounters = 2,
    ProcessVmCounters = 3,
    ProcessTimes = 4,
    ProcessBasePriority = 5,
    ProcessRaisePriority = 6,
    ProcessDebugPort = 7,
    ProcessExceptionPort = 8,
    ProcessAccessToken = 9,
    ProcessLdtInformation = 10,
    ProcessLdtSize = 11,
    ProcessDefaultHardErrorMode = 12,
    ProcessIoPortHandlers = 13,
    ProcessPooledUsageAndLimits = 14,
    ProcessWorkingSetWatch = 15,
    ProcessUserModeIOPL = 16,
    ProcessEnableAlignmentFaultFixup = 17,
    ProcessPriorityClass = 18,
    ProcessWx86Information = 19,
    ProcessHandleCount = 20,
    ProcessAffinityMask = 21,
    ProcessPriorityBoost = 22,
    ProcessDeviceMap = 23,
    ProcessSessionInformation = 24,
    ProcessForegroundInformation = 25,
    ProcessWow64Information = 26,
    ProcessImageFileName = 27,
    ProcessLUIDDeviceMapsEnabled = 28,
    ProcessBreakOnTermination = 29,
    ProcessDebugObjectHandle = 30,
    ProcessDebugFlags = 31,
    ProcessHandleTracing = 32,
    ProcessIoPriority = 33,
    ProcessExecuteFlags = 34,
    ProcessTlsInformation = 35,
    ProcessCookie = 36,
    ProcessImageInformation = 37,
    ProcessCycleTime = 38,
    ProcessPagePriority = 39,
    ProcessInstrumentationCallback = 40,
    ProcessThreadStackAllocation = 41,
    ProcessWorkingSetWatchEx = 42,
    ProcessImageFileNameWin32 = 43,
    ProcessImageFileMapping = 44,
    ProcessAffinityUpdateMode = 45,
    ProcessMemoryAllocationMode = 46,
    ProcessGroupInformation = 47,
    ProcessTokenVirtualizationEnabled = 48,
    ProcessOwnerInformation = 49,
    ProcessWindowInformation = 50,
    ProcessHandleInformation = 51,
    ProcessMitigationPolicy = 52,
    ProcessDynamicFunctionTableInformation = 53,
    ProcessHandleCheckingMode = 54,
    ProcessKeepAliveCount = 55,
    ProcessRevokeFileHandles = 56,
    ProcessWorkingSetControl = 57,
    ProcessHandleTable = 58,
    ProcessCheckStackExtentsMode = 59,
    ProcessCommandLineInformation = 60,
    ProcessProtectionInformation = 61,
    ProcessMemoryExhaustion = 62,
    ProcessFaultInformation = 63,
    ProcessTelemetryIdInformation = 64,
    ProcessCommitReleaseInformation = 65,
    ProcessReserved1Information = 66,
    ProcessReserved2Information = 67,
    ProcessSubsystemProcess = 68,
    ProcessInPrivate = 70,
    ProcessRaiseUMExceptionOnInvalidHandleClose = 71,
    ProcessSubsystemInformation = 75,
    ProcessWin32kSyscallFilterInformation = 79,
    ProcessEnergyTrackingState = 82,
    MaxProcessInfoClass
} PROCESSINFOCLASS;

// ------------------------  KCT ------------------------
typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _CURDIR
{
    UNICODE_STRING DosPath;
    HANDLE Handle;
} CURDIR, * PCURDIR;

// user32.dll!apfnDispatch
typedef struct _KERNELCALLBACKTABLE_T {
    ULONG_PTR __fnCOPYDATA;
    ULONG_PTR __fnCOPYGLOBALDATA;
    ULONG_PTR __fnDWORD;
    ULONG_PTR __fnNCDESTROY;
    ULONG_PTR __fnDWORDOPTINLPMSG;
    ULONG_PTR __fnINOUTDRAG;
    ULONG_PTR __fnGETTEXTLENGTHS;
    ULONG_PTR __fnINCNTOUTSTRING;
    ULONG_PTR __fnPOUTLPINT;
    ULONG_PTR __fnINLPCOMPAREITEMSTRUCT;
    ULONG_PTR __fnINLPCREATESTRUCT;
    ULONG_PTR __fnINLPDELETEITEMSTRUCT;
    ULONG_PTR __fnINLPDRAWITEMSTRUCT;
    ULONG_PTR __fnPOPTINLPUINT;
    ULONG_PTR __fnPOPTINLPUINT2;
    ULONG_PTR __fnINLPMDICREATESTRUCT;
    ULONG_PTR __fnINOUTLPMEASUREITEMSTRUCT;
    ULONG_PTR __fnINLPWINDOWPOS;
    ULONG_PTR __fnINOUTLPPOINT5;
    ULONG_PTR __fnINOUTLPSCROLLINFO;
    ULONG_PTR __fnINOUTLPRECT;
    ULONG_PTR __fnINOUTNCCALCSIZE;
    ULONG_PTR __fnINOUTLPPOINT5_;
    ULONG_PTR __fnINPAINTCLIPBRD;
    ULONG_PTR __fnINSIZECLIPBRD;
    ULONG_PTR __fnINDESTROYCLIPBRD;
    ULONG_PTR __fnINSTRING;
    ULONG_PTR __fnINSTRINGNULL;
    ULONG_PTR __fnINDEVICECHANGE;
    ULONG_PTR __fnPOWERBROADCAST;
    ULONG_PTR __fnINLPUAHDRAWMENU;
    ULONG_PTR __fnOPTOUTLPDWORDOPTOUTLPDWORD;
    ULONG_PTR __fnOPTOUTLPDWORDOPTOUTLPDWORD_;
    ULONG_PTR __fnOUTDWORDINDWORD;
    ULONG_PTR __fnOUTLPRECT;
    ULONG_PTR __fnOUTSTRING;
    ULONG_PTR __fnPOPTINLPUINT3;
    ULONG_PTR __fnPOUTLPINT2;
    ULONG_PTR __fnSENTDDEMSG;
    ULONG_PTR __fnINOUTSTYLECHANGE;
    ULONG_PTR __fnHkINDWORD;
    ULONG_PTR __fnHkINLPCBTACTIVATESTRUCT;
    ULONG_PTR __fnHkINLPCBTCREATESTRUCT;
    ULONG_PTR __fnHkINLPDEBUGHOOKSTRUCT;
    ULONG_PTR __fnHkINLPMOUSEHOOKSTRUCTEX;
    ULONG_PTR __fnHkINLPKBDLLHOOKSTRUCT;
    ULONG_PTR __fnHkINLPMSLLHOOKSTRUCT;
    ULONG_PTR __fnHkINLPMSG;
    ULONG_PTR __fnHkINLPRECT;
    ULONG_PTR __fnHkOPTINLPEVENTMSG;
    ULONG_PTR __xxxClientCallDelegateThread;
    ULONG_PTR __ClientCallDummyCallback;
    ULONG_PTR __fnKEYBOARDCORRECTIONCALLOUT;
    ULONG_PTR __fnOUTLPCOMBOBOXINFO;
    ULONG_PTR __fnINLPCOMPAREITEMSTRUCT2;
    ULONG_PTR __xxxClientCallDevCallbackCapture;
    ULONG_PTR __xxxClientCallDitThread;
    ULONG_PTR __xxxClientEnableMMCSS;
    ULONG_PTR __xxxClientUpdateDpi;
    ULONG_PTR __xxxClientExpandStringW;
    ULONG_PTR __ClientCopyDDEIn1;
    ULONG_PTR __ClientCopyDDEIn2;
    ULONG_PTR __ClientCopyDDEOut1;
    ULONG_PTR __ClientCopyDDEOut2;
    ULONG_PTR __ClientCopyImage;
    ULONG_PTR __ClientEventCallback;
    ULONG_PTR __ClientFindMnemChar;
    ULONG_PTR __ClientFreeDDEHandle;
    ULONG_PTR __ClientFreeLibrary;
    ULONG_PTR __ClientGetCharsetInfo;
    ULONG_PTR __ClientGetDDEFlags;
    ULONG_PTR __ClientGetDDEHookData;
    ULONG_PTR __ClientGetListboxString;
    ULONG_PTR __ClientGetMessageMPH;
    ULONG_PTR __ClientLoadImage;
    ULONG_PTR __ClientLoadLibrary;
    ULONG_PTR __ClientLoadMenu;
    ULONG_PTR __ClientLoadLocalT1Fonts;
    ULONG_PTR __ClientPSMTextOut;
    ULONG_PTR __ClientLpkDrawTextEx;
    ULONG_PTR __ClientExtTextOutW;
    ULONG_PTR __ClientGetTextExtentPointW;
    ULONG_PTR __ClientCharToWchar;
    ULONG_PTR __ClientAddFontResourceW;
    ULONG_PTR __ClientThreadSetup;
    ULONG_PTR __ClientDeliverUserApc;
    ULONG_PTR __ClientNoMemoryPopup;
    ULONG_PTR __ClientMonitorEnumProc;
    ULONG_PTR __ClientCallWinEventProc;
    ULONG_PTR __ClientWaitMessageExMPH;
    ULONG_PTR __ClientWOWGetProcModule;
    ULONG_PTR __ClientWOWTask16SchedNotify;
    ULONG_PTR __ClientImmLoadLayout;
    ULONG_PTR __ClientImmProcessKey;
    ULONG_PTR __fnIMECONTROL;
    ULONG_PTR __fnINWPARAMDBCSCHAR;
    ULONG_PTR __fnGETTEXTLENGTHS2;
    ULONG_PTR __fnINLPKDRAWSWITCHWND;
    ULONG_PTR __ClientLoadStringW;
    ULONG_PTR __ClientLoadOLE;
    ULONG_PTR __ClientRegisterDragDrop;
    ULONG_PTR __ClientRevokeDragDrop;
    ULONG_PTR __fnINOUTMENUGETOBJECT;
    ULONG_PTR __ClientPrinterThunk;
    ULONG_PTR __fnOUTLPCOMBOBOXINFO2;
    ULONG_PTR __fnOUTLPSCROLLBARINFO;
    ULONG_PTR __fnINLPUAHDRAWMENU2;
    ULONG_PTR __fnINLPUAHDRAWMENUITEM;
    ULONG_PTR __fnINLPUAHDRAWMENU3;
    ULONG_PTR __fnINOUTLPUAHMEASUREMENUITEM;
    ULONG_PTR __fnINLPUAHDRAWMENU4;
    ULONG_PTR __fnOUTLPTITLEBARINFOEX;
    ULONG_PTR __fnTOUCH;
    ULONG_PTR __fnGESTURE;
    ULONG_PTR __fnPOPTINLPUINT4;
    ULONG_PTR __fnPOPTINLPUINT5;
    ULONG_PTR __xxxClientCallDefaultInputHandler;
    ULONG_PTR __fnEMPTY;
    ULONG_PTR __ClientRimDevCallback;
    ULONG_PTR __xxxClientCallMinTouchHitTestingCallback;
    ULONG_PTR __ClientCallLocalMouseHooks;
    ULONG_PTR __xxxClientBroadcastThemeChange;
    ULONG_PTR __xxxClientCallDevCallbackSimple;
    ULONG_PTR __xxxClientAllocWindowClassExtraBytes;
    ULONG_PTR __xxxClientFreeWindowClassExtraBytes;
    ULONG_PTR __fnGETWINDOWDATA;
    ULONG_PTR __fnINOUTSTYLECHANGE2;
    ULONG_PTR __fnHkINLPMOUSEHOOKSTRUCTEX2;
} KERNELCALLBACKTABLE;


typedef struct _RTL_DRIVE_LETTER_CURDIR
{
    USHORT Flags;
    USHORT Length;
    ULONG TimeStamp;
    UNICODE_STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, * PRTL_DRIVE_LETTER_CURDIR;

typedef struct _RTL_USER_PROCESS_PARAMETERS
{
    ULONG MaximumLength;
    ULONG Length;

    ULONG Flags;
    ULONG DebugFlags;

    HANDLE ConsoleHandle;
    ULONG ConsoleFlags;
    HANDLE StandardInput;
    HANDLE StandardOutput;
    HANDLE StandardError;

    CURDIR CurrentDirectory;
    UNICODE_STRING DllPath;
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
    PVOID Environment;

    ULONG StartingX;
    ULONG StartingY;
    ULONG CountX;
    ULONG CountY;
    ULONG CountCharsX;
    ULONG CountCharsY;
    ULONG FillAttribute;

    ULONG WindowFlags;
    ULONG ShowWindowFlags;
    UNICODE_STRING WindowTitle;
    UNICODE_STRING DesktopInfo;
    UNICODE_STRING ShellInfo;
    UNICODE_STRING RuntimeData;
    RTL_DRIVE_LETTER_CURDIR CurrentDirectories[RTL_MAX_DRIVE_LETTERS];

    ULONG_PTR EnvironmentSize;
    ULONG_PTR EnvironmentVersion;
    PVOID PackageDependencyData;
    ULONG ProcessGroupId;
    ULONG LoaderThreads;

    UNICODE_STRING RedirectionDllName; // REDSTONE4
    UNICODE_STRING HeapPartitionName; // 19H1
    ULONG_PTR DefaultThreadpoolCpuSetMasks;
    ULONG DefaultThreadpoolCpuSetMaskCount;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB_LDR_DATA
{
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID      EntryInProgress;

} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _PEB_FREE_BLOCK
{
    struct _PEB_FREE_BLOCK* Next;
    ULONG Size;

} PEB_FREE_BLOCK, * PPEB_FREE_BLOCK;

typedef struct _PEB
{
    BOOLEAN InheritedAddressSpace;      // These four fields cannot change unless the
    BOOLEAN ReadImageFileExecOptions;   //
    BOOLEAN BeingDebugged;              //
    BOOLEAN SpareBool;                  //
    HANDLE Mutant;                      // INITIAL_PEB structure is also updated.

    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    PVOID SubSystemData;
    PVOID ProcessHeap;
    PVOID FastPebLock;
    PVOID FastPebLockRoutine;
    PVOID FastPebUnlockRoutine;
    ULONG EnvironmentUpdateCount;
    PVOID KernelCallbackTable;
    HANDLE SystemReserved;
    PVOID  AtlThunkSListPtr32;
    PPEB_FREE_BLOCK FreeList;
    ULONG TlsExpansionCounter;
    PVOID TlsBitmap;
    ULONG TlsBitmapBits[2];         // relates to TLS_MINIMUM_AVAILABLE
    PVOID ReadOnlySharedMemoryBase;
    PVOID ReadOnlySharedMemoryHeap;
    PVOID* ReadOnlyStaticServerData;
    PVOID AnsiCodePageData;
    PVOID OemCodePageData;
    PVOID UnicodeCaseTableData;

    //
    // Useful information for LdrpInitialize

    ULONG NumberOfProcessors;
    ULONG NtGlobalFlag;

    //
    // Passed up from MmCreatePeb from Session Manager registry key
    //

    LARGE_INTEGER CriticalSectionTimeout;
    ULONG HeapSegmentReserve;
    ULONG HeapSegmentCommit;
    ULONG HeapDeCommitTotalFreeThreshold;
    ULONG HeapDeCommitFreeBlockThreshold;

    //
    // Where heap manager keeps track of all heaps created for a process
    // Fields initialized by MmCreatePeb.  ProcessHeaps is initialized
    // to point to the first free byte after the PEB and MaximumNumberOfHeaps
    // is computed from the page size used to hold the PEB, less the fixed
    // size of this data structure.
    //

    ULONG NumberOfHeaps;
    ULONG MaximumNumberOfHeaps;
    PVOID* ProcessHeaps;

    //
    //
    PVOID GdiSharedHandleTable;
    PVOID ProcessStarterHelper;
    PVOID GdiDCAttributeList;
    PVOID LoaderLock;

    //
    // Following fields filled in by MmCreatePeb from system values and/or
    // image header. These fields have changed since Windows NT 4.0,
    // so use with caution
    //

    ULONG OSMajorVersion;
    ULONG OSMinorVersion;
    USHORT OSBuildNumber;
    USHORT OSCSDVersion;
    ULONG OSPlatformId;
    ULONG ImageSubsystem;
    ULONG ImageSubsystemMajorVersion;
    ULONG ImageSubsystemMinorVersion;
    ULONG ImageProcessAffinityMask;
    ULONG GdiHandleBuffer[GDI_HANDLE_BUFFER_SIZE];

} PEB, * PPEB;
// ------------------------

typedef struct _PROCESS_BASIC_INFORMATION {
    PVOID Reserved1;
    PPEB PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PROCESS_BASIC_INFORMATION, *PPROCESS_BASIC_INFORMATION;

// ------------------------  KCT end------------------------



// ------------------------ wnf callback ------------------------

#define WNF_STATE_KEY                0x41C64E6DA3BC0074

  // kernel-mode structures
#define WNF_NODE_SCOPE_MAP           0x901
#define WNF_NODE_SCOPE_INSTANCE      0x902
#define WNF_NODE_NAME_INSTANCE       0x903
#define WNF_NODE_STATE_DATA          0x904
#define WNF_NODE_SUBSCRIBE_INSTANCE  0x905
#define WNF_NODE_PROCESS_CONTEXT     0x906

// user-mode structures
#define WNF_NODE_SUBSCRIPTION_TABLE  0x911
#define WNF_NODE_NAME_SUBSCRIPTION   0x912
#define WNF_NODE_SERIALIZATION_GROUP 0x913
#define WNF_NODE_USER_SUBSCRIPTION   0x914

typedef enum _WNF_STATE_NAME_LIFETIME {
    WnfWellKnownStateName = 0x0,
    WnfPermanentStateName = 0x1,
    WnfPersistentStateName = 0x2,
    WnfTemporaryStateName = 0x3
} WNF_STATE_NAME_LIFETIME;

typedef enum _WNF_DATA_SCOPE {
    WnfDataScopeSystem = 0x0,
    WnfDataScopeSession = 0x1,
    WnfDataScopeUser = 0x2,
    WnfDataScopeProcess = 0x3,
    WnfDataScopeMachine = 0x4
} WNF_DATA_SCOPE;

typedef enum _WNF_STATE_NAME_INFORMATION {
    WnfInfoStateNameExist = 0x0,
    WnfInfoSubscribersPresent = 0x1,
    WnfInfoIsQuiescent = 0x2
} WNF_STATE_NAME_INFORMATION;

typedef struct _WNF_STATE_NAME_INTERNAL {
    ULONG64 Version : 4;
    ULONG64 NameLifetime : 2;
    ULONG64 DataScope : 4;
    ULONG64 PermanentData : 1;
    ULONG64 Unique : 53;
} WNF_STATE_NAME_INTERNAL, * PWNF_STATE_NAME_INTERNAL;

typedef ULONG LOGICAL;
typedef ULONG* PLOGICAL;

typedef struct _WNF_STATE_NAME {
    ULONG                             Data[2];
} WNF_STATE_NAME, * PWNF_STATE_NAME;

typedef const struct _WNF_STATE_NAME* PCWNF_STATE_NAME;

typedef struct _WNF_TYPE_ID {
    GUID                              TypeId;
} WNF_TYPE_ID, * PWNF_TYPE_ID;

typedef const WNF_TYPE_ID* PCWNF_TYPE_ID;

typedef ULONG WNF_CHANGE_STAMP, * PWNF_CHANGE_STAMP;

typedef struct _WNF_DELIVERY_DESCRIPTOR {
    ULONG64                           SubscriptionId;
    WNF_STATE_NAME                    StateName;
    WNF_CHANGE_STAMP                  ChangeStamp;
    ULONG                             StateDataSize;
    ULONG                             EventMask;
    WNF_TYPE_ID                       TypeId;
    ULONG                             StateDataOffset;
} WNF_DELIVERY_DESCRIPTOR, * PWNF_DELIVERY_DESCRIPTOR;

typedef struct _WNF_CONTEXT_HEADER {
    USHORT                            NodeTypeCode;
    USHORT                            NodeByteSize;
} WNF_CONTEXT_HEADER, * PWNF_CONTEXT_HEADER;

typedef struct _WNF_SUBSCRIPTION_TABLE {
    WNF_CONTEXT_HEADER                Header;
    SRWLOCK                           NamesTableLock;
    LIST_ENTRY                        NamesTableEntry;
    LIST_ENTRY                        SerializationGroupListHead;
    SRWLOCK                           SerializationGroupLock;
    DWORD                             Unknown1[2];
    DWORD                             SubscribedEventSet;
    DWORD                             Unknown2[2];
    PTP_TIMER                         Timer;
    ULONG64                           TimerDueTime;
} WNF_SUBSCRIPTION_TABLE, * PWNF_SUBSCRIPTION_TABLE;

typedef struct _WNF_NAME_SUBSCRIPTION {
    WNF_CONTEXT_HEADER                Header;
    ULONG64                           SubscriptionId;
    WNF_STATE_NAME_INTERNAL           StateName;
    WNF_CHANGE_STAMP                  CurrentChangeStamp;
    LIST_ENTRY                        NamesTableEntry;
    PWNF_TYPE_ID                      TypeId;
    SRWLOCK                           SubscriptionLock;
    LIST_ENTRY                        SubscriptionsListHead;
    ULONG                             NormalDeliverySubscriptions;
    ULONG                             NotificationTypeCount[5];
    PWNF_DELIVERY_DESCRIPTOR          RetryDescriptor;
    ULONG                             DeliveryState;
    ULONG64                           ReliableRetryTime;
} WNF_NAME_SUBSCRIPTION, * PWNF_NAME_SUBSCRIPTION;

typedef struct _WNF_SERIALIZATION_GROUP {
    WNF_CONTEXT_HEADER                Header;
    ULONG                             GroupId;
    LIST_ENTRY                        SerializationGroupList;
    ULONG64                           SerializationGroupValue;
    ULONG64                           SerializationGroupMemberCount;
} WNF_SERIALIZATION_GROUP, * PWNF_SERIALIZATION_GROUP;

typedef NTSTATUS(*PWNF_USER_CALLBACK) (
    WNF_STATE_NAME                    StateName,
    WNF_CHANGE_STAMP                  ChangeStamp,
    PWNF_TYPE_ID                      TypeId,
    PVOID                             CallbackContext,
    PVOID                             Buffer,
    ULONG                             BufferSize
);

typedef struct _WNF_USER_SUBSCRIPTION {
    WNF_CONTEXT_HEADER                Header;
    LIST_ENTRY                        SubscriptionsListEntry;
    PWNF_NAME_SUBSCRIPTION            NameSubscription;
    PWNF_USER_CALLBACK                Callback;
    PVOID                             CallbackContext;
    ULONG64                           SubProcessTag;
    ULONG                             CurrentChangeStamp;
    ULONG                             DeliveryOptions;
    ULONG                             SubscribedEventSet;
    PWNF_SERIALIZATION_GROUP          SerializationGroup;
    ULONG                             UserSubscriptionCount;
    ULONG64                           Unknown[10];
} WNF_USER_SUBSCRIPTION, * PWNF_USER_SUBSCRIPTION;

typedef struct _CT_CONTEXT {
    PTP_WORK                          WorkItem;
    PWNF_USER_SUBSCRIPTION            Subscription;
    HANDLE                            hEvent;
} CT_CONTEXT, * PCT_CONTEXT;

typedef struct _tagWnfName {
    const WCHAR* Name;
    ULONG64      StateName;
} WnfName;

// ------------------------ wnf callback ------------------------

// ------------------------ alpc callback ------------------------
typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR  ObjectTypeIndex;
    UCHAR  HandleAttributes;
    USHORT HandleValue;
    PVOID  Object;
    ULONG  GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

typedef struct _OBJECT_NAME_INFORMATION {
    UNICODE_STRING Name;
} OBJECT_NAME_INFORMATION, * POBJECT_NAME_INFORMATION;

typedef struct _ACTIVATION_CONTEXT* PACTIVATION_CONTEXT;
typedef struct _TP_CALLBACK_OBJECT {
    ULONG                             RefCount;
    PVOID                             CleanupGroupMember;
    PTP_CLEANUP_GROUP                 CleanupGroup;
    PTP_CLEANUP_GROUP_CANCEL_CALLBACK CleanupGroupCancelCallback;
    PTP_SIMPLE_CALLBACK               FinalizationCallback;
    LIST_ENTRY                        WorkList;
    ULONG64                           Barrier;
    ULONG64                           Unknown1;
    SRWLOCK                           SharedLock;
    TP_SIMPLE_CALLBACK                Callback;
    PACTIVATION_CONTEXT               ActivationContext;
    ULONG64                           SubProcessTag;
    GUID                              ActivityId;
    BOOL                              WorkingOnBehalfTicket;
    PVOID                             RaceDll;
    PTP_POOL                          Pool;
    LIST_ENTRY                        GroupList;
    ULONG                             Flags;
    TP_SIMPLE_CALLBACK                CallerAddress;
    TP_CALLBACK_PRIORITY              CallbackPriority;
} TP_CALLBACK_OBJECT, * PTP_CALLBACK_OBJECT;

typedef struct _TP_POOL {
    ULONG64                           RefCount;
    ULONG64                           Version;
    LIST_ENTRY                        NumaRelatedList;
    LIST_ENTRY                        PoolList;
    PVOID                             NodeList;

    HANDLE                            WorkerFactory;
    HANDLE                            IoCompletion;
    SRWLOCK                           PoolLock;
    LIST_ENTRY                        UnknownList1;
    LIST_ENTRY                        UnknownList2;

} TP_POOL, * PTP_POOL;

typedef struct _TP_WORK {
    TP_CALLBACK_OBJECT                CallbackObject;
    PVOID                             TaskId;
    ULONG64                           Unknown[4];
} TP_WORK, * PTP_WORK;

typedef enum _OBJECT_INFORMATION_CLASS {
    ObjectBasicInformation,          // = 0
    ObjectNameInformation,          // = 1
    ObjectTypeInformation,          // = 2
    ObjectTypesInformation,         // = 3    //object handle is ignored
    ObjectHandleFlagInformation     // = 4
} OBJECT_INFORMATION_CLASS;

typedef enum _SYSTEM_INFORMATION_CLASS
{
    SystemBasicInformation,                 // 0x00 SYSTEM_BASIC_INFORMATION
    SystemProcessorInformation,             // 0x01 SYSTEM_PROCESSOR_INFORMATION
    SystemPerformanceInformation,           // 0x02
    SystemTimeOfDayInformation,             // 0x03
    SystemPathInformation,                  // 0x04
    SystemProcessInformation,               // 0x05
    SystemCallCountInformation,             // 0x06
    SystemDeviceInformation,                // 0x07
    SystemProcessorPerformanceInformation,  // 0x08
    SystemFlagsInformation,                 // 0x09
    SystemCallTimeInformation,              // 0x0A
    SystemModuleInformation,                // 0x0B SYSTEM_MODULE_INFORMATION
    SystemLocksInformation,                 // 0x0C
    SystemStackTraceInformation,            // 0x0D
    SystemPagedPoolInformation,             // 0x0E
    SystemNonPagedPoolInformation,          // 0x0F
    SystemHandleInformation,                // 0x10
    SystemObjectInformation,                // 0x11
    SystemPageFileInformation,              // 0x12
    SystemVdmInstemulInformation,           // 0x13
    SystemVdmBopInformation,                // 0x14
    SystemFileCacheInformation,             // 0x15
    SystemPoolTagInformation,               // 0x16
    SystemInterruptInformation,             // 0x17
    SystemDpcBehaviorInformation,           // 0x18
    SystemFullMemoryInformation,            // 0x19
    SystemLoadGdiDriverInformation,         // 0x1A
    SystemUnloadGdiDriverInformation,       // 0x1B
    SystemTimeAdjustmentInformation,        // 0x1C
    SystemSummaryMemoryInformation,         // 0x1D
    SystemNextEventIdInformation,           // 0x1E
    SystemEventIdsInformation,              // 0x1F
    SystemCrashDumpInformation,             // 0x20
    SystemExceptionInformation,             // 0x21
    SystemCrashDumpStateInformation,        // 0x22
    SystemKernelDebuggerInformation,        // 0x23
    SystemContextSwitchInformation,         // 0x24
    SystemRegistryQuotaInformation,         // 0x25
    SystemExtendServiceTableInformation,    // 0x26
    SystemPrioritySeperation,               // 0x27
    SystemPlugPlayBusInformation,           // 0x28
    SystemDockInformation,                  // 0x29
    //SystemPowerInformation,               // 0x2A
    //SystemProcessorSpeedInformation,      // 0x2B
    //SystemCurrentTimeZoneInformation,     // 0x2C
    //SystemLookasideInformation            // 0x2D

} SYSTEM_INFORMATION_CLASS, * PSYSTEM_INFORMATION_CLASS;

typedef struct _REMOTE_PORT_VIEW {

    ULONG Length;                       // Size of this structure
    ULONG ViewSize;                     // The size of the view (bytes)
    PVOID ViewBase;                     // Base address of the view

} REMOTE_PORT_VIEW, * PREMOTE_PORT_VIEW;

typedef struct _PORT_VIEW {

    ULONG  Length;                      // Size of this structure
    HANDLE SectionHandle;               // Handle to section object with
    // SECTION_MAP_WRITE and SECTION_MAP_READ
    ULONG  SectionOffset;               // The offset in the section to map a view for
    // the port data area. The offset must be aligned
    // with the allocation granularity of the system.
    ULONG  ViewSize;                    // The size of the view (in bytes)
    PVOID  ViewBase;                    // The base address of the view in the creator
    //
    PVOID  ViewRemoteBase;              // The base address of the view in the process
    // connected to the port.
} PORT_VIEW, * PPORT_VIEW;
// ------------------------ alpc callback end ------------------------







// ------------------------ nt api ------------------------

typedef NTSTATUS(NTAPI* _NtQueryInformationProcess)(
    _In_ HANDLE ProcessHandle,
    _In_ PROCESSINFOCLASS ProcessInformationClass,
    _Out_writes_bytes_(ProcessInformationLength) PVOID ProcessInformation,
    _In_ ULONG ProcessInformationLength,
    _Out_opt_ PULONG ReturnLength
    );
extern _NtQueryInformationProcess NtQueryInformationProcess;


// wnf callback
typedef NTSTATUS(NTAPI* _NtUpdateWnfStateData)(
    _In_ PVOID StateName,
    _In_reads_bytes_opt_(Length) const VOID* Buffer,
    _In_opt_ ULONG Length,
    _In_opt_ PCWNF_TYPE_ID TypeId,
    _In_opt_ const VOID* ExplicitScope,
    _In_ WNF_CHANGE_STAMP MatchingChangeStamp,
    _In_ LOGICAL CheckStamp
    );
extern _NtUpdateWnfStateData NtUpdateWnfStateData;

// ctrl inject
typedef HRESULT(WINAPI* _RtlEncodeRemotePointer)(
    HANDLE    ProcessHandle,
    PVOID     Ptr,
    PVOID* EncodedPtr
);
extern _RtlEncodeRemotePointer RtlEncodeRemotePointer;

typedef HRESULT(WINAPI* _RtlDecodeRemotePointer)(
    HANDLE    ProcessHandle,
    PVOID     Ptr,
    PVOID*    DecodedPtr
);
extern _RtlDecodeRemotePointer RtlDecodeRemotePointer;

typedef NTSTATUS(NTAPI* _NtDuplicateObject)(
    IN HANDLE SourceProcessHandle,
    IN HANDLE SourceHandle,
    IN HANDLE TargetProcessHandle OPTIONAL,
    OUT PHANDLE TargetHandle OPTIONAL,
    IN ACCESS_MASK DesiredAccess,
    IN ULONG HandleAttributes,
    IN ULONG Options
);
extern _NtDuplicateObject NtDuplicateObject;

typedef NTSTATUS (NTAPI* _NtConnectPort)(
    OUT PHANDLE PortHandle,
    IN  PUNICODE_STRING PortName,
    IN  PSECURITY_QUALITY_OF_SERVICE SecurityQos,
    IN  OUT PPORT_VIEW ClientView OPTIONAL,
    OUT PREMOTE_PORT_VIEW ServerView OPTIONAL,
    OUT PULONG MaxMessageLength OPTIONAL,
    IN  OUT PVOID ConnectionInformation OPTIONAL,
    IN  OUT PULONG ConnectionInformationLength OPTIONAL
);
extern _NtConnectPort NtConnectPort;
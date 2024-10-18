
#ifndef MINIDUMP_SIGNATURE
#define MINIDUMP_SIGNATURE 0x504d444d
#endif

#ifndef MINIDUMP_VERSION
#define MINIDUMP_VERSION 42899
#endif

#define MINIDUMP_IMPL_VERSION 0

#define SIZE_OF_HEADER 32
#define SIZE_OF_DIRECTORY 12
#ifdef _WIN64
#define SIZE_OF_SYSTEM_INFO_STREAM 48
#else
#define SIZE_OF_SYSTEM_INFO_STREAM 56
#endif
#define SIZE_OF_MINIDUMP_MODULE 108

#define LSASRV_DLL L"lsasrv.dll"
#ifdef _WIN64
#define LDR_POINTER_OFFSET 0x18
#define MODULE_LIST_POINTER_OFFSET 0x10
#else
#define LDR_POINTER_OFFSET 0xc
#define MODULE_LIST_POINTER_OFFSET 0xc
#endif

typedef struct _ND_LDR_DATA_TABLE_ENTRY
{
    struct _LIST_ENTRY InLoadOrderLinks;
    struct _LIST_ENTRY InMemoryOrderLinks;
    struct _LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} ND_LDR_DATA_TABLE_ENTRY, * PND_LDR_DATA_TABLE_ENTRY;

enum StreamType
{
    SystemInfoStream = 7,
    ModuleListStream = 4,
    Memory64ListStream = 9,
};

enum ProcessorArchitecture
{
    AMD64 = 9,
    INTEL = 0,
};

enum MiniDumpType
{
    MiniDumpNormal = 0,
};

typedef struct _MiniDumpHeader
{
    ULONG32       Signature;
    SHORT         Version;
    SHORT         ImplementationVersion;
    ULONG32       NumberOfStreams;
    ULONG32       StreamDirectoryRva;
    ULONG32       CheckSum;
    ULONG32       Reserved;
    ULONG32       TimeDateStamp;
    ULONG32       Flags;
} MiniDumpHeader, * PMiniDumpHeader;

typedef struct _MiniDumpDirectory
{
    ULONG32       StreamType;
    ULONG32       DataSize;
    ULONG32       Rva;
} MiniDumpDirectory, * PMiniDumpDirectory;

typedef struct _dump_context
{
    HANDLE  hProcess;
    PVOID   BaseAddress;
    ULONG32 rva;
    SIZE_T  DumpMaxSize;
    ULONG32 Signature;
    USHORT  Version;
    USHORT  ImplementationVersion;
} dump_context, * Pdump_context;

#define RVA(type, base_addr, rva) (type)(ULONG_PTR)((ULONG_PTR) base_addr + rva)

typedef struct _MiniDumpSystemInfo
{
    SHORT ProcessorArchitecture;
    SHORT ProcessorLevel;
    SHORT ProcessorRevision;
    char    NumberOfProcessors;
    char    ProductType;
    ULONG32 MajorVersion;
    ULONG32 MinorVersion;
    ULONG32 BuildNumber;
    ULONG32 PlatformId;
    ULONG32 CSDVersionRva;
    SHORT SuiteMask;
    SHORT Reserved2;
#if _WIN64
    ULONG64 ProcessorFeatures1;
    ULONG64 ProcessorFeatures2;
#else
    ULONG32 VendorId1;
    ULONG32 VendorId2;
    ULONG32 VendorId3;
    ULONG32 VersionInformation;
    ULONG32 FeatureInformation;
    ULONG32 AMDExtendedCpuFeatures;
#endif
} MiniDumpSystemInfo, * PMiniDumpSystemInfo;

#ifdef _WIN64
#define CID_OFFSET 0x40
#define TEB_OFFSET 0x30
#define PEB_OFFSET 0x60
#define READ_MEMLOC __readgsqword
#else
#define CID_OFFSET 0x20
#define TEB_OFFSET 0x18
#define PEB_OFFSET 0x30
#define READ_MEMLOC __readfsdword
#endif

typedef struct _module_info
{
    struct _module_info* next;
    ULONG64 dll_base;
    ULONG32 size_of_image;
    char dll_name[512];
    ULONG32 name_rva;
    ULONG32 TimeDateStamp;
    ULONG32 CheckSum;
} module_info, * Pmodule_info;

typedef struct _MiniDumpLocationDescriptor
{
    ULONG32 DataSize;
    ULONG32 rva;
} MiniDumpLocationDescriptor, * PMiniDumpLocationDescriptor;

typedef struct _VsFixedFileInfo
{
    ULONG32 dwSignature;
    ULONG32 dwStrucVersion;
    ULONG32 dwFileVersionMS;
    ULONG32 dwFileVersionLS;
    ULONG32 dwProductVersionMS;
    ULONG32 dwProductVersionLS;
    ULONG32 dwFileFlagsMask;
    ULONG32 dwFileFlags;
    ULONG32 dwFileOS;
    ULONG32 dwFileType;
    ULONG32 dwFileSubtype;
    ULONG32 dwFileDateMS;
    ULONG32 dwFileDateLS;
} VsFixedFileInfo, * PVsFixedFileInfo;

typedef struct _MiniDumpModule
{
    ULONG64 BaseOfImage;
    ULONG32 SizeOfImage;
    ULONG32 CheckSum;
    ULONG32 TimeDateStamp;
    ULONG32 ModuleNameRva;
    VsFixedFileInfo VersionInfo;
    MiniDumpLocationDescriptor CvRecord;
    MiniDumpLocationDescriptor MiscRecord;
    ULONG64 Reserved0;
    ULONG64 Reserved1;
} MiniDumpModule, * PMiniDumpModule;

typedef struct _MiniDumpMemoryDescriptor64
{
    struct _MiniDumpMemoryDescriptor64* next;
    ULONG64 StartOfMemoryRange;
    ULONG64 DataSize;
    DWORD   State;
    DWORD   Protect;
    DWORD   Type;
} MiniDumpMemoryDescriptor64, * PMiniDumpMemoryDescriptor64;


typedef enum _MEMORY_INFORMATION_CLASS
{
    MemoryBasicInformation,
    MemoryWorkingSetInformation,
    MemoryMappedFilenameInformation,
    MemoryRegionInformation,
    MemoryWorkingSetExInformation,
    MemorySharedCommitInformation,
    MemoryImageInformation,
    MemoryRegionInformationEx,
    MemoryPrivilegedBasicInformation,
    MemoryEnclaveImageInformation,
    MemoryBasicInformationCapped
} MEMORY_INFORMATION_CLASS, * PMEMORY_INFORMATION_CLASS;

#define STATUS_SUCCESS 0x00000000
#define STATUS_UNSUCCESSFUL 0xC0000001
#define STATUS_PARTIAL_COPY 0x8000000D
#define STATUS_ACCESS_DENIED 0xC0000022
#define STATUS_OBJECT_PATH_NOT_FOUND 0xC000003A
#define STATUS_OBJECT_NAME_NOT_FOUND 0xC0000034
#define STATUS_OBJECT_NAME_INVALID 0xc0000033
#define STATUS_SHARING_VIOLATION 0xC0000043
#define STATUS_NO_MORE_ENTRIES 0x8000001A
#define STATUS_INVALID_CID 0xC000000B
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004
#define STATUS_OBJECT_PATH_SYNTAX_BAD 0xC000003B
#define STATUS_BUFFER_TOO_SMALL 0xC0000023
#define STATUS_OBJECT_NAME_COLLISION 0xC0000035
#define STATUS_ALERTED 0x00000101

#ifdef _DEBUG
#define DPRINT(fmt, ...) printf(fmt, __VA_ARGS__)
#define PRINT_ERR(fmt, ...) printf("[ERROR]"#fmt"\n", __VA_ARGS__)
#define DPRINT_ERR(fmt, ...) printf("[ERROR]"#fmt"\n", __VA_ARGS__)

#define syscall_failed(fmt, status) printf("syscall failed. %s %d\n", fmt, status)
#define malloc_failed() printf("[ERROR] malloc failed\n")
#else
#define DPRINT(fmt, ...) do {} while(0)
#define PRINT_ERR(fmt, ...) do {} while(0)
#define DPRINT_ERR(fmt, ...) do {} while(0)
#define syscall_failed(fmt, status) do {} while(0)
#define malloc_failed() do {} while(0)
#endif

#define intAlloc(size) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size)
#define intFree(addr) HeapFree(GetProcessHeap(), 0, addr)

#define DATA_FREE(d, l) \
    if (d) { \
        memset(d, 0, l); \
        intFree(d); \
        d = NULL; \
    }


struct _RTL_BALANCED_NODE
{
    union
    {
        struct _RTL_BALANCED_NODE* Children[2];                             //0x0
        struct
        {
            struct _RTL_BALANCED_NODE* Left;                                //0x0
            struct _RTL_BALANCED_NODE* Right;                               //0x8
        };
    };
    union
    {
        struct
        {
            UCHAR Red : 1;                                                    //0x10
            UCHAR Balance : 2;                                                //0x10
        };
        ULONGLONG ParentValue;                                              //0x10
    };
};
struct XND_LDR_DATA_TABLE_ENTRY
{
    struct _LIST_ENTRY InLoadOrderLinks;                                    //0x0
    struct _LIST_ENTRY InMemoryOrderLinks;                                  //0x10
    struct _LIST_ENTRY InInitializationOrderLinks;                          //0x20
    PVOID DllBase;                                                          //0x30
    PVOID EntryPoint;                                                       //0x38
    ULONG32 SizeOfImage;                                                    //0x40
    struct _UNICODE_STRING FullDllName;                                     //0x48
    struct _UNICODE_STRING BaseDllName;                                     //0x58
    UCHAR FlagGroup[4];                                                     //0x68
    USHORT ObsoleteLoadCount;                                               //0x6c
    USHORT TlsIndex;                                                        //0x6e
    struct _LIST_ENTRY HashLinks;                                           //0x70
    ULONG TimeDateStamp;                                                    //0x80
    struct _ACTIVATION_CONTEXT* EntryPointActivationContext;                //0x88
    VOID* Lock;                                                             //0x90
    struct _LDR_DDAG_NODE* DdagNode;                                        //0x98
    struct _LIST_ENTRY NodeModuleLink;                                      //0xa0
    struct _LDRP_LOAD_CONTEXT* LoadContext;                                 //0xb0
    VOID* ParentDllBase;                                                    //0xb8
    VOID* SwitchBackContext;                                                //0xc0
    struct _RTL_BALANCED_NODE BaseAddressIndexNode;                         //0xc8
    struct _RTL_BALANCED_NODE MappingInfoIndexNode;                         //0xe0
    ULONGLONG OriginalBase;                                                 //0xf8
    union _LARGE_INTEGER LoadTime;                                          //0x100
    ULONG BaseNameHashValue;                                                //0x108
    ULONG32 LoadReason;                                                     //0x10c
    ULONG ImplicitPathOptions;                                              //0x110
    ULONG ReferenceCount;                                                   //0x114
    ULONG DependentLoadFlags;                                               //0x118
    UCHAR SigningLevel;                                                     //0x11c
    ULONG CheckSum;                                                         //0x120
};

#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))

#ifdef __cplusplus
extern "C"
#endif
BOOL NanoDumpWriteDump(
    IN Pdump_context dc);

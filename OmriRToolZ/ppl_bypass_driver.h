#pragma once
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#include <psapi.h>
#include <winternl.h>
//#include <TlHelp32.h>
//#include <DbgHelp.h>


/*IOCTL to interrogate procexp driver*/
#define IOCTL_OPEN_PROTECTED_PROCESS_HANDLE 0x8335003c 
#define IOCTL_DUPLICATE_TOKEN 0x8335000c
#define IOCTL_CLOSE_HANDLE 0x83350004

/*Ask about protection of process*/
#define ProcessProtectionInformation 0x61

#define SystemHandleInformation 0x10
#define SystemHandleInformationSize 1024 * 1024 * 2

/*Define Errors NT_SUCCESS and so*/
#define NT_SUCCESS(x) ((x) >= 0)
#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004

#define SystemHandleInformation 16
#define ObjectBasicInformation 0
#define ObjectNameInformation 1


typedef enum _PS_PROTECTED_TYPE : UCHAR
{
    PsProtectedTypeNone,
    PsProtectedTypeProtectedLight,
    PsProtectedTypeProtected,
    PsProtectedTypeMax
} PS_PROTECTED_TYPE;

typedef enum _PS_PROTECTED_SIGNER : UCHAR
{
    PsProtectedSignerNone,
    PsProtectedSignerAuthenticode,
    PsProtectedSignerCodeGen,
    PsProtectedSignerAntimalware,
    PsProtectedSignerLsa,
    PsProtectedSignerWindows,
    PsProtectedSignerWinTcb,
    PsProtectedSignerWinSystem,
    PsProtectedSignerApp,
    PsProtectedSignerMax
} PS_PROTECTED_SIGNER;

typedef struct _PS_PROTECTION
{
    union
    {
        struct
        {
            PS_PROTECTED_TYPE Type : 3;
            BOOLEAN Audit : 1;
            PS_PROTECTED_SIGNER Signer : 4;
        } s;
        UCHAR Level;
    };
} PS_PROTECTION, * PPS_PROTECTION;
//
/*Protection codes*/

/*Define NtQuerySystemInformation*/
using fNtQuerySystemInformation = NTSTATUS(WINAPI*)(
    ULONGLONG SystemInformationClass,
    PVOID SystemInformation,
    ULONGLONG SystemInformationLength,
    PULONGLONG ReturnLength
    );

/*Define NtQueryProcessInformation*/

using fNtQueryProcessInformation = NTSTATUS(WINAPI*)(
    HANDLE           ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID            ProcessInformation,
    ULONG            ProcessInformationLength,
    PULONG           ReturnLength
    );
// handle information
typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR ObjectTypeIndex;
    UCHAR HandleAttributes;
    USHORT Handle;
    PVOID Object;
    ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

// handle table information
typedef struct _SYSTEM_HANDLE_INFORMATION
{
    long NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;



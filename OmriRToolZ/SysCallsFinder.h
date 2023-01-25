#pragma once


#ifndef OB97_HEADER_H_
#define OB97_HEADER_H_

#include <Windows.h>

#define OB97_SEED 0x2924F1F8
#define OB97_ROL8(v) (v << 8 | v >> 24)
#define OB97_ROR8(v) (v >> 8 | v << 24)
#define OB97_ROX8(v) ((OB97_SEED % 2) ? OB97_ROL8(v) : OB97_ROR8(v))
#define OB97_MAX_ENTRIES 500
#define OB97_RVA2VA(Type, DllBase, Rva) (Type)((ULONG_PTR) DllBase + Rva)

// Typedefs are prefixed to avoid pollution.

typedef struct _OB97_SYSCALL_ENTRY
{
	DWORD Hash;
	DWORD Address;
} OB97_SYSCALL_ENTRY, * POB97_SYSCALL_ENTRY;

typedef struct _OB97_SYSCALL_LIST
{
	DWORD Count;
	OB97_SYSCALL_ENTRY Entries[OB97_MAX_ENTRIES];
} OB97_SYSCALL_LIST, * POB97_SYSCALL_LIST;

typedef struct _OB97_PEB_LDR_DATA {
	BYTE Reserved1[8];
	PVOID Reserved2[3];
	LIST_ENTRY InMemoryOrderModuleList;
} OB97_PEB_LDR_DATA, * POB97_PEB_LDR_DATA;

typedef struct _OB97_LDR_DATA_TABLE_ENTRY {
	PVOID Reserved1[2];
	LIST_ENTRY InMemoryOrderLinks;
	PVOID Reserved2[2];
	PVOID DllBase;
} OB97_LDR_DATA_TABLE_ENTRY, * POB97_LDR_DATA_TABLE_ENTRY;

typedef struct _OB97_PEB {
	BYTE Reserved1[2];
	BYTE BeingDebugged;
	BYTE Reserved2[1];
	PVOID Reserved3[2];
	POB97_PEB_LDR_DATA Ldr;
} OB97_PEB, * POB97_PEB;

EXTERN_C DWORD OB97_Hash(PCSTR FunctionName);
BOOL OB97_PopulateList();
EXTERN_C DWORD OB97_GetNumber(DWORD FunctionHash);



#endif

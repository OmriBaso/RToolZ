#pragma once
#include "include/syscalls.h"

EXTERN_C HANDLE GetLsassHandle(DWORD lssass_pid, DWORD Method);

EXTERN_C BOOL SetDebugPrivilege();

EXTERN_C DWORD GetBuild();

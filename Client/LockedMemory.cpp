#include "LockedMemory.h"
#include <Windows.h>
#include <stdio.h>

__declspec(allocate(".LTEXT$1")) BYTE LTEXT_START= 0;
__declspec(allocate(".LTEXT$3")) BYTE LTEXT_END = 0;

__declspec(allocate(".LDATA$1")) BYTE LDATA_START= 0;
__declspec(allocate(".LDATA$3")) BYTE LDATA_END = 0;

bool lockRange(PVOID Start, PVOID End)
{
	SIZE_T Size = (SIZE_T)End - (SIZE_T)Start;
	if (VirtualLock(Start, Size)) {
		printf("Successfully locked memory range\n");
	}
	else {
		printf("Failed to lock memory range\n");
		return false;
	}
	return true;
}

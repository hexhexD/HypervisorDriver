#pragma once
#include <Windows.h>

// Lock shellcode in memory so when we execute in kernel mode and the interrupts
// are disabled, we don't page fault and crash the system.
// TODO: Interrups are disabled during shellcode execution, curretly we are just
// praying that kernel functions with IRQL requirements just work.

#pragma section(".LTEXT$1", read, execute)
#pragma section(".LTEXT$2", read, execute)
#pragma section(".LTEXT$3", read, execute)

#pragma section(".LDATA$1", read, write)
#pragma section(".LDATA$2", read, write)
#pragma section(".LDATA$3", read, write)

#define NON_PAGED_CODE __declspec( code_seg(".LTEXT$2") ) __declspec(noinline)
// Clang doesn't supprt data_seg
// #define NON_PAGED_DATA __declspec( data_seg(".LDATA$2") ) __declspec(noinline)

extern __declspec(allocate(".LTEXT$1")) BYTE LTEXT_START;
extern __declspec(allocate(".LTEXT$3")) BYTE LTEXT_END;

// extern __declspec(allocate(".LDATA$1")) BYTE LDATA_START;
// extern __declspec(allocate(".LDATA$3")) BYTE LDATA_END;

bool lockRange(PVOID Start = &LTEXT_START, PVOID End = &LTEXT_END);

// Struct, typedefs, macros and what not
#pragma once

#include <ntifs.h>
#include <ntddk.h>
#include "ntstrsafe.h"

// VMM stuff
typedef struct _MMPTE_HARDWARE
{
	ULONGLONG Valid : 1;							 // 0x0
	ULONGLONG Writable : 1;						 // 0x0
	ULONGLONG User : 1;								 // 0x0
	ULONGLONG WriteThrough : 1;				 // 0x0
	ULONGLONG CacheDisable : 1;				 // 0x0
	ULONGLONG Accessed : 1;						 // 0x0
	ULONGLONG Dirty : 1;							 // 0x0
	ULONGLONG LargePage : 1;					 // 0x0
	ULONGLONG Global : 1;							 // 0x0
	ULONGLONG CopyOnWrite : 1;				 // 0x0
	ULONGLONG Prototyp : 1;							 // 0x0
	ULONGLONG Write : 1;							 // 0x0
	ULONGLONG PageFrameNumber : 36;		 // 0x0
	ULONGLONG ReservedForHardware : 4; // 0x0
	ULONGLONG ReservedForSoftware : 4; // 0x0
	ULONGLONG WsleAge : 4;						 // 0x0
	ULONGLONG WsleProtection : 3;			 // 0x0
	ULONGLONG NoExecute : 1;					 // 0x0
} MMPTE_HARDWARE, *PMMPTE_HARDWARE;

typedef union _MMPTE {
	ULONGLONG Long;
	MMPTE_HARDWARE Hard;
} MMPTE, *PMMPTE;

typedef union _CR3 {
	ULONGLONG QuadPart;
struct{
	ULONGLONG ignored : 3;
	ULONGLONG pageLevelWriteTrhough : 1;
	ULONGLONG pageLevelCacheDisable : 1;
	ULONGLONG ignored2 : 7;
	ULONGLONG PML4Address : 40; // This is decided by MAXPHYADDR, but it doesn't matter for since the follwing reserved has to be 0s;
	ULONGLONG reserved : 12;
};
} CR3, *PCR3;

typedef PMMPTE(*MiGetPteAddressFunc)(PVOID VirtualAddress);

typedef struct DeviceContext
{
	UINT64 MmPtesBase; // Where the PTEs are located
	DWORD GameProcessId;
	ULONGLONG PayloadPhysicalAddress;
	PMMPTE ModifiedPTE;
} DeviceContext;

#define log(fmt, ...) KdPrint(("[RagDriver] (%s) " fmt, __func__, __VA_ARGS__))

#define getDeviceContext(DeviceObject) ((DeviceContext*)DeviceObject->DeviceExtension)


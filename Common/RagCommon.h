#pragma once

#ifndef IOCTL_BASE
	#define IOCTL_BASE (0x800)
#endif

typedef enum RagIoCtlCode {
	RagIoCtlCode_MapPhysToProc = 0,
	RagIoCtlCode_CreateSystemThread = 1,
	RagIoCtlCode_ApcExperiment = 2,
} RagIoCtlCode;

#define IOCTL_MAP_PHYS_INTO_PROC CTL_CODE(FILE_DEVICE_UNKNOWN, (IOCTL_BASE + RagIoCtlCode_MapPhysToProc), METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CREATE_SYSTEM_THREAD CTL_CODE(FILE_DEVICE_UNKNOWN, (IOCTL_BASE + RagIoCtlCode_CreateSystemThread), METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_APC_EXPERIMENT CTL_CODE(FILE_DEVICE_UNKNOWN, (IOCTL_BASE + RagIoCtlCode_ApcExperiment), METHOD_BUFFERED, FILE_ANY_ACCESS)

struct ThreadData {
	ULONG ThreadID;
	int Priority;
};

typedef struct _INPUT_PARAM {
	ULONGLONG MiGetPteAddress;
	ULONGLONG MmPteBase;
	ULONGLONG PagedToBeMapped;
	ULONG ProcessId;
	ULONG Value;
} INPUT_PARAM, *PINPUT_PARAM;

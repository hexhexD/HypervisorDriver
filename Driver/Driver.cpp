#include <ntifs.h>
#include <ntddk.h>
#include <sal.h>
#include "Driver.h"
#include "DriverDeviceControl.h"
#include "Common/RagCommon.h"
#include "wdm.h"
#include "Common/intrin.h"

NTSTATUS RagCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS RagWrite(PDEVICE_OBJECT DeviceObject, PIRP Irp);

// All globals are defined in the current file
PDEVICE_OBJECT g_DeviceObject;
MiGetPteAddressFunc g_miGetPteAddress;

NTSTATUS (* mmMarkPhysicalMemoryAsBad) ( __in PPHYSICAL_ADDRESS StartAddress, __inout PLARGE_INTEGER NumberOfBytes) = nullptr;

void jansPoC() {
	// Allocate one page
	PHYSICAL_ADDRESS Highest;
	Highest.QuadPart = MAXULONG64;
	const auto Quota = PAGE_SIZE;
	const auto VA = MmAllocateContiguousMemory(Quota, Highest);
	if (!VA) {
		log("Failed to allocate memory");
	}
	log("Virtual memory at %p\n", VA);
	RtlZeroMemory(VA, Quota);
	// virtual copy test
	MM_COPY_ADDRESS VirtualCopy;
	VirtualCopy.VirtualAddress = VA;
	UINT8 DstBuffer[10];
	memset(DstBuffer, 0x1, sizeof(DstBuffer));
	SIZE_T NumberOfBytesTransferred;
	auto Status = MmCopyMemory(DstBuffer,
														 VirtualCopy,
														 sizeof(DstBuffer),
														 MM_COPY_MEMORY_VIRTUAL,
														 &NumberOfBytesTransferred);
	if (!NT_SUCCESS(Status)) {
		log("VA MmCopyMemory failed %lx.\n", Status);
	}
	if (DstBuffer[0] != 0) {
		log("VA MmCopyMemory value faild.\n");
	}
	// physical copy test
	PHYSICAL_ADDRESS PA = MmGetPhysicalAddress(VA);
	if (PA.QuadPart == 0) {
		log("MmGetPhysicalAddress failed.\n");
	}
	log("Physical address: %llx\n", PA.QuadPart);

	MM_COPY_ADDRESS PhysicalCopy;
	PhysicalCopy.PhysicalAddress.QuadPart = PA.QuadPart;
	memset(DstBuffer, 0x1, sizeof(DstBuffer));
	NumberOfBytesTransferred = 0;
	Status = MmCopyMemory(DstBuffer,
												PhysicalCopy,
												sizeof(DstBuffer),
												MM_COPY_MEMORY_PHYSICAL,
												&NumberOfBytesTransferred);
	if (!NT_SUCCESS(Status)) {
		log("PA MmCopyMemory failed %lx.\n", Status);
	}
	if (DstBuffer[0] != 0) {
		log("PA MmCopyMemory value faild.\n");
	}
	// mark physical memory as bad
	LARGE_INTEGER NumberOfBytes;
	NumberOfBytes.QuadPart = Quota;
	Status = mmMarkPhysicalMemoryAsBad(&PA, &NumberOfBytes);
	if (!NT_SUCCESS(Status)) {
		log("mmMarkPhysicalMemoryAsBad failed %lx.\n", Status);
	}
	// Test again
	NumberOfBytesTransferred = 0;
	memset(DstBuffer, 0x1, sizeof(DstBuffer));
	Status = MmCopyMemory(DstBuffer,
												PhysicalCopy,
												sizeof(DstBuffer),
												MM_COPY_MEMORY_PHYSICAL,
												&NumberOfBytesTransferred);
	if (!NT_SUCCESS(Status)) {
		log("PA2 MmCopyMemory failed %lx.\n", Status);
	}
	if (DstBuffer[0] != 0) {
		log("PA2 MmCopyMemory value faild.\n");
	}

	memset(DstBuffer, 0x1, sizeof(DstBuffer));
	NumberOfBytesTransferred = 0;
	Status = MmCopyMemory(DstBuffer,
												VirtualCopy,
												sizeof(DstBuffer),
												MM_COPY_MEMORY_VIRTUAL,
												&NumberOfBytesTransferred);
	if (!NT_SUCCESS(Status)) {
		log("VA2 MmCopyMemory failed %lx.\n", Status);
	}
	if (DstBuffer[0] != 0) {
		log("VA2 MmCopyMemory value faild.\n");
	}

	MmFreeContiguousMemory(VA);
}

void onTimeout(KDPC* Dpc, PVOID Ctx, PVOID, PVOID) {
	UNREFERENCED_PARAMETER(Dpc);
	UNREFERENCED_PARAMETER(Ctx);

	// NT_ASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL);
	KdPrint(("I'm a timeout callback\n"));
}

KTIMER Timer;
KDPC TD;

void queueATimer(ULONG Msec) {
	KeInitializeTimer(&Timer);
	KeInitializeDpc(&TD, onTimeout, nullptr);

	LARGE_INTEGER Interval;
	Interval.QuadPart = -10000LL * Msec;
	KeSetTimer(&Timer, Interval, &TD);
}

int workWithUserBuffer(ThreadData* Data)
{
	if (Data->Priority <1 || Data->Priority > 31) {
		return 0;
	}

	PETHREAD Thread;
	auto Status = PsLookupThreadByThreadId(ULongToHandle(Data->ThreadID), &Thread);
	if (!NT_SUCCESS(Status))
		return 0;

	auto OldPriority = KeSetPriorityThread(Thread, Data->Priority);
	KdPrint(("Priority change for thread %u from %d to %d succeeded!\n",
					 Data->ThreadID,
					 OldPriority,
					 Data->Priority));
	ObDereferenceObject(Thread);
	return 1;
}

NTSTATUS RagCreateClose(PDEVICE_OBJECT, PIRP Irp)
{
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS RagWrite(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	auto Status = STATUS_SUCCESS;
	ULONG_PTR Information = 0;

	auto CS = IoGetCurrentIrpStackLocation(Irp);

	do {
		if (CS->Parameters.Write.Length < sizeof(ThreadData)) {
			Status = STATUS_BUFFER_TOO_SMALL;
			break;
		}
		auto Data = static_cast<ThreadData *>(Irp->UserBuffer);
		if (Data == nullptr) {
			Status = STATUS_INVALID_PARAMETER;
			break;
		}

		__try {
			if (!workWithUserBuffer(Data)) {
				Status = STATUS_INVALID_USER_BUFFER;
				break;
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			Status = STATUS_ACCESS_VIOLATION;
		}
	} while (false);

	Irp->IoStatus.Status = Status;
	Irp->IoStatus.Information = sizeof(ThreadData);
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Status;
}

void UndoPageTableModification()
{
	log("Undoing page table modification\n");
	auto DC = getDeviceContext(g_DeviceObject);
	DC->ModifiedPTE->Long = 0;
}

void ProcessNotifyRoutineEx(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo)
{
	log("Called\n");
	auto GamePid = getDeviceContext(g_DeviceObject)->GameProcessId;
	if (!CreateInfo && GamePid != 0 && (HANDLE)GamePid == ProcessId)
		UndoPageTableModification();
}

void MyUnload(_In_ PDRIVER_OBJECT DriverObject) {
	KdPrint(("RagDriver unloading...\n"));

	PsSetCreateProcessNotifyRoutineEx(ProcessNotifyRoutineEx, TRUE);

	UNICODE_STRING SymbolicLInk = RTL_CONSTANT_STRING(LR"(\??\RagDriver)");
	IoDeleteSymbolicLink(&SymbolicLInk);
	IoDeleteDevice(DriverObject->DeviceObject);
}

extern "C" NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject,
																_In_ PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);
	DriverObject->DriverUnload = MyUnload;

	DriverObject->MajorFunction[IRP_MJ_CREATE] = RagCreateClose;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = RagCreateClose;
	DriverObject->MajorFunction[IRP_MJ_WRITE] = RagWrite;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = RagDeviceIo;

	UNICODE_STRING mmMarkPhysicalMemoryAsBadName = RTL_CONSTANT_STRING(
			L"MmMarkPhysicalMemoryAsBad");
	mmMarkPhysicalMemoryAsBad = (decltype(mmMarkPhysicalMemoryAsBad))
			MmGetSystemRoutineAddress(&mmMarkPhysicalMemoryAsBadName);

	UNICODE_STRING Name = RTL_CONSTANT_STRING(L"\\Device\\RagDriver");
	PDEVICE_OBJECT DO;
	NTSTATUS Status = IoCreateDevice(DriverObject,
																	 sizeof(DeviceContext),
																	 &Name,
																	 FILE_DEVICE_UNKNOWN,
																	 0,
																	 TRUE,
																	 &DO);
	UNICODE_STRING SymbolicName = RTL_CONSTANT_STRING(L"\\??\\RagDriver");
	g_DeviceObject = nullptr;
	Status = IoCreateSymbolicLink(&SymbolicName, &Name);
	if (!NT_SUCCESS(Status))
	{
		KdPrint(("Failed to create symbolic link (0x%08X)\n", Status));
		IoDeleteDevice(DO);
		g_DeviceObject = nullptr;
	}
	g_DeviceObject = DO;
	DO->Flags |= DO_BUFFERED_IO;
	if (!NT_SUCCESS(PsSetCreateProcessNotifyRoutineEx(ProcessNotifyRoutineEx, FALSE)))
			log("Failed to set process notify routine");

	// queueATimer(5000);
	// jansPoC();

	return STATUS_SUCCESS;
}

#include "Driver.h"
#include "Imports.h"
#include "DriverDeviceControl.h"
#include "Common/Common.h"
#include "Common/intrin.h"

extern PDEVICE_OBJECT g_DeviceObject;
extern MiGetPteAddressFunc g_miGetPteAddress;

PMMPTE getPteAddress(PVOID VirtualAddress) {
	UINT_PTR MmPteBase = getDeviceContext(g_DeviceObject)->MmPtesBase;
	UINT_PTR VA = ((UINT_PTR)VirtualAddress >> 9 & ((1LL << 39 ) - 1)) | (MmPteBase & ~7ll);

	return (PMMPTE)VA;
}

ULONGLONG getPhysicalAddress(PVOID VA) {
	auto PTE = getPteAddress(VA);
	return (PTE->Hard.PageFrameNumber << 12) | ((ULONGLONG)VA & 0xFFFll);
}

// end of VMM stuff


// This is a function because LLVM can't catch exception in line
void insertPageTableEntry(MMPTE_HARDWARE *pageBuffer, ULONGLONG PayloadPhysicalAddress)
{
	/* Sleep example
	LARGE_INTEGER Interval;
	// Want to sleep for 10 seconds
	LONGLONG inMilliseconds = 10'000;
	LONGLONG inNanoseconds = inMilliseconds * 1000'000;
	LONGLONG multipleOf100ns = inNanoseconds / 100;
	LONGLONG RelativeTime = -multipleOf100ns;
	Log("Sleeping for %lld milliseconds\n", inMilliseconds);
	Interval.QuadPart = RelativeTime;
	KeDelayExecutionThread(KernelMode, FALSE, &Interval);
	Log("Woke up from sleep");
	*/

	MMPTE_HARDWARE* pageBufferPML4 = pageBuffer;
	MMPTE_HARDWARE* pageBufferPDPT = (MMPTE_HARDWARE *)((UINT_PTR)pageBuffer + 4096);
	MMPTE_HARDWARE* pageBufferPD = (MMPTE_HARDWARE *)((UINT_PTR)pageBuffer + 4096 * 2);
	MMPTE_HARDWARE* pageBufferPT = (MMPTE_HARDWARE *)((UINT_PTR)pageBuffer + 4096 * 3);

	CR3 Cr3;
	Cr3.QuadPart = __readcr3();
	
	ULONGLONG PML4 = Cr3.PML4Address << 12;
	MM_COPY_ADDRESS PhysicalCopy;
	PhysicalCopy.PhysicalAddress.QuadPart = PML4;
	Log("PML4 Physical Address: %llx\n", PML4);
	SIZE_T NumberOfBytesTransferred;
	auto Status = MmCopyMemory(pageBufferPML4, PhysicalCopy, 512 * 8, MM_COPY_MEMORY_PHYSICAL, &NumberOfBytesTransferred);
	if (!NT_SUCCESS(Status))
	{
		Log("MmCopyMemory failed PML4 entries %lx.\n", Status);
	}
	else
	{
		const int PML4Index = 0x0FF; // Upper part of user space where dlls go. The highest index for user mode
		if (pageBufferPML4[PML4Index].Valid && pageBufferPML4[PML4Index].User)
		{
			PhysicalCopy.PhysicalAddress.QuadPart = pageBufferPML4[PML4Index].PageFrameNumber << 12;
			if (NT_SUCCESS(MmCopyMemory(pageBufferPDPT, PhysicalCopy, 512 * 8, MM_COPY_MEMORY_PHYSICAL, &NumberOfBytesTransferred)))
			{
				for (int PDPTIndex = 0; PDPTIndex < 512; PDPTIndex++)
				{
					if (pageBufferPDPT[PDPTIndex].Valid && pageBufferPDPT[PDPTIndex].User)
					{
						PhysicalCopy.PhysicalAddress.QuadPart = pageBufferPDPT[PDPTIndex].PageFrameNumber << 12;
						if (NT_SUCCESS(MmCopyMemory(pageBufferPD, PhysicalCopy, 512 * 8, MM_COPY_MEMORY_PHYSICAL, &NumberOfBytesTransferred)))
						{
							Log("PDPTIndex %d entry copy success\n", PDPTIndex);
							for (int PDIndex = 0; PDIndex < 512; PDIndex++)
							{
								if (pageBufferPD[PDIndex].Valid && pageBufferPD[PDIndex].User)
								{
									PhysicalCopy.PhysicalAddress.QuadPart = pageBufferPD[PDIndex].PageFrameNumber << 12;
									if (NT_SUCCESS(MmCopyMemory(pageBufferPT, PhysicalCopy, 512 * 8, MM_COPY_MEMORY_PHYSICAL, &NumberOfBytesTransferred)))
									{
										for (int PTIndex = 0; PTIndex < 512; PTIndex++)
										{
											if (!pageBufferPT[PTIndex].Valid)
											{
												const PVOID VA = (PVOID)(((ULONGLONG)PML4Index << 39) | ((ULONGLONG)PDPTIndex << 30) | ((ULONGLONG)PDIndex << 21) | ((ULONGLONG)PTIndex << 12));
												MMPTE_HARDWARE NewPTE = {};
												RtlCopyMemory(&NewPTE, &pageBufferPT[PTIndex], sizeof(MMPTE_HARDWARE));
												NewPTE.PageFrameNumber = PayloadPhysicalAddress >> 12;
												NewPTE.Valid = 1;
												NewPTE.User = 1;
												NewPTE.NoExecute = 0;
												NewPTE.Write = 1;
												NewPTE.WriteThrough = 0;
												NewPTE.CacheDisable = 0;
												NewPTE.Accessed = 0;
												NewPTE.Dirty = 0;
												NewPTE.LargePage = 0;
												NewPTE.Global = 0;
												NewPTE.CopyOnWrite = 0;
												NewPTE.Prototyp = 0;
												NewPTE.Write = 0;
												// Get virtual address of the PTE so we can rewrite it's content
												auto TargetPTE = getPteAddress(VA);
												TargetPTE->Hard = NewPTE;
												getDeviceContext(g_DeviceObject)->ModifiedPTE = TargetPTE;

												Log("Physical page %llx mapped to virtual address %p\n", PayloadPhysicalAddress, VA);
												goto LABEL_SUCCESS;
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
		else
		{
			Log("PML4 255 entry is not valid or not user mode, WTF");
		}
	}
	return;

LABEL_SUCCESS:
	Log("We are done here\n");
}

UINT_PTR mapPagesIntoTarget(DWORD ProcessID, ULONGLONG PayloadPhysicalAddress)
{
	PEPROCESS GameProcess = nullptr;
	NTSTATUS Status = PsLookupProcessByProcessId((HANDLE)ProcessID, &GameProcess);

	MMPTE_HARDWARE* pageBuffer = (MMPTE_HARDWARE *)ExAllocatePool2(NonPagedPool, 4096 * 4, NULL);
	if (pageBuffer)
	{
		if (NT_SUCCESS(Status))
		{
			Status = PsAcquireProcessExitSynchronization(GameProcess);
			if (NT_SUCCESS(Status))
			{
				HANDLE GameProcessHandle = nullptr;
				Status = ObOpenObjectByPointer(GameProcess,
																			 OBJ_KERNEL_HANDLE,
																			 NULL,
																			 PROCESS_ALL_ACCESS,
																			 *PsProcessType,
																			 KernelMode,
																			 &GameProcessHandle);
				if (NT_SUCCESS(Status))
				{
					Log("GameProcessHandle: %p\n", GameProcessHandle);
					KAPC_STATE apcState;
					KeStackAttachProcess(GameProcess, &apcState);
					__try
					{
						insertPageTableEntry(pageBuffer, PayloadPhysicalAddress);
					}
					__except (EXCEPTION_EXECUTE_HANDLER) {}
					KeUnstackDetachProcess(&apcState);
					ZwClose(GameProcessHandle);
					GameProcessHandle = nullptr;
				}
				PsReleaseProcessExitSynchronization(GameProcess);
			}
			ObDereferenceObject(GameProcess);
		}
		ExFreePool(pageBuffer);
	}
	return 0;
}


NTSTATUS IoMapPhysToProc(ULONG_PTR *Information,
												 PVOID SystemBuffer,
												 DeviceContext *DC,
												 ULONG InputBufferLength,
												 ULONG OutputBufferLength,
												 PVOID UserBuffer) {
	auto Status = STATUS_UNSUCCESSFUL;
	if (InputBufferLength != sizeof(INPUT_PARAM)) {
		Status = STATUS_INVALID_PARAMETER;
		return Status;
	}
	INPUT_PARAM *Input = static_cast<INPUT_PARAM *>(SystemBuffer);
	DC->GameProcessId = Input->ProcessId;
	g_miGetPteAddress =	(MiGetPteAddressFunc)Input->MiGetPteAddress;
	DC->MmPtesBase = *(PUINT64)Input->MmPteBase;

	Log("ProcessId: %d\n", DC->GameProcessId);
	Log("MiGetPteAddress at: %p\n", g_miGetPteAddress);
	Log("MmPteBase at: %p\n", Input->MmPteBase);
	Log("MmPteBase value: %llX\n", DC->MmPtesBase);
	
	ULONGLONG PhysicalMemory = getPhysicalAddress((PVOID)Input->PagedToBeMapped);
	DC->PayloadPhysicalAddress = PhysicalMemory;
	Log("PagedToBeMapped at: %p\n", Input->PagedToBeMapped);
	Log("PagedToBeMapped PhysicalMemory: %llX\n", PhysicalMemory);
	mapPagesIntoTarget(DC->GameProcessId, DC->PayloadPhysicalAddress);

	Status = STATUS_SUCCESS;
	return Status;
}

void exampleSystemThread() {
	PETHREAD EThread;
	__asm {
		push rax
		mov rax, gs:188
		mov EThread, rax
		pop rax
	}

	Log("Current CR3: %llX, _ETHREAD at %p\n", __readcr3(), PsGetCurrentThread());
}

IO_WORKITEM_ROUTINE_EX workRoutineEx;
void workRoutineEx(PVOID DeviceObject, PVOID Context, PIO_WORKITEM WorkItem) {
	Log("Work routine called\n");
	IoFreeWorkItem(WorkItem);
}

NTSTATUS IoCreateSystemThread(ULONG_PTR *Information,
												 PVOID SystemBuffer,
												 DeviceContext *DC,
												 ULONG InputBufferLength,
												 ULONG OutputBufferLength,
												 PVOID UserBuffer) {
	Log("CR3 of usermode caller of DeviceIoControl : %llx\n", __readcr3());
	HANDLE SystemThread;
	// get current process
	PEPROCESS CurrentProcess = 0;
	__asm {
		push rax
		mov rax, gs:0x188
		mov rax, [rax + 0xB8] // _KTHREAD->ApcState->Process
		mov CurrentProcess, rax
		pop rax
	}
	Log("asm result: %p, API result: %p\n", CurrentProcess, PsGetCurrentProcess());

	HANDLE CurrentProcessHandle;
	auto Status = ObOpenObjectByPointer(CurrentProcess, NULL, NULL, PROCESS_ALL_ACCESS, *PsProcessType, KernelMode, &CurrentProcessHandle);
	if (NT_SUCCESS(Status)) {
		PsCreateSystemThread(&SystemThread, (ACCESS_MASK)NULL, NULL, CurrentProcessHandle, NULL, (PKSTART_ROUTINE)exampleSystemThread, NULL);
		ZwClose(CurrentProcessHandle);
	}
	Log("Create system thread again without a process handle\n");
	PsCreateSystemThread(&SystemThread, (ACCESS_MASK)NULL, NULL, (HANDLE)NULL, NULL, (PKSTART_ROUTINE)exampleSystemThread, NULL);

	// Work items
	PIO_WORKITEM Work = IoAllocateWorkItem(g_DeviceObject);
	IoQueueWorkItemEx(Work, workRoutineEx, DelayedWorkQueue, NULL);
	
	return STATUS_SUCCESS;
}

void enableVMX()
{
	UINT64 CR4_VMXE = 1 << 13;
	__writecr4(__readcr4() | CR4_VMXE);
}

NTSTATUS DeviceControl(PDEVICE_OBJECT DO, PIRP Irp) {
	NTSTATUS Status = STATUS_INVALID_DEVICE_REQUEST;
	ULONG_PTR Information = 0;
	PVOID SystemBuffer = Irp->AssociatedIrp.SystemBuffer;
	auto SP = IoGetCurrentIrpStackLocation(Irp);
	auto InputBufferLength = SP->Parameters.DeviceIoControl.InputBufferLength;
	auto OutputBufferLength = SP->Parameters.DeviceIoControl.OutputBufferLength;
	DeviceContext *DC = getDeviceContext(DO);
	Log("RagDeviceIo called");

	switch (SP->Parameters.DeviceIoControl.IoControlCode)
	{
	case IOCTL_MAP_PHYS_INTO_PROC:
	{
		Status = IoMapPhysToProc(&Information,
														 SystemBuffer,
														 DC,
														 InputBufferLength,
														 OutputBufferLength,
														 Irp->UserBuffer);
	}
	case IOCTL_CREATE_SYSTEM_THREAD:
		Status = IoCreateSystemThread(&Information,
																	SystemBuffer,
																	DC,
																	InputBufferLength,
																	OutputBufferLength,
																	Irp->UserBuffer);
	default:
		break;
	}

	Irp->IoStatus.Status = Status;
	Irp->IoStatus.Information = Information;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Status;
}

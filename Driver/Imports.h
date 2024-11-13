#pragma once

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

extern "C" NTSTATUS ZwQueryDirectoryObject(HANDLE, PVOID, ULONG, BOOLEAN, BOOLEAN, PULONG, PULONG);
extern "C" void* PsGetProcessSectionBaseAddress(struct _KPROCESS*);
extern "C" PVOID RtlImageDirectoryEntryToData(PVOID, BOOLEAN, USHORT, PULONG);
extern "C" NTSTATUS PsAcquireProcessExitSynchronization(PEPROCESS);
extern "C" void PsReleaseProcessExitSynchronization(PEPROCESS);
extern "C" NTSTATUS ObReferenceObjectByName(PUNICODE_STRING, ULONG, PACCESS_STATE, ACCESS_MASK, POBJECT_TYPE, KPROCESSOR_MODE, PVOID, PVOID*);
extern "C" NTSTATUS NtQuerySystemInformation(unsigned int, PVOID, ULONG, PULONG);
extern "C" NTSTATUS NtQuerySystemInformationEx(unsigned int, PVOID, ULONG, PVOID, ULONG, PULONG);
extern "C" NTSTATUS ZwQuerySection(HANDLE, int, PVOID, ULONG, PULONG);
extern "C" NTSTATUS ObOpenObjectByName(POBJECT_ATTRIBUTES, POBJECT_TYPE, KPROCESSOR_MODE, PACCESS_STATE, ACCESS_MASK, PVOID, PHANDLE);
extern "C" const char* PsGetProcessImageFileName(PEPROCESS);
extern "C" void ExfUnblockPushLock(PULONG_PTR, struct _EX_PUSH_LOCK_WAIT_BLOCK*);
extern "C" PVOID PsGetCurrentThreadWin32Thread();
extern "C" PVOID PsGetThreadWin32Thread(PETHREAD);

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

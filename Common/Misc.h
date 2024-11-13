#include <windows.h>
#include <winternl.h>
#include <dbghelp.h>
#include <sal.h>
#include <Shlwapi.h>

#include <filesystem>
#include <string>
#include <string_view>
#include <fstream>
#include <filesystem>
#include "symsrvdll.h"

#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "Shlwapi.lib")

#if 1
#define LOG(fmt, ...) printf("%s: " fmt, __func__, ##__VA_ARGS__)
#else
#define LOG(fmt, ...)
#endif

#define SystemModuleInformation 0xB

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
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

// Existing file is overwritten
inline bool
createFileFromMemory(const std::string_view Path, const char *Buf, size_t Sz) {
	std::ofstream File(Path.data(), std::ios_base::binary | std::ios_base::trunc);
	if (!File.write(Buf, Sz)) {
		printf("Failed to create file from memory, smoething might be using the existing copy\n");
		return false;
	}
	return true;
}

inline bool lastError(std::string_view Msg) {
	printf("%s (error=%lu)\n", Msg.data(), GetLastError());
	return false;
}

inline UINT64 getSystemModuleBaseAddress(std::string ModuleName)
{
	// RTL_PROCESS_MODULES Info[1];
	// Fails with C0000005 if buffer too small
	RTL_PROCESS_MODULES *Info = (RTL_PROCESS_MODULES *)
			VirtualAlloc(nullptr, 1024 * 100, MEM_COMMIT, PAGE_READWRITE);
	auto Status = NtQuerySystemInformation(
			(SYSTEM_INFORMATION_CLASS)SystemModuleInformation,
			Info,
			1024 * 100,
			NULL);
	if (!NT_SUCCESS(Status)) {
		printf("Failed to query systeminformation %lX\n", Status);
		return 0;
	}
	for (int i = 0; i < Info->NumberOfModules; ++i) {
		if (StrStrIA((const char *)Info->Modules[i].FullPathName, ModuleName.c_str())) {
			UINT64 ModulelBase = (UINT64)Info->Modules[i].IMAGEBase;
			LOG("FullPathName: %s\n", Info->Modules[i].FullPathName);
			LOG("IMAGEBase: %llX\n", ModulelBase);
			return ModulelBase;
		}
	}
	return 0;
}

// Get valid address in kernel space
inline UINT64 getSystemSymbolOffset(_In_ const std::string &ModuleName,
																		_In_ const std::string &FunctionName) {
	UINT64 Offset = 0;
	HANDLE PseudoHandle = (HANDLE)1234;
	SymSetOptions(SYMOPT_UNDNAME);
	if (!SymInitializeW(PseudoHandle, L"SRV*https://msdl.microsoft.com/download/symbols", FALSE)) {
		lastError("SymInitialize failed\n");
		return 0;
	}

	TCHAR	System[MAX_PATH];
	if (GetSystemDirectory(System, MAX_PATH) == 0) {
		lastError("GetSystemWindowsDirectory failed\n");
		return 0;
	}
	std::wstring SystemDir(System);

	std::wstring SymsrvPath = SystemDir + L"\\symsrv.dll";
	if (!createFileFromMemory(std::filesystem::path(SymsrvPath).string(), (char *)SymsrvDllBytes, sizeof(SymsrvDllBytes)))
		LOG("Make sure you are running as admin\n");

	std::wstring ModulePath = SystemDir + L"\\" + std::wstring(ModuleName.begin(), ModuleName.end());

	DWORD64 BaseAddr = 0;
	DWORD64 BaseOfImage = 0;
	BaseOfImage = SymLoadModuleExW(PseudoHandle, NULL, ModulePath.c_str(), NULL, BaseAddr, 0, NULL, 0);

	if (BaseOfImage == 0) {
		lastError("SymLoadModuleEx failed\n");
		SymCleanup(PseudoHandle);
		return 0;
	}
	ULONG64 buffer[(sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR) + sizeof(ULONG64) - 1) / sizeof(ULONG64)];
	PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)buffer;
	pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
	pSymbol->MaxNameLen = MAX_SYM_NAME;
	if (!SymFromName(PseudoHandle, FunctionName.c_str(), pSymbol)) {
		lastError("SymFromName failed");
		SymCleanup(PseudoHandle);
		return 0;
	}
	if (pSymbol->Address <= BaseOfImage) {
		LOG("SymFromName returned invalid address\n");
		SymCleanup(PseudoHandle);
		return 0;
	}
	Offset = (ULONG)(pSymbol->Address - BaseOfImage);
	LOG("%s offset is: %llX\n", FunctionName.c_str(), Offset);

	SymCleanup(PseudoHandle);
	return Offset;
}

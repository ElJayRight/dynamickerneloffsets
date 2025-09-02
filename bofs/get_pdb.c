#include <windows.h>
//#include "structs.h"
#include "beacon.h"

#pragma pack(push, 1)
typedef struct _CV_INFO_PDB70
{
  DWORD  CvSignature;
  GUID Signature;
  DWORD Age;
  BYTE PdbFileName[];
} CV_INFO_PDB70;

#pragma pack(pop)

long rva_to_offset(DWORD rva, IMAGE_SECTION_HEADER *sections, int nsects) {
    for (int i = 0; i < nsects; i++) {
        DWORD va = sections[i].VirtualAddress; DWORD sz = sections[i].SizeOfRawData;
        if (rva >= va && rva < va + sz) {
            return (rva - va) + sections[i].PointerToRawData;
        }
    }
    return -1; // not found
}

DECLSPEC_IMPORT HANDLE KERNEL32$CreateFileA(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
DECLSPEC_IMPORT BOOL KERNEL32$ReadFile(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
DECLSPEC_IMPORT BOOL KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT HANDLE KERNEL32$GetProcessHeap();
DECLSPEC_IMPORT BOOL KERNEL32$SetFilePointerEx(HANDLE, LARGE_INTEGER, PLARGE_INTEGER, DWORD);
DECLSPEC_IMPORT LPVOID KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
DECLSPEC_IMPORT BOOL KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);
DECLSPEC_IMPORT int USER32$wsprintfA(LPSTR, LPCSTR, ...);

//int main(int argc, char* argv[]){
void go(char* args, int argc){

		datap Parser = { 0 };
        PSTR filename = { 0 };
        int Length = { 0 };

        BeaconDataParse(&Parser, args, argc);

        filename = BeaconDataExtract(&Parser, &Length);

        BeaconPrintf( CALLBACK_OUTPUT, "Parsed Arguments: \n"
                        " - filename: %s [%d bytes]\n",
                        filename, Length);

	HANDLE hFile = KERNEL32$CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE){
		BeaconPrintf( CALLBACK_ERROR, "File not found\n");
		return;
	}

	IMAGE_DOS_HEADER dos_header = { 0 };
	DWORD dwBytesRead = 0;

	BOOL result = KERNEL32$ReadFile(hFile, &dos_header, sizeof(dos_header), &dwBytesRead, NULL);
	if (dos_header.e_magic != 0x5a4d){ // MZ
		BeaconPrintf(CALLBACK_ERROR, "Not a valid PE File\n");
		KERNEL32$CloseHandle(hFile);
		return;
	}
	LARGE_INTEGER liDistance = {0};
	liDistance.QuadPart = dos_header.e_lfanew;

	result = KERNEL32$SetFilePointerEx(hFile, liDistance, NULL, FILE_BEGIN);
	IMAGE_NT_HEADERS64 nt_header = { 0 };
	KERNEL32$ReadFile(hFile, &nt_header, sizeof(nt_header), &dwBytesRead, NULL);
	if (nt_header.Signature != 0x00004550){ // PE\0\0
		BeaconPrintf(CALLBACK_ERROR, "Bad PE signature\n");
		KERNEL32$CloseHandle(hFile);
		return;
	}

	int nt_sections = nt_header.FileHeader.NumberOfSections;

	HANDLE heap = KERNEL32$GetProcessHeap();
	IMAGE_SECTION_HEADER *sections = (IMAGE_SECTION_HEADER *)KERNEL32$HeapAlloc(heap, HEAP_ZERO_MEMORY, nt_sections*sizeof(IMAGE_SECTION_HEADER));
	KERNEL32$ReadFile(hFile, sections, sizeof(IMAGE_SECTION_HEADER)*nt_sections, &dwBytesRead, NULL);

	IMAGE_DATA_DIRECTORY debug_directory_info = nt_header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];

	if (debug_directory_info.VirtualAddress == 0 || debug_directory_info.Size == 0) {
		BeaconPrintf(CALLBACK_ERROR, "No debug directories found.\n");
		KERNEL32$HeapFree(heap, 0, sections);
		KERNEL32$CloseHandle(hFile);
		return;
	}

	long debug_directory_offset = rva_to_offset(debug_directory_info.VirtualAddress, sections, nt_sections);
	if (debug_directory_offset == -1){
		BeaconPrintf(CALLBACK_ERROR, "Could not find offset.\n");
		KERNEL32$HeapFree(heap, 0, sections);
		KERNEL32$CloseHandle(hFile);
		return;
	}

    int count = debug_directory_info.Size / sizeof(IMAGE_DEBUG_DIRECTORY);

    BeaconPrintf(CALLBACK_OUTPUT, "$$Debug Directory: RVA=0x%x Size=%u -> offset=0x%lx (%d entries)\n", debug_directory_info.VirtualAddress, debug_directory_info.Size, debug_directory_offset, count);

	liDistance.QuadPart = debug_directory_offset;
	result = KERNEL32$SetFilePointerEx(hFile, liDistance, NULL, FILE_BEGIN);
    for (int i = 0; i < count; i++) {
        IMAGE_DEBUG_DIRECTORY dir = {0};
		KERNEL32$ReadFile(hFile, &dir, sizeof(dir), &dwBytesRead, NULL);
		if (dir.Type == 2){

			void *buf = KERNEL32$HeapAlloc(heap, HEAP_ZERO_MEMORY, dir.SizeOfData);

			//CV_INFO_PDB70 cv_info_obj = { 0 };
			liDistance.QuadPart = dir.PointerToRawData;
			KERNEL32$SetFilePointerEx(hFile, liDistance, NULL, FILE_BEGIN);
			KERNEL32$ReadFile(hFile, buf, dir.SizeOfData, &dwBytesRead, NULL);

			CV_INFO_PDB70 *cv_info_obj = (CV_INFO_PDB70 *)buf;
			//fread(&cv_info_obj, sizeof(cv_info_obj), 1, fp);

			if ( cv_info_obj->CvSignature != 0x53445352){
				BeaconPrintf(CALLBACK_ERROR, "Not a valid PDB7 Signature\n");
				return;
			}
			/*
			printf("Valid CodeView (RSDS) record found\n");
			printf("  GUID: %08x-%04x-%04x",
				   cv_info_obj->Signature.Data1,
				   cv_info_obj->Signature.Data2,
				   cv_info_obj->Signature.Data3);
			for (int i = 0; i < 2; i++) printf("%02x", cv_info_obj->Signature.Data4[i]);
			printf("-");
			for (int i = 2; i < 8; i++) printf("%02x", cv_info_obj->Signature.Data4[i]);
			printf("\n");

			printf("  Age: %u\n", cv_info_obj->Age);
			printf("  PDB: %s\n", cv_info_obj->PdbFileName);
			*/


			char *guid_string = (char *)KERNEL32$HeapAlloc(heap, HEAP_ZERO_MEMORY, 64);
			int offset = USER32$wsprintfA(guid_string, "%08x%04x%04x",
					cv_info_obj->Signature.Data1,
					cv_info_obj->Signature.Data2,
					cv_info_obj->Signature.Data3);

			for (int i = 0; i < 8; i++){
				offset += USER32$wsprintfA(guid_string + offset, "%02x", cv_info_obj->Signature.Data4[i]);

			}

			BeaconPrintf(CALLBACK_OUTPUT, "$$Download path: https://msdl.microsoft.com/download/symbols/%s/%s",
					cv_info_obj->PdbFileName,
					guid_string);

			BeaconPrintf(CALLBACK_OUTPUT, "%u/%s\n", cv_info_obj->Age, cv_info_obj->PdbFileName);

			KERNEL32$HeapFree(heap, 0, buf);

		}
    }

	KERNEL32$HeapFree(heap, 0, sections);
	KERNEL32$CloseHandle(hFile);

	return;
}

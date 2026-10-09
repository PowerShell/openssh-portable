
#include "w32fd.h"
#include "inc\utf.h"
#include "misc_internal.h"
#include "debug.h"

#include <Windows.h>
#include <winternl.h>
#include <sys/stat.h>


static const NTSTATUS STATUS_SUCCESS = 0;

#define MAX_EA_INFO_SIZE 64

#pragma pack(push, 1)
typedef struct _FILE_FULL_EA_INFORMATION {
	ULONG                   NextEntryOffset;
	BYTE                    Flags;
	BYTE                    EaNameLength;
	USHORT                  EaValueLength;
	CHAR                    EaName[1];
} FILE_FULL_EA_INFORMATION, * PFILE_FULL_EA_INFORMATION;

#pragma pack(pop)

typedef
NTSTATUS
(NTAPI* NtSetEaFileFn)(
	IN HANDLE               FileHandle,
	OUT PIO_STATUS_BLOCK    IoStatusBlock,
	IN PVOID                EaBuffer,
	IN ULONG                EaBufferSize);

struct ea_keyvalue {
	const char* name;
	const char* value;
	ULONG value_len;
};

static void lxss_set_ea_info(wchar_t* path, char* buffer, ULONG length, int reparse){
	IO_STATUS_BLOCK ioStatus;
	NTSTATUS r;
	HMODULE hmod = GetModuleHandleW(L"ntdll.dll");
	if (hmod == NULL)
		return;
	NtSetEaFileFn NtSetEaFile = (NtSetEaFileFn)GetProcAddress(hmod, "NtSetEaFile");
	if (NtSetEaFile == NULL)
		return;
	HANDLE file = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL, OPEN_EXISTING,
		FILE_FLAG_BACKUP_SEMANTICS | (reparse ? FILE_FLAG_OPEN_REPARSE_POINT : 0), NULL);
	if (file == INVALID_HANDLE_VALUE)
		return;

	r = NtSetEaFile(file, &ioStatus, buffer, length);
	if (r != STATUS_SUCCESS)
		return;
	CloseHandle(file);
}

void lxss_set_perm(wchar_t* path, int reparse, ULONG uid, ULONG gid, ULONG mode){
	struct ea_keyvalue** p;
	struct ea_keyvalue* ea[4]; // **
	int count = 0;
	struct ea_keyvalue uid_ea = {"$LXUID", (char*)&uid, sizeof(uid)};
	struct ea_keyvalue gid_ea = {"$LXGID", (char*)&gid, sizeof(gid)};
	struct ea_keyvalue mode_ea = {"$LXMOD", (char*)&mode, sizeof(mode)};
	FILE_FULL_EA_INFORMATION* ea_info = NULL;
	ea[0] = &uid_ea;
	ea[1] = &gid_ea;
	ea[2] = &mode_ea;
	ea[3] = NULL;
	__declspec(align(16)) char buffer[MAX_EA_INFO_SIZE * sizeof(ea) / sizeof(ea[0])];
	char *pb = buffer;

	for (p = ea; *p != NULL; p++) {
		ea_info = (FILE_FULL_EA_INFORMATION*)pb;
		ea_info->NextEntryOffset = MAX_EA_INFO_SIZE;
		ea_info->Flags = 0;
		ea_info->EaNameLength = (BYTE)strlen((*p)->name);
		ea_info->EaValueLength = (USHORT)(*p)->value_len;
		memcpy(ea_info->EaName, (*p)->name, ea_info->EaNameLength);
		memcpy(ea_info->EaName + ea_info->EaNameLength, (*p)->value, (*p)->value_len);
		pb += MAX_EA_INFO_SIZE;
		++count;
	}
	// mark last info
	if (ea_info)
		ea_info->NextEntryOffset = 0;
	lxss_set_ea_info(path, buffer, count * MAX_EA_INFO_SIZE, reparse);
}

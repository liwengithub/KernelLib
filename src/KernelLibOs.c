#include "KernelLibOs.h"
#include <ntifs.h>
#include <WinDef.h>
#include <Ntstrsafe.h>

VOID OsRestart()
{
	const PUCHAR KEYBOARD_DATA_PORT = (PUCHAR)0x60;
	const PUCHAR KEYBOARD_CTRL_PORT = (PUCHAR)0x64;
	const UCHAR KEYBOARD_RESET_CMD = 0xFE;

	READ_PORT_UCHAR(KEYBOARD_CTRL_PORT);
	READ_PORT_UCHAR(KEYBOARD_DATA_PORT);
	WRITE_PORT_UCHAR(KEYBOARD_CTRL_PORT, KEYBOARD_RESET_CMD);
}

ULONG OsGetMajorVersion()
{
	RTL_OSVERSIONINFOW		VerInfo = { 0 };
	ULONG					MajorVer;
	NTSTATUS				Status;

	VerInfo.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOW);
	Status = RtlGetVersion(&VerInfo);
	if (!NT_SUCCESS(Status)){
		return 0;
	}

	MajorVer = VerInfo.dwMajorVersion;
	return MajorVer;
}

ULONG OsGetMinorVersion()
{
	RTL_OSVERSIONINFOW	VerInfo = { 0 };
	ULONG					MinorVer;
	NTSTATUS				Status;

	VerInfo.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOW);
	Status = RtlGetVersion(&VerInfo);
	if (!NT_SUCCESS(Status)){
		return 0;
	}

	MinorVer = VerInfo.dwMinorVersion;
	return MinorVer;
}

ULONG OsGetBuildNumber()
{
	RTL_OSVERSIONINFOW	VerInfo = { 0 };
	ULONG					BuildNum;
	NTSTATUS				Status;

	VerInfo.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOW);
	Status = RtlGetVersion(&VerInfo);
	if (!NT_SUCCESS(Status)){
		return 0;
	}

	BuildNum = VerInfo.dwBuildNumber;
	return BuildNum;
}

BOOLEAN OsParseSymlnk(IN PUNICODE_STRING Symlnk, OUT PUNICODE_STRING Target)
{
	BOOLEAN Result = FALSE;
	NTSTATUS Status;
	HANDLE hDir = NULL;
	HANDLE hSymbolic = NULL;
	OBJECT_ATTRIBUTES ObjSymbolic;

	do
	{
		InitializeObjectAttributes(&ObjSymbolic, Symlnk, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, hDir, NULL);
		Status = ZwOpenSymbolicLinkObject(&hSymbolic, GENERIC_READ, &ObjSymbolic);
		if (!NT_SUCCESS(Status)){
			break;
		}

		Status = ZwQuerySymbolicLinkObject(hSymbolic, Target, NULL);
		if (!NT_SUCCESS(Status)){
			break;
		}
		Result = TRUE;
	} while (FALSE);

	return Result;
}

BOOLEAN OsGetPath(OUT PUNICODE_STRING Dir, IN const PWCHAR wSymbolicName)
{
	UNICODE_STRING uSymbolicName = { 0 };
	UNICODE_STRING uTargetName = { 0 };
	WCHAR wTargetName[MAX_PATH] = { 0 };
	RtlInitEmptyUnicodeString(&uTargetName, wTargetName, MAX_PATH*sizeof(WCHAR));
	RtlAppendUnicodeToString(Dir, L"\\??\\");

	RtlInitUnicodeString(&uSymbolicName, wSymbolicName);
	if (OsParseSymlnk(&uSymbolicName, &uTargetName))
	{
		RtlAppendUnicodeStringToString(Dir, &uTargetName);
		return TRUE;
	}
	return FALSE;
}

BOOLEAN	OsGetWinDir(OUT PUNICODE_STRING Dir)
{
	return OsGetPath(Dir, L"\\SystemRoot");
}

BOOLEAN OsGetSyswow64Dir(OUT PUNICODE_STRING Dir)
{
#ifdef _AMD64_
	return OsGetPath(Dir, L"\\KnownDlls32\\KnownDllPath");
#else
	return FALSE;
#endif
}

BOOLEAN OsGetSystem32Dir(OUT PUNICODE_STRING Dir)
{
	return OsGetPath(Dir, L"\\KnownDlls\\KnownDllPath");
}
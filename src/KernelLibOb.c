#include "KernelLibOb.h"
#include <ntifs.h>

BOOLEAN ObParseSymlnk(IN PUNICODE_STRING Symlnk, OUT PUNICODE_STRING Target)
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
		if (!NT_SUCCESS(Status))
		{
			KdPrint(("ERROR: Cannot open sysmbolic 0x%x \n", Status));
			break;
		}

		Status = ZwQuerySymbolicLinkObject(hSymbolic, Target, NULL);
		if (!NT_SUCCESS(Status))
		{
			KdPrint(("ERROR: Cannot query symbolic 0x%x \n", Status));
			break;
		}
		Result = TRUE;
	} while (FALSE);

	if (hSymbolic)
	{
		ZwClose(hSymbolic);
	}
	return Result;
}

BOOLEAN GetDeviceObjectByName(_In_ PUNICODE_STRING ObjectName, _Out_ PDEVICE_OBJECT* pDeviceObject)
{
	PFILE_OBJECT pFileObject = NULL;
	PDEVICE_OBJECT pObject = NULL;
	BOOLEAN ret = FALSE;
	NTSTATUS nStatus = IoGetDeviceObjectPointer(ObjectName, FILE_ALL_ACCESS, &pFileObject, &pObject);
	if (!NT_SUCCESS(nStatus))
	{
		KdPrint(("IoGetDeviceObjectPointer Fail nStauts = [0x%x]\r\n", nStatus));
	}

	if (pObject)
	{
		*pDeviceObject = pObject;
		ret = TRUE;
	}

	if (pFileObject)
	{
		ObDereferenceObject(pFileObject);
	}
	return ret;
}
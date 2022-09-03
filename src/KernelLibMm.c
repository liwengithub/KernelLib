#include "KernelLibMm.h"
#include <ntifs.h>

#ifdef _WIN64	// 64位定义

KIRQL MmWriteProtectOff()
{
	KIRQL Irql = KeRaiseIrqlToDpcLevel();
	UINT64 cr0 = __readcr0();
	cr0 &= 0xfffffffffffeffff;
	__writecr0(cr0);
	_disable();
	return Irql;
}

void MmWriteProtectOn(IN KIRQL Irql)
{
	UINT64 cr0 = __readcr0();
	cr0 |= 0x10000;
	_enable();
	__writecr0(cr0);
	KeLowerIrql(Irql);
}

#else	// 32位定义

KIRQL MmWriteProtectOff()
{
	KIRQL Irql = KeRaiseIrqlToDpcLevel();
	_asm
	{
		cli;
		push eax;
		mov  eax, cr0;
		and  eax, ~0x10000
		mov  cr0, eax;
		pop  eax;
	};
	return Irql;
}

VOID MmWriteProtectOn(IN KIRQL Irql)
{
	_asm
	{
		push eax;
		mov  eax, cr0
		or   eax, 0x10000
		mov  cr0, eax
		pop  eax;
		sti;
	};
	KeLowerIrql(Irql);
}
#endif

BOOLEAN MmSafeCopyeMemory(IN PVOID pSource, IN PVOID pDest, IN ULONG Size, IN BOOLEAN Write)
{
	PMDL		Mdl = NULL;
	PVOID		pSafeAddress = NULL;
	BOOLEAN		Result = FALSE;
	BOOLEAN		IsLockPages = FALSE;

	do
	{
		if (!MmIsAddressValid(pSource) || !MmIsAddressValid(pDest)){
			break;
		}

		Mdl = IoAllocateMdl(pSource, (ULONG)Size, FALSE, FALSE, NULL);
		if (Mdl == NULL){
			break;
		}

		__try
		{
			MmProbeAndLockPages(Mdl, KernelMode, pSource > MM_HIGHEST_USER_ADDRESS ? IoWriteAccess : IoReadAccess);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			KdPrint(("MmProbeAndLockPages Exception [0x%X]", GetExceptionCode()));
			break;
		}

		IsLockPages = TRUE;
		pSafeAddress = MmGetSystemAddressForMdlSafe(Mdl, NormalPagePriority);
		if (pSafeAddress == NULL)	{
			break;
		}

		__try
		{
			if (Write){
				RtlCopyMemory(pSafeAddress, pDest, Size);
			}
			else{
				RtlCopyMemory(pDest, pSafeAddress, Size);
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			break;
		}

		Result = TRUE;
	} while (FALSE);

	if (Mdl)
	{
		if (IsLockPages)
		{
			MmUnlockPages(Mdl);
		}
		IoFreeMdl(Mdl);
	}

	return Result;
}

BOOLEAN MmSafeReadMemory(IN PVOID pSource, IN PVOID pDest, IN ULONG Size)
{
	return MmSafeCopyeMemory(pSource, pDest, Size, FALSE);
}

BOOLEAN MmSafeWriteMemory(IN PVOID pSource, IN PVOID pDest, IN ULONG Size)
{
	return MmSafeCopyeMemory(pSource, pDest, Size, TRUE);
}

// 内存映射文件，返回基址 
// 调用者负责ZwUnmapViewOfSection(ZwCurrentProcess(), BaseAddress);
PVOID MmCreateMapFile(IN PUNICODE_STRING FilePath, OUT PULONG Size)
{
#define SEC_IMAGE 0x01000000

	PVOID MapFileBaseAddress = NULL;
	HANDLE  FileHandle = NULL;
	HANDLE  SectionHandle = NULL;
	NTSTATUS status;
	IO_STATUS_BLOCK IoStatus = { 0 };
	OBJECT_ATTRIBUTES oa = { 0 };
	SIZE_T	ViewSize = 0;

	InitializeObjectAttributes(&oa, FilePath, OBJ_CASE_INSENSITIVE, 0, 0);
	status = ZwOpenFile(&FileHandle,
		FILE_READ_DATA,
		&oa,
		&IoStatus,
		FILE_SHARE_READ,
		FILE_SYNCHRONOUS_IO_NONALERT);
	if (!NT_SUCCESS(status)){
		return NULL;
	}

	oa.ObjectName = 0;
	status = ZwCreateSection(&SectionHandle,
		SECTION_ALL_ACCESS,
		&oa,
		0,
		PAGE_READONLY,
		SEC_IMAGE,
		FileHandle);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("ZwCreateSection failed: 0x%x\n", status));
		ZwClose(FileHandle);
		return NULL;
	}

	status = ZwMapViewOfSection(SectionHandle,
		ZwCurrentProcess(),
		&MapFileBaseAddress,
		0,
		0,
		0,
		&ViewSize,
		ViewUnmap,
		0,
		PAGE_READONLY);
	*Size = (ULONG)ViewSize;

	if (!NT_SUCCESS(status))
	{
		KdPrint(("ZwMapViewOfSection failed: 0x%x\n", status));
		ZwClose(SectionHandle);
		ZwClose(FileHandle);
		return NULL;
	}

	ZwClose(SectionHandle);
	ZwClose(FileHandle);
	return MapFileBaseAddress;
}

BOOLEAN MmIsAddressSafe(IN PVOID Address, IN ULONG Size)
{
	ULONG i = 0;
	if ((PVOID)Address < MM_HIGHEST_USER_ADDRESS)
	{
		__try
		{
			ProbeForRead((PVOID)Address, Size, 1);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			return FALSE;
		}
	}
	else
	{
		for (i = 0; i < Size; i++)
		{
			if (!MmIsAddressValid((PUCHAR)Address + i))
			{
				return FALSE;
			}
		}
	}
	return TRUE;
}

PVOID MmGetSystemRoutine(IN PCWSTR FunctionName)
{
	UNICODE_STRING UsFunctionName;
	RtlInitUnicodeString(&UsFunctionName, FunctionName);
	return MmGetSystemRoutineAddress(&UsFunctionName);
}
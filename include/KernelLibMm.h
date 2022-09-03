#pragma once
#include <ntdef.h>

//Memory
VOID		MmWriteProtectOn(IN KIRQL Irql);
KIRQL		MmWriteProtectOff();
BOOLEAN		MmSafeReadMemory(IN PVOID pSource, IN PVOID pDest, IN ULONG Size);
BOOLEAN		MmSafeWriteMemory(IN PVOID pSource, IN PVOID pDest, IN ULONG Size);
PVOID		MmCreateMapFile(IN PUNICODE_STRING FilePath, OUT PULONG Size);
BOOLEAN		MmIsAddressSafe(IN PVOID Address, IN ULONG Size);
PVOID		MmGetSystemRoutine(IN PCWSTR FunctionName);
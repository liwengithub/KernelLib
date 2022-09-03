#pragma once
#include <ntifs.h>
#include <WinDef.h>

typedef enum _IMAGE_TYPE
{
	TypeImageUnknow = 0,
	TypeImageDriver,
	TypeImageDll,
	TypeImageExe,
	TypeImageMax
}IMAGE_TYPE;

//Pe
BOOLEAN		PeIsRegionValid(IN PVOID ImageBase, IN DWORD ImageSize, IN PVOID Address, IN DWORD RegionSize);
BOOLEAN		PeIsRegionSections(IN PVOID ImageBase, IN PVOID Address);
BOOLEAN		PeIsImage32(IN PVOID ImageBase);
BOOLEAN		PeIsImage64(IN PVOID ImageBase);
BOOLEAN		PeIsImageValid(IN PVOID ImageBase);
PVOID		PeGetImageNtHeader(IN PVOID ImageBase);
BOOLEAN		PeGetEntryPoint(IN PVOID ImageBase, OUT PVOID* EntryPoint);
IMAGE_TYPE	PeGetImageType(IN PVOID ImageBase);
ULONG_PTR	PeVaToOffset(IN PVOID ImageBase, IN ULONG_PTR VirtualAddress);
ULONG_PTR	PeRvaToOffset(IN PVOID ImageBase, IN ULONG_PTR RelativeVirtualAddress);
ULONG_PTR	PeOffsetToRVA(IN PVOID ImageBase, IN ULONG_PTR FileOffset);
VOID		PeFixBaseRelocationByVA(IN PVOID BaseAddress);
PVOID		PeGetProcAddress(PVOID ImageBase, ULONG ImageSize, CHAR* ProcName);
#include "KernelLibPe.h"
#include <ntimage.h>

NTSYSAPI	PPEB	PsGetProcessPeb(__in PEPROCESS Process);

#define NB10_SIG	'01BN'
#define RSDS_SIG	'SDSR'
typedef struct  CV_HEADER
{
	DWORD Signature;
	DWORD Offset;
}CV_HEADER;

typedef struct CV_INFO_PDB20
{
	CV_HEADER	CvHeader;
	DWORD		Signature;
	DWORD		Age;
	BYTE		PdbFileName[1];
}CV_INFO_PDB20;

typedef struct CV_INFO_PDB70
{
	DWORD	CvSignature;
	GUID	Signature;
	DWORD	Age;
	BYTE	PdbFileName[1];
}CV_INFO_PDB70;

typedef struct {
	WORD Offset : 12;
	WORD Type : 4;
}TYPE_OFFSET, *PTYPE_OFFSET;

BOOLEAN PeIsRegionValid(IN PVOID ImageBase, IN DWORD ImageSize, IN PVOID Address, IN DWORD RegionSize)
{
	return ((PBYTE)Address >= (PBYTE)ImageBase && ((PBYTE)Address + RegionSize) <= ((PBYTE)ImageBase + ImageSize));
}

BOOLEAN PeIsRegionSections(IN PVOID ImageBase, IN PVOID Address)
{
	PBYTE Base = (PBYTE)ImageBase;
	PIMAGE_NT_HEADERS NtHeader = NULL;
	PIMAGE_SECTION_HEADER Sections = NULL;
	PUCHAR SectionStart = NULL, SectionEnd = NULL;
	ULONG SectionSize = 0, NumberOfSection = 0, i = 0;
	BOOLEAN Result = FALSE;

	do
	{
		if (Base == NULL || Address == NULL){
			return FALSE;
		}

		NtHeader = PeGetImageNtHeader(ImageBase);
		if (NtHeader == NULL){
			break;
		}

		NumberOfSection = NtHeader->FileHeader.NumberOfSections;
		if (NumberOfSection == 0){
			break;
		}

		Sections = IMAGE_FIRST_SECTION(NtHeader);
		if (Sections == NULL){
			break;
		}

		for (i = 0; i < NumberOfSection; i++)
		{
			if (Sections[i].VirtualAddress == 0 || Sections[i].Misc.VirtualSize == 0){
				continue;
			}

			SectionStart = Sections[i].VirtualAddress + (PUCHAR)Base;
			SectionSize = Sections[i].Misc.VirtualSize;
			SectionEnd = (PUCHAR)SectionStart + SectionSize;
			if (SectionStart <= (PUCHAR)Address && (PUCHAR)Address <= SectionEnd)
			{
				if ((Sections[i].Characteristics & IMAGE_SCN_MEM_DISCARDABLE) == 0)
				{
					Result = TRUE;
					break;
				}
			}
		}
	} while (FALSE);
	
	return Result;
}

BOOLEAN PeIsImage32(IN PVOID ImageBase)
{
	PIMAGE_NT_HEADERS NtHeader = PeGetImageNtHeader(ImageBase);
	if (NtHeader->FileHeader.Machine == IMAGE_FILE_MACHINE_I386 ||
		NtHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
	{
		return TRUE;
	}
	return FALSE;
}

BOOLEAN PeIsImage64(IN PVOID ImageBase)
{
	PIMAGE_NT_HEADERS NtHeader = PeGetImageNtHeader(ImageBase);
	if (NtHeader->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 ||
		NtHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		return TRUE;
	}
	return FALSE;
}

BOOLEAN PeIsImageValid(IN PVOID ImageBase)
{
	BOOLEAN Result = FALSE;

	do
	{
		if ((PVOID)ImageBase < MM_HIGHEST_USER_ADDRESS)
		{
			__try
			{
				//if usermode adress is not Valid will raise Exception
				ProbeForRead((PVOID)ImageBase, sizeof(IMAGE_NT_HEADERS)+sizeof(IMAGE_DOS_HEADER), 1);
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				break;
			}
		}
		else
		{
			if (MmIsAddressValid(ImageBase) == FALSE)
			{
				break;
			}
		}

		if (!PeIsImage32(ImageBase) && !PeIsImage64(ImageBase)){
			break;
		}

		Result = TRUE;
	} while (FALSE);

	return Result;
}

PVOID PeGetImageNtHeader(IN PVOID ImageBase)
{
	PBYTE Base = (PBYTE)ImageBase;
	PIMAGE_DOS_HEADER	DosHeader = NULL;
	PIMAGE_NT_HEADERS	NtHeader = NULL;

	if (Base == NULL){
		return NULL;
	}

	DosHeader = (PIMAGE_DOS_HEADER)Base;
	if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE){
		return NULL;
	}

	NtHeader = (PIMAGE_NT_HEADERS)(Base + DosHeader->e_lfanew);
	if (NtHeader->Signature != IMAGE_NT_SIGNATURE){
		return NULL;
	}
	return NtHeader;
}

BOOLEAN	PeGetEntryPoint(IN PVOID ImageBase, OUT PVOID* EntryPoint)
{
	PIMAGE_NT_HEADERS NtHeader = NULL;
	if (ImageBase == NULL){
		return FALSE;
	}

	NtHeader = PeGetImageNtHeader(ImageBase);
	if (NtHeader == NULL)
	{
		return FALSE;
	}

	if (PeIsImage32(ImageBase))
	{
		PIMAGE_NT_HEADERS32 NtHeader32 = (PIMAGE_NT_HEADERS32)NtHeader;
		*EntryPoint = (PVOID)((PCHAR)ImageBase + NtHeader32->OptionalHeader.AddressOfEntryPoint);
		return TRUE;
	}
	else if (PeIsImage64(ImageBase))
	{
		PIMAGE_NT_HEADERS64 NtHeader64 = (PIMAGE_NT_HEADERS64)NtHeader;
		*EntryPoint = (PVOID)((PCHAR)ImageBase + NtHeader64->OptionalHeader.AddressOfEntryPoint);
		return TRUE;
	}
	return FALSE;
}

BOOLEAN PeIsProcess(IN PVOID ImageBase)
{
#ifdef _AMD64_
	const	ULONG ImageBaseAddressOffset = 0x10;
#else
	const	ULONG ImageBaseAddressOffset = 8;
#endif
	PPEB	Peb = PsGetProcessPeb(PsGetCurrentProcess());
	if (Peb && (ImageBase == *(PVOID*)((ULONG)Peb + ImageBaseAddressOffset)))
	{
		return TRUE;
	}
	return FALSE;
}

BOOLEAN PeIsProcess64(IN PVOID ImageBase)
{
	const	ULONG64 ImageBaseAddressOffset = 0x10;
	PPEB	Peb = PsGetProcessPeb(PsGetCurrentProcess());
	if (Peb && ImageBase == *(PVOID*)((ULONG64)Peb + ImageBaseAddressOffset))
	{
		return TRUE;
	}
	return FALSE;
}

IMAGE_TYPE PeGetImageType(IN PVOID ImageBase)
{
	PIMAGE_FILE_HEADER			FileHeader = NULL;
	IMAGE_TYPE					ImageType = TypeImageMax;

	if (PeIsImage32(ImageBase))
	{
		PIMAGE_NT_HEADERS32			NtHeader32 = NULL;
		PIMAGE_OPTIONAL_HEADER32	OpHeader32 = NULL;
		NtHeader32 = PeGetImageNtHeader(ImageBase);
		OpHeader32 = (PIMAGE_OPTIONAL_HEADER32)&NtHeader32->OptionalHeader;
		FileHeader = (PIMAGE_FILE_HEADER)&NtHeader32->FileHeader;

		if (FileHeader->Characteristics & IMAGE_FILE_DLL)
		{
			ImageType = TypeImageDll;
		}
		else if (PeIsProcess(ImageBase))
		{
			ImageType = TypeImageExe;
		}
		else if ((OpHeader32->Subsystem & IMAGE_SUBSYSTEM_NATIVE)
			&& ImageBase >= MM_HIGHEST_USER_ADDRESS)
		{
			ImageType = TypeImageDriver;
		}
	}
	else if (PeIsImage64(ImageBase))
	{
		PIMAGE_NT_HEADERS64			NtHeader64 = NULL;
		PIMAGE_OPTIONAL_HEADER64	OpHeader64 = NULL;
		NtHeader64 = PeGetImageNtHeader(ImageBase);
		OpHeader64 = (PIMAGE_OPTIONAL_HEADER64)&NtHeader64->OptionalHeader;
		FileHeader = (PIMAGE_FILE_HEADER)&NtHeader64->FileHeader;

		if (FileHeader->Characteristics & IMAGE_FILE_DLL)
		{
			ImageType = TypeImageDll;
		}
		else if (PeIsProcess64(ImageBase))
		{
			ImageType = TypeImageExe;
		}
		else if (OpHeader64->Subsystem & IMAGE_SUBSYSTEM_NATIVE
			&& ImageBase >= MM_HIGHEST_USER_ADDRESS)
		{
			ImageType = TypeImageDriver;
		}
	}
	return ImageType;
}

ULONG_PTR PeVaToOffset(IN PVOID BaseAddress, IN ULONG_PTR VirtualAddress)
{
	PIMAGE_NT_HEADERS NtHeader = NULL;
	PIMAGE_OPTIONAL_HEADER OptionalHeader = NULL;
	PIMAGE_SECTION_HEADER SectionHeader = NULL;
	ULONG_PTR ImageBase = 0;
	ULONG_PTR Alignment = 0;
	ULONG_PTR AlignmentSize = 0;
	ULONG_PTR Begin = 0;
	ULONG_PTR End = 0;

	NtHeader = (PIMAGE_NT_HEADERS)((ULONG_PTR)BaseAddress + ((PIMAGE_DOS_HEADER)BaseAddress)->e_lfanew);
	OptionalHeader = &NtHeader->OptionalHeader;
	if (PeIsImage32(BaseAddress))
	{
		ImageBase = ((PIMAGE_OPTIONAL_HEADER32)OptionalHeader)->ImageBase;
		Alignment = ((PIMAGE_OPTIONAL_HEADER32)OptionalHeader)->SectionAlignment;
	}
	else
	{
		ImageBase = (ULONG_PTR)((PIMAGE_OPTIONAL_HEADER64)OptionalHeader)->ImageBase;
		Alignment = (ULONG_PTR)((PIMAGE_OPTIONAL_HEADER64)OptionalHeader)->SectionAlignment;
	}
	SectionHeader = IMAGE_FIRST_SECTION((PIMAGE_NT_HEADERS)NtHeader);

	do
	{
		AlignmentSize = 0;

		// 对齐粒度
		if (SectionHeader->Misc.VirtualSize % Alignment)
			AlignmentSize = (SectionHeader->Misc.VirtualSize + Alignment) / Alignment * Alignment;
		else
			AlignmentSize = SectionHeader->Misc.VirtualSize;

		// 计算 节 边界
		Begin = SectionHeader->VirtualAddress + ImageBase;
		End = Begin + AlignmentSize;

		// 在对应的区段计算offset
		if (Begin <= VirtualAddress && VirtualAddress < End)
		{
			return VirtualAddress - Begin + SectionHeader->PointerToRawData;
		}

		++SectionHeader;
	} while (SectionHeader->Name);

	return 0;
}

ULONG_PTR PeRvaToOffset(IN PVOID BaseAddress, IN ULONG_PTR RelativeVirtualAddress)
{
	PIMAGE_NT_HEADERS NtHeader = NULL;
	PIMAGE_OPTIONAL_HEADER OptionalHeader = NULL;
	PIMAGE_SECTION_HEADER SectionHeader = NULL;
	ULONG_PTR ImageBase = 0;
	ULONG_PTR Alignment = 0;
	ULONG_PTR AlignmentSize = 0; 
	ULONG_PTR Begin = 0;
	ULONG_PTR End = 0;

	NtHeader = (PIMAGE_NT_HEADERS)((ULONG_PTR)BaseAddress + ((PIMAGE_DOS_HEADER)BaseAddress)->e_lfanew);
	OptionalHeader = &NtHeader->OptionalHeader;
	if (PeIsImage32(BaseAddress))
	{
		ImageBase = (ULONG_PTR)((PIMAGE_OPTIONAL_HEADER32)OptionalHeader)->ImageBase;
		Alignment = (ULONG_PTR)((PIMAGE_OPTIONAL_HEADER32)OptionalHeader)->SectionAlignment;
	}
	else
	{
		ImageBase = (ULONG_PTR)((PIMAGE_OPTIONAL_HEADER64)OptionalHeader)->ImageBase;
		Alignment = (ULONG_PTR)((PIMAGE_OPTIONAL_HEADER64)OptionalHeader)->SectionAlignment;
	}
	SectionHeader = IMAGE_FIRST_SECTION((PIMAGE_NT_HEADERS)NtHeader);

	do
	{
		AlignmentSize = 0;

		// 对齐粒度
		if (SectionHeader->Misc.VirtualSize % Alignment)
			AlignmentSize = (SectionHeader->Misc.VirtualSize + Alignment) / Alignment * Alignment;
		else
			AlignmentSize = SectionHeader->Misc.VirtualSize;

		// 计算 节 边界
		Begin = SectionHeader->VirtualAddress;
		End = Begin + AlignmentSize;

		// 在对应的区段计算offset
		if (Begin <= RelativeVirtualAddress && RelativeVirtualAddress < End)
		{
			return RelativeVirtualAddress - Begin + SectionHeader->PointerToRawData;
		}

		++SectionHeader;
	} while (SectionHeader->Name);

	return 0;
}

ULONG_PTR PeOffsetToRVA(IN PVOID BaseAddress, IN ULONG_PTR FileOffset)
{
	PIMAGE_NT_HEADERS NtHeader = NULL;
	PIMAGE_OPTIONAL_HEADER OptionalHeader = NULL;
	PIMAGE_SECTION_HEADER SectionHeader = NULL;
	ULONG_PTR ImageBase = 0;
	ULONG_PTR Alignment = 0;
	ULONG_PTR AlignmentSize = 0;
	ULONG_PTR Begin = 0;
	ULONG_PTR End = 0;

	NtHeader = (PIMAGE_NT_HEADERS)((ULONG_PTR)BaseAddress + ((PIMAGE_DOS_HEADER)BaseAddress)->e_lfanew);
	OptionalHeader = &NtHeader->OptionalHeader;
	if (PeIsImage32(BaseAddress))
	{
		ImageBase = (ULONG_PTR)((PIMAGE_OPTIONAL_HEADER32)OptionalHeader)->ImageBase;
		Alignment = (ULONG_PTR)((PIMAGE_OPTIONAL_HEADER32)OptionalHeader)->SectionAlignment;
	}
	else
	{
		ImageBase = (ULONG_PTR)((PIMAGE_OPTIONAL_HEADER64)OptionalHeader)->ImageBase;
		Alignment = (ULONG_PTR)((PIMAGE_OPTIONAL_HEADER64)OptionalHeader)->SectionAlignment;
	}
	SectionHeader = IMAGE_FIRST_SECTION((PIMAGE_NT_HEADERS)NtHeader);

	do
	{
		AlignmentSize = SectionHeader->SizeOfRawData;

		// 计算 节 边界
		Begin = SectionHeader->PointerToRawData;
		End = Begin + AlignmentSize;

		if (Begin <= FileOffset && FileOffset < End)
		{
			return FileOffset - Begin + SectionHeader->VirtualAddress;
		}

		++SectionHeader;
	} while (SectionHeader->Name);

	return 0;
}

VOID PeFixBaseRelocationByVA(IN PVOID BaseAddress)
{
    PIMAGE_NT_HEADERS NtHeader = NULL;
    PIMAGE_OPTIONAL_HEADER OptionalHeader = NULL;
    PIMAGE_DATA_DIRECTORY DataDirectory = NULL;
    PIMAGE_BASE_RELOCATION BaseRelocation = NULL;
    
    PVOID ImageBase = NULL;
    ULONG_PTR SectionAlignment = 0;
    ULONG_PTR Offset = 0;
    ULONG_PTR VirtualSize = 0;

    NtHeader = (PIMAGE_NT_HEADERS)((ULONG_PTR)BaseAddress + ((PIMAGE_DOS_HEADER)BaseAddress)->e_lfanew);
    OptionalHeader = &NtHeader->OptionalHeader;
    if (PeIsImage32(BaseAddress))
    {
        if ( ((PIMAGE_OPTIONAL_HEADER32)OptionalHeader)->NumberOfRvaAndSizes <= 
            IMAGE_DIRECTORY_ENTRY_BASERELOC )
        {
            return;
        }
        DataDirectory = &(((PIMAGE_OPTIONAL_HEADER32)OptionalHeader)->DataDirectory)[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        ImageBase = (PVOID)(((PIMAGE_OPTIONAL_HEADER32)OptionalHeader)->ImageBase);
        SectionAlignment = ((PIMAGE_OPTIONAL_HEADER32)OptionalHeader)->SectionAlignment;
    }
    else
    {
        if (((PIMAGE_OPTIONAL_HEADER64)OptionalHeader)->NumberOfRvaAndSizes <=
            IMAGE_DIRECTORY_ENTRY_BASERELOC)
        {
            return;
        }
        DataDirectory = &(((PIMAGE_OPTIONAL_HEADER64)OptionalHeader)->DataDirectory)[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        ImageBase = (PVOID)(((PIMAGE_OPTIONAL_HEADER64)OptionalHeader)->ImageBase);
        SectionAlignment = ((PIMAGE_OPTIONAL_HEADER64)OptionalHeader)->SectionAlignment;
    }
    if (!DataDirectory->VirtualAddress)
    {
        return;
    }
    if (BaseAddress == ImageBase)
    {
        return;
    }

    Offset = (ULONG_PTR)BaseAddress - (ULONG_PTR)ImageBase;
    if (Offset % SectionAlignment)
    {
        VirtualSize = (Offset + SectionAlignment) / SectionAlignment * SectionAlignment;
    }
    else
    {
        VirtualSize = Offset;
    }

    BaseRelocation = (PIMAGE_BASE_RELOCATION)((ULONG_PTR)BaseAddress + DataDirectory->VirtualAddress);
    while (BaseRelocation->VirtualAddress)
    {
        ULONG TypeCount = (BaseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        PTYPE_OFFSET TypeOffset = (PTYPE_OFFSET)((ULONG_PTR)BaseRelocation + sizeof(IMAGE_BASE_RELOCATION));
		ULONG i = 0;
        for (i = 0; i < TypeCount; ++i)
        {
            switch (TypeOffset->Type)
            {
            default:
                break;

            case IMAGE_REL_BASED_HIGH:
            {
                PWORD RelocationVA = (PWORD)((ULONG_PTR)BaseAddress + BaseRelocation->VirtualAddress + TypeOffset[i].Offset);
                RelocationVA[0] += (WORD)VirtualSize;
                break;
            }

            case IMAGE_REL_BASED_LOW:
            {
                PWORD RelocationVA = (PWORD)((ULONG_PTR)BaseAddress + BaseRelocation->VirtualAddress + TypeOffset[i].Offset);
                RelocationVA[1] += (WORD)VirtualSize;
                break;
            }

            case IMAGE_REL_BASED_HIGHLOW:
            {
                PDWORD RelocationVA = (PDWORD)((ULONG_PTR)BaseAddress + BaseRelocation->VirtualAddress + TypeOffset[i].Offset);
                RelocationVA[0] += (DWORD)VirtualSize;
                break;
            }

            case IMAGE_REL_BASED_HIGHADJ:
            {
                // DWORD RelOffset = MAKELONG(TypeOffset[i + 1].offset, TypeOffset[i].offset);

                ++i;
                break;
            }

            case IMAGE_REL_BASED_DIR64:
            {
                PDWORD64 RelocationVA = (PDWORD64)((ULONG_PTR)BaseAddress + BaseRelocation->VirtualAddress + TypeOffset[i].Offset);
                RelocationVA[0] += (DWORD64)VirtualSize;
                break;
            }
            }
        }

        BaseRelocation = (PIMAGE_BASE_RELOCATION)((ULONG_PTR)BaseRelocation + BaseRelocation->SizeOfBlock);
    }
}

PVOID PeGetProcAddress(PVOID ImageBase, ULONG ImageSize, CHAR* ProcName)
{
	PIMAGE_NT_HEADERS NtHeader = NULL;
	ULONG DirIndex = IMAGE_DIRECTORY_ENTRY_EXPORT;
	IMAGE_EXPORT_DIRECTORY* ExportDir = NULL;
	ULONG ExportDirSize = 0;
	ULONG* NameAddrArr = NULL;
	ULONG i = 0;
	CHAR* FunctionName = NULL;
	USHORT* NameOrdinals = NULL;
	ULONG* Functions = NULL;
	ULONGLONG FoundFunction = 0;

	if (ImageBase == NULL) {
		return NULL;
	}

	NtHeader = PeGetImageNtHeader(ImageBase);
	if (NtHeader == NULL){
		return NULL;
	}

	ExportDir = (IMAGE_EXPORT_DIRECTORY*)((PUCHAR)ImageBase + 
		NtHeader->OptionalHeader.DataDirectory[DirIndex].VirtualAddress);
	ExportDirSize = NtHeader->OptionalHeader.DataDirectory[DirIndex].Size;
	if (!PeIsRegionValid(ImageBase, ImageSize, ExportDir, ExportDirSize)){
		return NULL;
	}

	NameAddrArr = (ULONG*)((PUCHAR)ImageBase + ExportDir->AddressOfNames);
	for (i = 0; i < ExportDir->NumberOfNames; ++i)
	{
		FunctionName = (char*)ImageBase + NameAddrArr[i];
		if (!PeIsRegionValid(ImageBase, ImageSize, ImageBase, NameAddrArr[i])){
			continue;
		}

		if (_stricmp(FunctionName, ProcName) == 0)
		{
			NameOrdinals = (USHORT*)((PUCHAR)ImageBase + ExportDir->AddressOfNameOrdinals);
			if (!PeIsRegionValid(ImageBase, ImageSize, ImageBase, ExportDir->AddressOfNameOrdinals)){
				return NULL;
			}

			Functions = (ULONG*)((PUCHAR)ImageBase + ExportDir->AddressOfFunctions);
			if (!PeIsRegionValid(ImageBase, ImageSize, ImageBase, ExportDir->AddressOfFunctions)){
				return NULL;
			}

			FoundFunction = (ULONGLONG)ImageBase + Functions[NameOrdinals[i]];
			if (!PeIsRegionValid(ImageBase, ImageSize, ImageBase, Functions[NameOrdinals[i]]))
			{
				return NULL;
			}
			else
			{
				return (PVOID)FoundFunction;
			}
		}
	}
	return NULL;
}



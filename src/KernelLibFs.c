#include "KernelLibFs.h"
#include <ntstrsafe.h>

// 得到文件大小
BOOLEAN FsGetFileSize(IN PUNICODE_STRING pFilePath, OUT PULONG pFileSize)
{
	BOOLEAN						Result = FALSE;
	NTSTATUS					Status;
	LARGE_INTEGER				li;
	IO_STATUS_BLOCK				isb;
	FILE_STANDARD_INFORMATION	FileStandardInfo;
	OBJECT_ATTRIBUTES			oa;
	HANDLE						hFile;

	if (pFilePath == NULL || pFileSize == NULL){
		return Result;
	}
	*pFileSize = 0;

	do 
	{
		InitializeObjectAttributes(&oa, pFilePath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
		Status = ZwCreateFile(&hFile,
			GENERIC_READ | SYNCHRONIZE,
			&oa,
			&isb,
			NULL,
			FILE_ATTRIBUTE_NORMAL,
			FILE_SHARE_READ,
			FILE_OPEN,
			FILE_NON_DIRECTORY_FILE|FILE_RANDOM_ACCESS| 
			FILE_NO_INTERMEDIATE_BUFFERING|
			FILE_SYNCHRONOUS_IO_NONALERT,
			NULL,
			0
			);
		if (!NT_SUCCESS(Status))
		{
			if (Status == STATUS_OBJECT_NAME_NOT_FOUND)
			{
				Result = TRUE;
			}
			KdPrint(("FsGetFileSize ZwCreateFile Failed:0x%x", Status));
			break;
		}

		// 查询文件基本信息
		Status = ZwQueryInformationFile(
			hFile,
			&isb,
			&FileStandardInfo,
			sizeof(FileStandardInfo),
			FileStandardInformation
			);
		ZwClose(hFile);
		if (!NT_SUCCESS(Status))
		{
			KdPrint(("FsGetFileSize ZwQueryInformationFile Failed:0x%x\n", Status));
			break;
		}

		// 存储文件大小
		li.QuadPart = FileStandardInfo.EndOfFile.QuadPart;
		*pFileSize = li.LowPart;
		Result = TRUE;
	}while(0);

	return Result;
}

// 判断文件是否存在
BOOLEAN FsIsFileExist(IN PUNICODE_STRING pFilePath)
{
	NTSTATUS					Status;
	IO_STATUS_BLOCK				isb;
	OBJECT_ATTRIBUTES			oa;
	HANDLE						hFile;

	if (pFilePath == NULL){
		return FALSE;
	}

	InitializeObjectAttributes(&oa, pFilePath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	Status = ZwCreateFile(&hFile,
		GENERIC_READ | SYNCHRONIZE,
		&oa,
		&isb,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ,
		FILE_OPEN,
		FILE_NON_DIRECTORY_FILE | FILE_RANDOM_ACCESS | FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0
		);

	if (hFile){
		ZwClose(hFile);
	}
	return NT_SUCCESS(Status) ? TRUE : FALSE;
}

BOOLEAN FsReadFile(IN PUNICODE_STRING pFilePath, OUT PCHAR pFileBuf, IN ULONG FileBufSize, IN PLARGE_INTEGER pFileOffset)
{
	NTSTATUS Status;
	IO_STATUS_BLOCK	isb;
	OBJECT_ATTRIBUTES oa;
	HANDLE hFile = NULL;

	if (pFilePath == NULL || pFileBuf == NULL || FileBufSize == 0){
		return FALSE;
	}

	do
	{
		InitializeObjectAttributes(&oa, pFilePath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
		Status = ZwCreateFile(&hFile,
			GENERIC_READ | SYNCHRONIZE,
			&oa,
			&isb,
			NULL,
			FILE_ATTRIBUTE_NORMAL,
			FILE_SHARE_READ,
			FILE_OPEN,
			FILE_NON_DIRECTORY_FILE | FILE_RANDOM_ACCESS |
			FILE_NO_INTERMEDIATE_BUFFERING |
			FILE_SYNCHRONOUS_IO_NONALERT,
			NULL,
			0
			);
		if (!NT_SUCCESS(Status)){
			break;
		}

		Status = ZwReadFile(hFile,
			NULL,
			NULL,
			NULL,
			&isb,
			pFileBuf,
			FileBufSize,
			pFileOffset,
			NULL
			);
	} while (FALSE);

	if (hFile != NULL){
		ZwClose(hFile);
	}
	return NT_SUCCESS(Status) ? TRUE : FALSE;
}

BOOLEAN FsWriteFile(IN PUNICODE_STRING pFilePath, IN PCHAR pFileBuf, IN ULONG FileBufSize)
{
	HANDLE hDestinFile;
	OBJECT_ATTRIBUTES ObjectAttrDestin;
	IO_STATUS_BLOCK  IoStatusBlock = { 0 };
	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	do
	{
		//"\\??\\C:\\test.txt"
		InitializeObjectAttributes(&ObjectAttrDestin, pFilePath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
		Status = ZwCreateFile(&hDestinFile,
			GENERIC_WRITE | SYNCHRONIZE,
			&ObjectAttrDestin,
			&IoStatusBlock,
			NULL,
			FILE_ATTRIBUTE_NORMAL,
			FILE_SHARE_READ,
			FILE_OPEN_IF,	//打开或新建 								
			FILE_NON_DIRECTORY_FILE | FILE_RANDOM_ACCESS |
			FILE_SYNCHRONOUS_IO_NONALERT,
			NULL,
			0
			);
		if (!NT_SUCCESS(Status)) {
			break;
		}

		Status = ZwWriteFile(hDestinFile,
			NULL,
			NULL,
			NULL,
			&IoStatusBlock,
			pFileBuf,
			FileBufSize,
			NULL,
			NULL);

	} while (FALSE);

	if (hDestinFile != NULL){
		ZwClose(hDestinFile);
	}
	return NT_SUCCESS(Status) ? TRUE : FALSE;
}

BOOLEAN FsAppendFile(IN PUNICODE_STRING pFilePath, IN PCHAR pFileBuf, IN ULONG FileBufSize)
{
	HANDLE hDestinFile;
	OBJECT_ATTRIBUTES ObjectAttrDestin;
	IO_STATUS_BLOCK  IoStatusBlock = { 0 };
	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	do
	{
		//"\\??\\C:\\test.txt"
		InitializeObjectAttributes(&ObjectAttrDestin, pFilePath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
		Status = ZwCreateFile(&hDestinFile,
			FILE_APPEND_DATA,
			&ObjectAttrDestin,
			&IoStatusBlock,
			NULL,
			FILE_ATTRIBUTE_NORMAL,
			FILE_SHARE_READ,
			FILE_OPEN_IF,	//打开或新建 								
			FILE_NON_DIRECTORY_FILE | FILE_RANDOM_ACCESS |
			FILE_SYNCHRONOUS_IO_NONALERT,
			NULL,
			0
		);
		if (!NT_SUCCESS(Status)) {
			break;
		}

		Status = ZwWriteFile(hDestinFile,
			NULL,
			NULL,
			NULL,
			&IoStatusBlock,
			pFileBuf,
			FileBufSize,
			NULL,
			NULL);

	} while (FALSE);

	if (hDestinFile != NULL) {
		ZwClose(hDestinFile);
	}
	return NT_SUCCESS(Status) ? TRUE : FALSE;
}

BOOLEAN FsRenameFile(IN PUNICODE_STRING pSrcFile, IN PUNICODE_STRING pDstFile)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	OBJECT_ATTRIBUTES oa = { sizeof(oa) };
	HANDLE FileHandle = NULL;
	IO_STATUS_BLOCK isb = { 0 };
	PFILE_RENAME_INFORMATION RenameInfo = NULL;

	PAGED_CODE();

	do
	{
		if (!pSrcFile || !pDstFile){
			break;
		}

		RenameInfo = (PFILE_RENAME_INFORMATION)ExAllocatePoolWithTag(NonPagedPool,
			sizeof(FILE_RENAME_INFORMATION)+2048 * sizeof(WCHAR), 'RENM');
		if (!RenameInfo)
		{
			Status = STATUS_NO_MEMORY;
			break;
		}
		RtlSecureZeroMemory(RenameInfo, sizeof(FILE_RENAME_INFORMATION)+2048 * sizeof(WCHAR));

		RenameInfo->ReplaceIfExists = FALSE;
		RenameInfo->RootDirectory = NULL;
		RenameInfo->FileNameLength = pDstFile->Length;
		RtlStringCchCopyNW(RenameInfo->FileName, 2048, pDstFile->Buffer, pDstFile->Length / sizeof(WCHAR));

		InitializeObjectAttributes(&oa, pSrcFile, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
		Status = ZwCreateFile(&FileHandle,
			SYNCHRONIZE | DELETE,
			&oa,
			&isb,
			NULL,
			FILE_ATTRIBUTE_NORMAL,
			FILE_SHARE_READ,
			FILE_OPEN,
			FILE_SYNCHRONOUS_IO_NONALERT | FILE_NO_INTERMEDIATE_BUFFERING,
			NULL, 0);
		if (!NT_SUCCESS(Status)){
			break;
		}

		Status = ZwSetInformationFile(
			FileHandle,
			&isb,
			RenameInfo,
			sizeof(FILE_RENAME_INFORMATION)+2048 * sizeof(WCHAR),
			FileRenameInformation);

	} while (FALSE);

	if (RenameInfo){
		ExFreePoolWithTag(RenameInfo, 'RENM');
	}

	if (FileHandle){
		ZwClose(FileHandle);
	}
	return NT_SUCCESS(Status) ? TRUE : FALSE;
}

BOOLEAN FsDeleteFile(PUNICODE_STRING pFilePath)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	OBJECT_ATTRIBUTES oa = { sizeof(oa) };

	InitializeObjectAttributes(&oa, pFilePath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	Status = ZwDeleteFile(&oa);
	return NT_SUCCESS(Status) ? TRUE : FALSE;
}

BOOLEAN FsCreateDirectory(IN PUNICODE_STRING DirectoryPath)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	OBJECT_ATTRIBUTES oa = { sizeof(oa) };
	HANDLE FileHandle = NULL;
	IO_STATUS_BLOCK isb = { 0 };

	PAGED_CODE();

	if (!DirectoryPath){
		return FALSE;
	}

	InitializeObjectAttributes(&oa, DirectoryPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	Status = ZwCreateFile(
		&FileHandle,
		GENERIC_READ,
		&oa,
		&isb,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ,
		FILE_CREATE,
		FILE_DIRECTORY_FILE,
		NULL, 0);

	if (FileHandle){
		ZwClose(FileHandle);
	}
	return NT_SUCCESS(Status) ? TRUE : FALSE;
}

BOOLEAN FsFindFirstFile(IN PUNICODE_STRING DirectoryPath,
	OUT PHANDLE FindHandle,
	OUT PFILE_BOTH_DIR_INFORMATION *lpFindFileData
	)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	OBJECT_ATTRIBUTES oa = { sizeof(oa) };
	HANDLE FileHandle = NULL;
	IO_STATUS_BLOCK isb = { 0 };
	ULONG SingleFindSize = sizeof(FILE_BOTH_DIR_INFORMATION)+260 * sizeof(WCHAR);
	ULONG MultipleFindSize = SingleFindSize * 0x100;
	PFILE_BOTH_DIR_INFORMATION FindFileData = NULL;
	ULONG ulFirstOffset = 0;

	PAGED_CODE();

	if (!DirectoryPath || !FindHandle || !lpFindFileData){
		return FALSE;
	}

	*FindHandle = NULL;
	*lpFindFileData = NULL;

	// Open directory
	InitializeObjectAttributes(&oa, DirectoryPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	status = ZwOpenFile(&FileHandle,
		GENERIC_READ,
		&oa,
		&isb,
		FILE_SHARE_READ,
		FILE_DIRECTORY_FILE);
	if (!NT_SUCCESS(status))
	{
		goto __end;
	}
	
	do
	{
		ulFirstOffset = 0;
		ExFreePoolWithTag(FindFileData, 'Find');
		FindFileData = (PFILE_BOTH_DIR_INFORMATION)ExAllocatePoolWithTag(PagedPool, MultipleFindSize, 'Find');
		RtlSecureZeroMemory(FindFileData, MultipleFindSize);

		// first query
		status = ZwQueryDirectoryFile(
			FileHandle,
			NULL,
			NULL,
			NULL,
			&isb,
			FindFileData,
			MultipleFindSize,
			FileBothDirectoryInformation,
			TRUE,   // ReturnSingleEntry
			NULL,
			TRUE);  // RestartScan
		if (!NT_SUCCESS(status)){
			break;
		}

		// second query
		ulFirstOffset = (ULONG)isb.Information;
		FindFileData->NextEntryOffset = (ULONG)ulFirstOffset;
		status = ZwQueryDirectoryFile(
			FileHandle,
			NULL,
			NULL,
			NULL,
			&isb,
			(PVOID)((ULONG_PTR)FindFileData + ulFirstOffset),
			MultipleFindSize - ulFirstOffset,
			FileBothDirectoryInformation,
			FALSE,
			NULL,
			FALSE);
		if (!NT_SUCCESS(status) && status != STATUS_BUFFER_OVERFLOW){
			break;
		}

		MultipleFindSize = MultipleFindSize * 2;

	} while ((status == STATUS_BUFFER_OVERFLOW) ||
		((ulFirstOffset + isb.Information + SingleFindSize) > (MultipleFindSize / 2)));

	if (!NT_SUCCESS(status))
	{
		ExFreePoolWithTag(FindFileData, 'Find');
		goto __end;
	}

	*FindHandle = FindFileData; // use of free resource
	*lpFindFileData = FindFileData; // use of query

__end:
	ZwClose(FileHandle);
	return NT_SUCCESS(status) ? TRUE : FALSE;
}

BOOLEAN FsFindNextFile(IN PFILE_BOTH_DIR_INFORMATION *lpFindFileData)
{
	if (!lpFindFileData || !(*lpFindFileData)){
		return FALSE;
	}

	if ((*lpFindFileData)->NextEntryOffset)
	{
		(*lpFindFileData) = (PFILE_BOTH_DIR_INFORMATION)((ULONG_PTR)(*lpFindFileData) + (*lpFindFileData)->NextEntryOffset);
		return TRUE;
	}
	return FALSE;
}

BOOLEAN FsFindClose(IN PHANDLE FindHandle)
{
	PAGED_CODE();

	if (!FindHandle || !(*FindHandle)){
		return FALSE;
	}

	ExFreePoolWithTag(*FindHandle, 'Find');
	*FindHandle = (HANDLE)0;
	return TRUE;
}

BOOLEAN FsSetFileCanDelete(PUNICODE_STRING pFilePath)
{
	if (KeGetCurrentIrql() > PASSIVE_LEVEL) {
		return FALSE;
	}

	HANDLE hFile = NULL;
	OBJECT_ATTRIBUTES	oa;
	IO_STATUS_BLOCK isb = { 0 };
	InitializeObjectAttributes(&oa, pFilePath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	NTSTATUS Status = ZwCreateFile(&hFile,
		GENERIC_READ | SYNCHRONIZE,
		&oa,
		&isb,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ,
		FILE_OPEN,
		FILE_NON_DIRECTORY_FILE | FILE_RANDOM_ACCESS | FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0
	);

	if (!NT_SUCCESS(Status) || hFile == NULL){
		return FALSE;
	}

	PFILE_OBJECT FileObject = NULL;
	Status = ObReferenceObjectByHandle(hFile, DELETE,
		*IoFileObjectType, KernelMode, &FileObject, NULL);
	if (!NT_SUCCESS(Status) || FileObject == NULL)
	{
		ZwClose(hFile);
		return FALSE;
	}	

	//MmFlushImageSection 函数通过这个结构来检查是否可以删除文件。
	PSECTION_OBJECT_POINTERS pSectionObjectPointer = FileObject->SectionObjectPointer;
	pSectionObjectPointer->ImageSectionObject = 0;
	pSectionObjectPointer->DataSectionObject = 0;
	ObDereferenceObject(FileObject);
	ZwClose(hFile);
	return TRUE;
}
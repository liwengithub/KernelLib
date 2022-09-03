#pragma once
#include <ntdef.h>
#include <ntifs.h>

//File
BOOLEAN		FsGetFileSize(IN PUNICODE_STRING pFilePath, OUT PULONG pFileSize);
BOOLEAN		FsIsFileExist(IN PUNICODE_STRING pFilePath);
BOOLEAN		FsRenameFile(IN PUNICODE_STRING pSrcFile, IN PUNICODE_STRING pDstFile);
BOOLEAN		FsDeleteFile(PUNICODE_STRING pFilePath);
BOOLEAN		FsReadFile(IN PUNICODE_STRING pFilePath, OUT PCHAR pFileBuf, IN ULONG FileBufSize, IN PLARGE_INTEGER pFileOffset);
BOOLEAN		FsWriteFile(IN PUNICODE_STRING pFilePath, IN PCHAR pFileBuf, IN ULONG FileBufSize);
BOOLEAN		FsAppendFile(IN PUNICODE_STRING pFilePath, IN PCHAR pFileBuf, IN ULONG FileBufSize);
BOOLEAN		FsCreateDirectory(IN PUNICODE_STRING DirectoryPath);
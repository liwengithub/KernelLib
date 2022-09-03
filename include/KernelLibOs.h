#pragma once
#include <ntdef.h>

//OS
VOID		OsRestart();
ULONG		OsGetMajorVersion();
ULONG		OsGetMinorVersion();
ULONG		OsGetBuildNumber();
BOOLEAN		OsParseSymlnk(IN PUNICODE_STRING Symlnk, OUT PUNICODE_STRING Target);
BOOLEAN		OsGetWinDir(OUT PUNICODE_STRING Dir);
BOOLEAN		OsGetSyswow64Dir(OUT PUNICODE_STRING Dir);
BOOLEAN		OsGetSystem32Dir(OUT PUNICODE_STRING Dir);
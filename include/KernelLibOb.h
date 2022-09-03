#pragma once
#include <ntdef.h>
#include <ntifs.h>

BOOLEAN ObParseSymlnk(IN PUNICODE_STRING Symlnk, OUT PUNICODE_STRING Target);

BOOLEAN GetDeviceObjectByName(_In_ PUNICODE_STRING ObjectName, _Out_ PDEVICE_OBJECT* pDeviceObject);

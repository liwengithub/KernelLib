#pragma once
#include <ntifs.h>
#include <WinDef.h>

//Process
BOOLEAN PsSuspendProcessById(HANDLE ProcessId);
BOOLEAN PsResumeProcessById(HANDLE ProcessId);
BOOLEAN PsTerminateProcessById(HANDLE Pid);
CHAR* PsGetProcessImageFileNameByPid(HANDLE ProcessId);
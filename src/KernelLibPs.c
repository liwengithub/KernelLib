#include "KernelLibPs.h"

NTSTATUS PsSuspendProcess(PEPROCESS Eprocess);
NTSTATUS PsResumeProcess(PEPROCESS Eprocess);
NTSYSAPI UCHAR* NTAPI PsGetProcessImageFileName(PEPROCESS Process);

BOOLEAN PsResumeProcessById(HANDLE ProcessId)
{
	PEPROCESS Eprocess;
	NTSTATUS status = PsLookupProcessByProcessId(ProcessId, &Eprocess);
	if (NT_SUCCESS(status))
	{
		PsResumeProcess(Eprocess);
		ObDereferenceObject(Eprocess);
		return TRUE;
	}
	return FALSE;
}

BOOLEAN PsSuspendProcessById(HANDLE ProcessId)
{
	PEPROCESS Eprocess;
	NTSTATUS status = PsLookupProcessByProcessId(ProcessId, &Eprocess);
	if (NT_SUCCESS(status))
	{
		PsSuspendProcess(Eprocess);
		ObDereferenceObject(Eprocess);
		return TRUE;
	}
	return FALSE;
}

BOOLEAN PsTerminateProcessById(HANDLE Pid)
{
#define PROCESS_TERMINATE                  (0x0001) 
	HANDLE hProc;
	OBJECT_ATTRIBUTES oa;
	CLIENT_ID stPID;
	stPID.UniqueThread = 0;
	stPID.UniqueProcess = (HANDLE)Pid;
	InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
	if (NT_SUCCESS(ZwOpenProcess(&hProc, PROCESS_TERMINATE, &oa, &stPID)))
	{
		if (NT_SUCCESS(ZwTerminateProcess(hProc, 0)))
		{
			return TRUE;
		}
	}
	return FALSE;
}

CHAR* PsGetProcessImageFileNameByPid(HANDLE ProcessId)
{
	PEPROCESS pEprocess = NULL;
	NTSTATUS Status = PsLookupProcessByProcessId(ProcessId, &pEprocess);
	CHAR *pName = NULL;
	if (NT_SUCCESS(Status) && pEprocess){
		pName = (CHAR*)PsGetProcessImageFileName(pEprocess);
	}

	if (pEprocess){
		ObDereferenceObject(pEprocess);
	}
	return pName;
}

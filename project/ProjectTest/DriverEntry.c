#include "../../include/KernelLib.h"

NTSTATUS CreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

void TestMm()
{
	PVOID HookCode = ExAllocatePool(NonPagedPool, 0x200);
	RtlFillMemory(HookCode, 0x200, 0x90);
	RtlMoveMemory(HookCode, NtOpenProcess, 0x3);
	MmSafeWriteMemory(NtOpenProcess, HookCode, 0x3);
}

void TestOs()
{
	WCHAR SystemDirBuf[MAX_PATH] = { 0 };
	UNICODE_STRING SystemDir;
	WCHAR Syswow64DirBuf[MAX_PATH] = { 0 };
	UNICODE_STRING Syswow64Dir;

	RtlInitEmptyUnicodeString(&SystemDir, SystemDirBuf, MAX_PATH * sizeof(WCHAR));
	OsGetSystem32Dir(&SystemDir);
	KdPrint(("System32:%wZ\n", &SystemDir));

	RtlInitEmptyUnicodeString(&Syswow64Dir, Syswow64DirBuf, MAX_PATH * sizeof(WCHAR));
	OsGetSyswow64Dir(&Syswow64Dir);
	KdPrint(("Syswow64:%wZ\n", &Syswow64Dir));
}

void TestStr()
{
	CHAR Buf[MAX_PATH + 1] = { 0 };
	if (StrFormatA("0x%x%S", Buf, MAX_PATH, 0x1011, L"0123TestStr²âÊÔ×Ö·û´®"))
	{
		KdPrint(("%s", Buf));
	}
}

void TestFs()
{
	UNICODE_STRING FilePath = RTL_CONSTANT_STRING(L"\\??\\C:\\1.log");
	BOOLEAN Ret = 0;
	Ret = FsAppendFile(&FilePath, "1234", 4);
	KdPrint(("FsAppendFile Ret:%d", Ret));
}

VOID UnloadDriver(PDRIVER_OBJECT DriverObject)
{

}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
{
	NTSTATUS status = 0;

	//TestMm();
	TestOs();
	TestStr();
	TestFs();

	DriverObject->DriverUnload = UnloadDriver;
	return 0;
}
#include "Main.h"

IOCTL_DISPATCH_ENTRY ioctlDispatchRoutineArray[] =
{
	{IOCTL_TERMINATE_PROCESS,	TerminateProcessIoctlHandler},
	{IOCTL_DELETE_LINK,			DeleteLinkIoctlHandler},
	{IOCTL_DELETE_FILE,			DeleteFileIoctlHandler},
	{IOCTL_BUGCHECK,			BugCheckIoctlHandler},
	{IOCTL_PROTECT_PROCESS,		ProtectProcessIoctlHandler},
	{IOCTL_CREATE_FILE,			CreateFileIoctlHandler},
	{IOCTL_CREATE_DIRECTORY,	CreateDirectoryIoctlHandler},
	{IOCTL_DELETE_KEY,			DeleteKeyIoctlHandler},
	{IOCTL_CREATE_KEY,			CreateKeyIoctlHandler},
	{IOCTL_UNLOAD_DRIVER,		UnloadDriverIoctlHandler},
	{IOCTL_CRITICAL_THREAD,		CriticalThreadIoctlHandler},
	{IOCTL_COPY_FILE,			CopyFileIoctlHandler},
	{IOCTL_SET_KEY_VALUE,		SetKeyValueIoctlHandler},
	{IOCTL_RET_FIRMWARE,		ReturnToFirmwareIoctlHandler},
	{IOCTL_MINIMAL_PROCESS,		MinimalProcessIoctlHandler},
	{IOCTL_TRIPLE_FAULT,		TripleFaultIoctlHandler},
	{IOCTL_INJECT_SHELLCODE,	InjectShellcodeIoctlHandler},
};


NTSTATUS DeviceControlHandler(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
	NTSTATUS status = STATUS_SUCCESS;
	PIO_STACK_LOCATION irpStack = NULL;
	ULONG ioctlCode = 0;

	IoSetCancelRoutine(pIrp, NULL);

	irpStack = IoGetCurrentIrpStackLocation(pIrp);

	ioctlCode = irpStack->Parameters.DeviceIoControl.IoControlCode;


	for (size_t i = 0; i < ARRAYSIZE(ioctlDispatchRoutineArray); i++)
	{
		if (ioctlDispatchRoutineArray[i].ioctlCode == ioctlCode)
		{
			status = (ioctlDispatchRoutineArray[i].handlerFunction)(pIrp);
		}
	}


	pIrp->IoStatus.Status = status;
	pIrp->IoStatus.Information = 0;
	pIrp->IoStatus.Pointer = NULL;

	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return status;
}


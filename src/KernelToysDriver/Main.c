
#include "Main.h"


PDEVICE_OBJECT g_pDeviceObject = NULL;
UNICODE_STRING g_devicePath = { 0 };
UNICODE_STRING g_deviceSymbolicLinkPath = { 0 };


NTSTATUS DriverObjectCreateClose(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;

	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}



void DriverUnload(PDRIVER_OBJECT pDriverObject)
{

	IoDeleteSymbolicLink(&g_deviceSymbolicLinkPath);

	IoDeleteDevice(pDriverObject->DeviceObject);

	pDriverObject->DriverUnload = NULL;

}


NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING registryPath)
{
	NTSTATUS status = STATUS_SUCCESS;

	OK("KernelToys driver started!");

	RtlInitUnicodeString(&g_devicePath, L"\\Device\\kerneltoys");
	RtlInitUnicodeString(&g_deviceSymbolicLinkPath, L"\\DosDevices\\kerneltoys");


#if KERNELTOYS_SECURE_DEVICE

	UNICODE_STRING deviceSecurityDescriptor = SDDL_DEVOBJ_SYS_ALL_ADM_ALL;

	status = WdmlibIoCreateDeviceSecure(pDriverObject, 0, &g_devicePath, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &deviceSecurityDescriptor, NULL, &g_pDeviceObject);

#else

	status = IoCreateDevice(pDriverObj, 0, &device, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pDeviceObject);

#endif


	if (!NT_SUCCESS(status))
	{
#if KERNELTOYS_SECURE_DEVICE
		DBGERRNTSTATUS("WdmLibIoCreateDeviceSecure", status);
#else
		DBGERRNTSTATUS("IoCreateDevice", status);
#endif
		
		return status;
	}

	
	status = IoCreateSymbolicLink(&g_deviceSymbolicLinkPath, &g_devicePath);


	if (!NT_SUCCESS(status))
	{
		DBGERRNTSTATUS("IoCreateSymbolicLink", status);

		IoDeleteDevice(g_pDeviceObject);

		return status;
	}


	pDriverObject->MajorFunction[IRP_MJ_CREATE] = DriverObjectCreateClose;
	pDriverObject->MajorFunction[IRP_MJ_CLOSE] = DriverObjectCreateClose;
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControlHandler;

	g_pDeviceObject->Flags |= DO_BUFFERED_IO;

	pDriverObject->DriverUnload = DriverUnload;

	return status;
}
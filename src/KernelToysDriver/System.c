#include "Main.h"


NTSTATUS DeleteLinkIoctlHandler(PIRP pIrp)
{
	UNICODE_STRING symbolicLinkName = { 0 };
	LPWSTR symbolicLinkToDelete = (LPWSTR)pIrp->AssociatedIrp.SystemBuffer;

	RtlInitUnicodeString(&symbolicLinkName, symbolicLinkToDelete);

	return IoDeleteSymbolicLink(&symbolicLinkName);
}

NTSTATUS BugCheckIoctlHandler(PIRP pIrp)
{
	KeBugCheck(*((PULONG)pIrp->AssociatedIrp.SystemBuffer));
}

NTSTATUS UnloadDriverIoctlHandler(PIRP pIrp)
{
	UNICODE_STRING unicodeStrDriverPath;

	WCHAR* driverPath = (WCHAR*)pIrp->AssociatedIrp.SystemBuffer;
	
	RtlInitUnicodeString(&unicodeStrDriverPath, driverPath);
	
	return ZwUnloadDriver(&unicodeStrDriverPath);
}

NTSTATUS PortIoIoctlHandler(PIRP pIrp)
{	
	NTSTATUS ntStatus = STATUS_SUCCESS;

	PPORT_IO_PARAMETER pIoctlInfo = (PPORT_IO_PARAMETER)pIrp->AssociatedIrp.SystemBuffer;
	
	if (pIoctlInfo->In)
	{
		DBGINFO("Reading %lu bytes from I/O port 0x%04X", pIoctlInfo->Size, pIoctlInfo->PortAddress);

		switch (pIoctlInfo->Size)
		{
			case sizeof(UINT8):
				*pIoctlInfo->PortData.pInputByte = __inbyte(pIoctlInfo->PortAddress);
			break;

			case sizeof(UINT16):
				*pIoctlInfo->PortData.pInputWord = __inword(pIoctlInfo->PortAddress);
			break;

			case sizeof(UINT32):
				*pIoctlInfo->PortData.pInputDword = __indword(pIoctlInfo->PortAddress);
			break;

			default:
				return STATUS_INVALID_PARAMETER;
		}
	}
	else
	{
		DBGINFO("Writing %lu bytes to I/O port 0x%04X", pIoctlInfo->Size, pIoctlInfo->PortAddress);

		switch (pIoctlInfo->Size)
		{
			case sizeof(UINT8):
				__outbyte(pIoctlInfo->PortAddress, pIoctlInfo->PortData.OutputByte);
			break;

			case sizeof(UINT16):
				__outword(pIoctlInfo->PortAddress, pIoctlInfo->PortData.OutputWord);
			break;

			case sizeof(UINT32):
				__outdword(pIoctlInfo->PortAddress, pIoctlInfo->PortData.OutputDword);
			break;

			default:
				return STATUS_INVALID_PARAMETER;
		}
	}

	
	return ntStatus;
}


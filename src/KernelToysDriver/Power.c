#include "Main.h"


NTSTATUS ReturnToFirmwareIoctlHandler(PIRP pIrp)
{
	FIRMWARE_REENTRY firmwareReentryOption = *((PFIRMWARE_REENTRY)pIrp->AssociatedIrp.SystemBuffer);

	HalReturnToFirmware(firmwareReentryOption);

	return STATUS_SUCCESS; // Unreachable
}

NTSTATUS TripleFaultIoctlHandler(PIRP pIrp)
{
	IDT zeroIdt = { 0 };

	LoadIDT(&zeroIdt);

	// "I didn't save my document, will it be lost?" yessir!
	IntThree();

	return STATUS_SUCCESS; // Unreachable
}
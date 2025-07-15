#pragma once

typedef enum _FIRMWARE_REENTRY
{
	HalHaltRoutine,
	HalPowerDownRoutine,
	HalRestartRoutine,
	HalRebootRoutine,
	HalInteractiveModeRoutine,
	HalMaximumRoutine
} FIRMWARE_REENTRY, * PFIRMWARE_REENTRY;

typedef struct _IDT
{
	unsigned short Limit;
	UINT64 Base;
} IDT, * PIDT;

void HalReturnToFirmware(FIRMWARE_REENTRY PowerOption);

extern void LoadIDT(PIDT pIdt);
extern void IntThree();


NTSTATUS ReturnToFirmwareIoctlHandler(PIRP pIrp);

NTSTATUS TripleFaultIoctlHandler(PIRP pIrp);
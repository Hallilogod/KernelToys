#pragma once

typedef enum _FIRMWARE_REENTRY {
    HalHaltRoutine,
    HalPowerDownRoutine, 
    HalRestartRoutine,
    HalRebootRoutine,
    HalInteractiveModeRoutine,
    HalMaximumRoutine
} FIRMWARE_REENTRY, *PFIRMWARE_REENTRY;

typedef enum _SHUTDOWN_ACTION
{
    ShutdownNoReboot,
    ShutdownReboot,
    ShutdownPowerOff,
    ShutdownRebootForRecovery // since WIN11
} SHUTDOWN_ACTION;

NTSYSCALLAPI NTSTATUS NTAPI NtShutdownSystem(_In_ SHUTDOWN_ACTION Action);

BOOL ReturnToFirmwareToyHandler(LPWSTR arguments[], UINT argumentCount);

BOOL TripleFaultToyHandler(LPWSTR arguments[], UINT argumentCount);


BOOL NtShutdownToyHandler(LPWSTR arguments[], UINT argumentCount);

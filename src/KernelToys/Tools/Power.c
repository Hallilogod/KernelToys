#include "../Main.h"

BOOL NtShutdownToyHandler(LPWSTR arguments[], UINT argumentCount)
{
    SHUTDOWN_ACTION shutdownAction = 0;
    HANDLE ownTokenHandle = NULL;

    if (wcsicmp(arguments[1], L"shutdown") == 0)
    {
        shutdownAction = ShutdownNoReboot;
    }
    else if (wcsicmp(arguments[1], L"reboot") == 0)
    {
        shutdownAction = ShutdownReboot;        
    }
    /*
    It's called BIOS since ShutdownPowerOff tries to call the BIOS shutdown function, in case the hardware
    doesn't support this, ShutdownReboot is called. - https://ntdoc.m417z.com/shutdown_action
    */
    else if (wcsicmp(arguments[1], L"bios") == 0)
    {       
        shutdownAction = ShutdownPowerOff;
    }
    else
    {
        ERR("Invalid power operation '%ls'", arguments[1]);
        return FALSE;
    }

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, ownTokenHandle))
    {
        ERR("Failed to open own process token, lasterror: %ld", GetLastError());
        return FALSE;
    }

    if (!AdjustPrivilegeForToken(ownTokenHandle, L"SeShutdownPrivilege"))
    {
        CloseHandle(ownTokenHandle);

        return FALSE;
    }

    CloseHandle(ownTokenHandle);

    INFO("Calling NtShutdownSystem...");
    
    NTSTATUS shutdownNtStatus = NtShutdownSystem(shutdownAction);

    if(shutdownNtStatus != 0)
    {
        ERR("Failed to perform power operation, ntstatus: %08lX", shutdownNtStatus);

        return FALSE;
    }

    return TRUE; // Should be unreachable
}

BOOL ReturnToFirmwareToyHandler(LPWSTR arguments[], UINT argumentCount)
{
    int powerOperation = 0;

    if (wcsicmp(arguments[1], L"powerdown") == 0)
    {
        powerOperation = HalPowerDownRoutine;
    }
    else if (wcsicmp(arguments[1], L"reboot") == 0)
    {
        // Altenative name, HalWindowsUpdateRoutine
        powerOperation = HalRebootRoutine;
    }
    else if (wcsicmp(arguments[1], L"halt") == 0)
    {
        powerOperation = HalHaltRoutine;
    }
    else
    {
        ERR("Invalid power option '%ls'", arguments[1]);
        return FALSE;
    }

    INFO("Sending device control to perform power operation...");

    return DeviceControlDriver(IOCTL_RET_FIRMWARE, &powerOperation, sizeof(powerOperation));
}

BOOL TripleFaultToyHandler(LPWSTR arguments[], UINT argumentCount)
{
    // System cutely fucking dies ^-^
    return DeviceControlDriver(IOCTL_TRIPLE_FAULT, NULL, 0);
}

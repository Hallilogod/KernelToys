#pragma once
#include "Main.h"


#define DRIVER_SERVICE_NAME "kerneltoys"

#define DRIVER_FILE_NAME "KernelToysDriver.sys"

typedef struct _BIT_FLAG32
{
    UINT32 bit;
    LPSTR flagName;
} BIT_FLAG32, *PBIT_FLAG32;






/*
Creates the service for the kerneltoys driver.

@param none

@return A handle to the driver service or NULL on failure
*/
SC_HANDLE CreateDriverService();

BOOL StartDriverService(SC_HANDLE driverServiceHandle, PBOOL pDriverAlreadyRunning);

BOOL PrintDriverServiceInformation(SC_HANDLE driverServiceHandle, _In_opt_ SERVICE_STATUS* pDriverServiceStatus);

SC_HANDLE StopDriverService(_Out_ SERVICE_STATUS* pDriverServiceStatus);

BOOL DeleteDriverService(SC_HANDLE driverServiceHandle);

BOOL DeviceControlDriver(DWORD ioctlCode, PVOID ioctlInfo, SIZE_T ioctlInfoSizeBytes);
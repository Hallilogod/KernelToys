#include "Main.h"

BIT_FLAG32 serviceTypeBitFlags[] =
{		
    { 0x00000001, "SERVICE_KERNEL_DRIVER" },

    { 0x00000002, "SERVICE_FILE_SYSTEM_DRIVER" },

    { 0x00000010, "SERVICE_WIN32_OWN_PROCESS" },

    { 0x00000020, "SERVICE_WIN32_SHARE_PROCESS" },

    { 0x00000050, "SERVICE_USER_OWN_PROCESS" },

    { 0x00000060, "SERVICE_USER_SHARE_PROCESS" },

    { 0x00000100, "SERVICE_INTERACTIVE_PROCESS" }
};
// Array using the service type values as indexes to the strings 
LPSTR serviceStatusValuesLookupArray[] =
{	
    /* 0x00000000 */ "",

    /* 0x00000001 */ "SERVICE_STOPPED",

    /* 0x00000002 */ "SERVICE_START_PENDING",

    /* 0x00000003 */ "SERVICE_STOP_PENDING",

    /* 0x00000004 */ "SERVICE_RUNNING",

    /* 0x00000005 */ "SERVICE_CONTINUE_PENDING",

    /* 0x00000006 */ "SERVICE_PAUSE_PENDING",

    /* 0x00000007 */ "SERVICE_PAUSED"
};

BIT_FLAG32 acceptedControlsBitFlags[] =
{
    { 0x00000001, "SERVICE_ACCEPT_STOP" },

    { 0x00000002, "SERVICE_ACCEPT_PAUSE_CONTINUE" },

    { 0x00000004, "SERVICE_ACCEPT_SHUTDOWN" },

    { 0x00000008, "SERVICE_ACCEPT_PARAMCHANGE" },

    { 0x00000010, "SERVICE_ACCEPT_NETBINDCHANGE" },

    { 0x00000020, "SERVICE_ACCEPT_HARDWAREPROFILECHANGE" },

    { 0x00000040, "SERVICE_ACCEPT_POWEREVENT" },

    { 0x00000080, "SERVICE_ACCEPT_SESSIONCHANGE" },

    { 0x00000100, "SERVICE_ACCEPT_PRESHUTDOWN" },

    { 0x00000200, "SERVICE_ACCEPT_TIMECHANGE" },

    { 0x00000400, "SERVICE_ACCEPT_TRIGGEREVENT" },

    { 0x00000800, "SERVICE_ACCEPT_USERMODEREBOOT" },

};


VOID PrintBitFlags(PBIT_FLAG32 bitFlagsNames, UINT bitFlagsNamesArraySize, ULONG bitsToPrint)
{
    BOOL firstBit = TRUE;

    for(UINT i = 0; i < bitFlagsNamesArraySize; i++)
    {
        if(bitFlagsNames[i].bit & bitsToPrint)
        {
            if(!firstBit)
            {
                PRINT(" | ");
            }

            PRINT(bitFlagsNames[i].flagName);

            firstBit = FALSE;
        }
    }
}

SC_HANDLE CreateDriverService()
{
    char driverImagePath[MAX_PATH + 1];
    DWORD result = GetFullPathNameA(DRIVER_FILE_NAME, sizeof(driverImagePath), driverImagePath, NULL);

    if (result == 0)
    {
        ERR("Could not get the full path of KernelToysDriver.sys, please make sure to not rename, move or delete it and that the full file path doesn't exceed MAX_PATH (260) lasterror: %ld", GetLastError());
        return NULL;
    }

    // Open a handle to the SCM, necessary to create services
    SC_HANDLE scmHandle = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE | SERVICE_QUERY_STATUS);

    if (scmHandle == NULL)
    {
        ERR("Failed to open a handle to the SCM");
        return NULL;
    }

    // Create the service
    SC_HANDLE driverServiceHandle = CreateServiceA( scmHandle,
                                                    DRIVER_SERVICE_NAME,
                                                    NULL,
                                                    SERVICE_QUERY_STATUS | DELETE | SERVICE_START,
                                                    SERVICE_KERNEL_DRIVER,
                                                    SERVICE_DEMAND_START,
                                                    SERVICE_ERROR_NORMAL,
                                                    driverImagePath,
                                                    NULL, NULL, NULL, NULL, NULL);
                  
                                                    
    if (driverServiceHandle != NULL)
    {
        CloseServiceHandle(scmHandle);

        return driverServiceHandle;
    }

    if (GetLastError() == ERROR_SERVICE_EXISTS)
    {
        WARN("The service already exists, opening it");

        driverServiceHandle = OpenServiceA(scmHandle, "kerneltoys", SERVICE_QUERY_STATUS | DELETE | SERVICE_START);

        CloseServiceHandle(scmHandle);

        if(driverServiceHandle != NULL)
        {   
            return driverServiceHandle;
        }

        ERR("Failed to open driver service handle");
    }
    else
    {
        ERR("CreateService failed with lasterror %ld", GetLastError());
    }

    return NULL;
}

BOOL StartDriverService(SC_HANDLE driverServiceHandle, PBOOL pAlreadyRunning)
{
    if (StartServiceA(driverServiceHandle, 0, NULL) != FALSE)
    {
        return TRUE;
    }

    if (GetLastError() == ERROR_SERVICE_ALREADY_RUNNING)
    {
        *pAlreadyRunning = TRUE;
        return TRUE;
    }
    else
    {
        ERR("Failed to start kerneltoys driver, lasterror: %ld", GetLastError());

        return FALSE;
    }
}


BOOL PrintDriverServiceInformation(SC_HANDLE driverServiceHandle, _In_opt_ SERVICE_STATUS* pDriverServiceStatus)
{
    SERVICE_STATUS currentServiceStatus = { 0 };
    SERVICE_STATUS* pCurrentDriverServiceStatus = pDriverServiceStatus;

    if(pDriverServiceStatus == NULL)
    {
        if(QueryServiceStatus(driverServiceHandle, &currentServiceStatus) == FALSE)
        {
            ERR("Failed to query driver service status, lasterror: %lu", GetLastError());
            return FALSE;
        } 
        
        pCurrentDriverServiceStatus = &currentServiceStatus;
    }


    INFO(   "Driver information:");
    INFO(   "   SERVICE NAME:       %s", DRIVER_SERVICE_NAME);

    INFO_NN("   TYPE:               ");
    PrintBitFlags(serviceTypeBitFlags, ARRAYSIZE(serviceTypeBitFlags), pCurrentDriverServiceStatus->dwServiceType);
    PRINT("\n");

    INFO(   "   CURRENT STATE:      %s", serviceStatusValuesLookupArray[pCurrentDriverServiceStatus->dwCurrentState]);

    INFO_NN("   ACCEPTED CONTROLS:  "); 
    PrintBitFlags(acceptedControlsBitFlags, ARRAYSIZE(acceptedControlsBitFlags), pCurrentDriverServiceStatus->dwServiceType);
    PRINT(  "\n");

    INFO(   "   CHECKPOINT:         0x%lX (%lu)", pCurrentDriverServiceStatus->dwCheckPoint, pCurrentDriverServiceStatus->dwCheckPoint);
    INFO(   "   WAIT HINT:          0x%lX (%lu)", pCurrentDriverServiceStatus->dwWaitHint, pCurrentDriverServiceStatus->dwWaitHint);
    INFO(   "   WIN32 EXIT CODE:    0x%lX (%lu)", pCurrentDriverServiceStatus->dwWin32ExitCode, pCurrentDriverServiceStatus->dwWin32ExitCode);
    INFO(   "   SERVICE EXIT CODE:  0x%lX (%lu)", pCurrentDriverServiceStatus->dwServiceSpecificExitCode, pCurrentDriverServiceStatus->dwServiceSpecificExitCode);

    return TRUE;
}

SC_HANDLE StopDriverService(_Out_ SERVICE_STATUS* pDriverServiceStatus)
{
    SC_HANDLE scmHandle = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE | SERVICE_QUERY_STATUS);

    if (scmHandle == NULL)
    {
        ERR("Failed to open a handle to the SCM");
        return NULL;
    }

    SC_HANDLE driverServiceHandle = OpenServiceA(scmHandle, DRIVER_SERVICE_NAME, SERVICE_QUERY_STATUS | SERVICE_STOP | DELETE);

    CloseHandle(scmHandle);
    
    if(ControlService(driverServiceHandle, SERVICE_CONTROL_STOP, pDriverServiceStatus) != FALSE)
    {
        return driverServiceHandle;
    }
    
    ERR("Failed to send stop service control to kerneltoys driver service, lasterror: %lu", GetLastError());

    return driverServiceHandle;
}

BOOL DeleteDriverService(SC_HANDLE driverServiceHandle)
{
    if(DeleteService(driverServiceHandle) == FALSE)
    {
        ERR("Failed to delete driver service, lasterror: %lu", GetLastError());

        return FALSE;
    }

    return TRUE;
}


BOOL DeviceControlDriver(DWORD ioctlCode, PVOID ioctlInputBuffer, SIZE_T ioctlInputBufferSizeBytes, _Out_opt_ PVOID ioctlOutputBuffer, _Out_ LPDWORD ioctlOutputBufferSizeBytes)
{
    BOOL returnValue = TRUE;

	HANDLE driverHandle = CreateFileW(L"\\\\.\\kerneltoys", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

	if (driverHandle == INVALID_HANDLE_VALUE)
	{
		ERR("Failed to get a handle to the driver (\\\\.\\kerneltoys), lasterror: %ld", GetLastError());
        
		return FALSE;
	}
	
	DWORD bytesReturned = 0;

	if (!DeviceIoControl(driverHandle, ioctlCode, ioctlInputBuffer, ioctlInputBufferSizeBytes, ioctlOutputBuffer, bytesReturned, &bytesReturned, NULL))
	{
		ERR("The operation failed! Lasterror: %ld", GetLastError());

        returnValue = FALSE;
	}

	CloseHandle(driverHandle);

    if(ioctlOutputBuffer != NULL)
    {
        *ioctlOutputBufferSizeBytes = bytesReturned;
    }
    
    return returnValue;
}

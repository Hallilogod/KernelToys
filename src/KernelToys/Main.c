
#include "Main.h"

// This is just to help printf be able to pretty print format the list of tools, adjust as needed
#define MAX_TOOL_NAME_CHARS 16
#define MAX_ARGUMENTS_CHARS 60 
TOOL tools[] = 
{
    // Kernelmode tools
    MAKE_KERNEL_TOOL(L"terminate", L"<PID>", 1, L"Terminates the target process", TerminateProcessToyHandler),
    MAKE_KERNEL_TOOL(L"deletesymblink", L"<\"Native SymbolicLink path\">", 1, L"Deletes the target symbolic link", DeleteSymbLinkToyHandler),
    MAKE_KERNEL_TOOL(L"deletefile", L"<\"Full path to file\">", 1, L"Force deletes nearly any file", DeleteFileToyHandler),
    MAKE_KERNEL_TOOL(L"bugcheck", L"<Hex:stopcode>", 1, L"Triggers a bugcheck with the specified stopcode", BugCheckToyHandler),
    MAKE_KERNEL_TOOL(L"ppl", L"<PID> [none|light|full|max] (<Hex:ProtectionMemberOffset>)", 2, L"Manages the protection of a process (protected process light)", ProtectProcessToyHandler),
    MAKE_KERNEL_TOOL(L"createfile", L"<\"Full path to file\">", 1, L"Creates a new file. Fails if the file already exists", CreateFileToyHandler),
    MAKE_KERNEL_TOOL(L"createdir", L"<\"Full path to directory\">", 1, L"Creates a new directory. Fails if the directory already exists", CreateDirectoryToyHandler),
    MAKE_KERNEL_TOOL(L"deletekey", L"<\"NT path to registry key\">", 1, L"Force deletes nearly any registry key", DeleteKeyToyHandler),
    MAKE_KERNEL_TOOL(L"createkey", L"<\"NT path to registry key\">", 1, L"Creates the specified registry key", CreateKeyToyHandler),
    MAKE_KERNEL_TOOL(L"unloaddriver", L"<\"Service name\">", 1, L"Unloads the specified driver", UnloadDriverToyHandler),
    MAKE_KERNEL_TOOL(L"criticalthread", L"<TID> [true|false]", 2, L"Sets a thread as critical or non-critical", CriticalThreadToyHandler),
    MAKE_KERNEL_TOOL(L"copyfile", L"<\"source file\"> <\"dest file\">", 2, L"Copies a file. Overwrites if the destination file already exists", CopyFileToyHandler),
    MAKE_KERNEL_TOOL(L"firmwarepower", L"[powerdown|reboot|halt]", 1, L"Performs low level UEFI firmware/ACPI power operations", ReturnToFirmwareToyHandler),
    MAKE_KERNEL_TOOL(L"minimalprocess", L"<\"process name\">", 1, L"Creates a minimal process", MinimalProcessToyHandler),
    MAKE_KERNEL_TOOL(L"triplefault", L"", 0, L"Triple faults the CPU", TripleFaultToyHandler),
    MAKE_KERNEL_TOOL(L"injectshellcode", L"<PID> <\"Shellcode file path\">", 2, L"Injects and runs shellcode in the target process", InjectShellcodeToyHandler),
    MAKE_KERNEL_TOOL(L"portio", L"[in|out] [byte|word|dword] <Hex:I/O Port Address> (<Hex:Value to write>)", 3, L"Reads/Writes to the specified I/O port in the I/O address space", PortIoToyHandler),

    // Usermode Tools
    MAKE_USER_TOOL(L"ntshutdown", L"[shutdown|reboot|biosshutdown]", 1, L"Performs power operations using NtShutdownSystem", FALSE, NtShutdownToyHandler),
    MAKE_USER_TOOL(L"criticalprocess", L"<PID> [true|false]", 2, L"Sets a process as critical or non-critical", TRUE, CriticalProcessToyHandler),
    MAKE_USER_TOOL(L"tokengrab", L"<PID> <\"ImagePath\"> (<Privileges>)", 2, L"Runs the specified executable with the token of the target process's PID", TRUE, TokengrabToyHander)
};

BOOL AdjustPrivilegeForToken(HANDLE tokenHandle, LPWSTR privilegeName)
{
	TOKEN_PRIVILEGES tokenPrivileges = { 0 };
	tokenPrivileges.PrivilegeCount = 1;
	tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!LookupPrivilegeValueW(NULL, privilegeName, &tokenPrivileges.Privileges[0].Luid))
	{
        ERR("Failed to lookup privilege value for privilege '%ls', lasterror: %ld", privilegeName, GetLastError());
		return FALSE;
	}

	if(!AdjustTokenPrivileges(tokenHandle, FALSE, &tokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
    {
        ERR("Failed to adjust token privileges, lasterror: %ld", GetLastError());

        return FALSE;
    }
    
    return TRUE;
}

BOOL IsOwnProcessTokenElevated()
{
	HANDLE ownTokenHandle = NULL;
    TOKEN_ELEVATION tokenElevation = { 0 };
    DWORD size = 0;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &ownTokenHandle))
	{
        ERR("Failed to open own process token for elevation check ,lasterror: %ld", GetLastError());

        return FALSE;
    }

    if (!GetTokenInformation(ownTokenHandle, TokenElevation, &tokenElevation, sizeof(tokenElevation), &size))
    {
        ERR("Failed to get token information for own process token, lasterror: %ld", GetLastError());

        CloseHandle(ownTokenHandle);

        return FALSE;
    }

    CloseHandle(ownTokenHandle);

    return tokenElevation.TokenIsElevated;
}

void PrintUsage(LPWSTR programName, TOOL toolArray[], UINT toolArrayLength)
{

    printf(MAGENTA("Usage:") " %ls <tool> (<arguments>)\n", programName);
	printf(BLUE("Driver Options:\n"));
	printf("  -startdriver ([nodsepatch])          Starts the kerneltoys driver, this is REQUIRED before using any of the kernel tools.\n");
	printf("  -stopdriver                          Stops the kerneltoys driver and deletes the service.\n");
	printf(BLUE("\nKernel Tools:\n"));

    for(UINT i = 0; i < toolArrayLength; i++)
    {
        if(!toolArray[i].IsKernelTool)
        {
            continue;
        }

        printf("  %-*ls %-*ls %ls.\n", 
            MAX_TOOL_NAME_CHARS, toolArray[i].CommandName,
            MAX_ARGUMENTS_CHARS, toolArray[i].CommandArguments,
            toolArray[i].CommandDescription);
    }

    printf(BLUE("\nUsermode Tools:\n"));

    for(UINT i = 0; i < toolArrayLength; i++)
    {
        if(toolArray[i].IsKernelTool)
        {
            continue;
        }

        printf("  %-*ls %-*ls %ls.\n", 
            MAX_TOOL_NAME_CHARS, toolArray[i].CommandName,
            MAX_ARGUMENTS_CHARS, toolArray[i].CommandArguments,
            toolArray[i].CommandDescription);
        
    }
}


int wmain(int argc, LPWSTR wargv[])
{
    int returnValue = EXIT_SUCCESS;
    
#if SUPPORT_COLORS
    HANDLE consoleHandle = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD oldConsoleMode = 0;
    GetConsoleMode(consoleHandle, &oldConsoleMode); 
    SetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), oldConsoleMode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
#endif

    if (argc < 2)
	{

		PRINT(GREEN("---------  ")  MAGENTA("Welcome to KernelToys \\(^-^)")  GREEN("  ---------") "\n\n");

		PrintUsage(wargv[0], tools, ARRAYSIZE(tools));
        
        return EXIT_SUCCESS;
	}

    if(!_wcsicmp(wargv[1], L"-startdriver") || !_wcsicmp(wargv[1], L"-sa"))
    {

        INFO("Creating KernelToys driver service...");

        SC_HANDLE driverServiceHandle = CreateDriverService();

        if(driverServiceHandle == NULL)
        {
            return EXIT_FAILURE;
        }

        OK("Service created");

        INFO("Patching system DSE flags...");

        BOOL dseFlagsPatched = FALSE;
        DWORD oldDseFlags = 0;
        
        if(!(argc > 2 && !_wcsicmp(wargv[2], L"nodsepatch")))
        {
            if(!PatchDse(0, &oldDseFlags))
            {
                return EXIT_FAILURE;
            }

            dseFlagsPatched = TRUE;

            PRINT("\n");

            OK("Successfully patched DSE flags to 0");
        }

        INFO("Starting driver...");
        
        BOOL driverAlreadyRunning = FALSE;

        if(StartDriverService(driverServiceHandle, &driverAlreadyRunning))
        {
            if(driverAlreadyRunning)
            {
                WARN("The driver is already running");
            }
            else
            {
                OK("KernelToys driver started successfully");
            }
        }

        PRINT("\n");

        PrintDriverServiceInformation(driverServiceHandle, NULL);

        PRINT("\n");

        if(dseFlagsPatched)
        {
            INFO("Trying to write back old DSE flags...");

            if(!PatchDse(oldDseFlags, NULL))
            {
                ERR("Failed to write back old DSE flags");

                returnValue = EXIT_FAILURE;
            }
        }
    }
    else if(!_wcsicmp(wargv[1], L"-stopdriver") || !_wcsicmp(wargv[1], L"-so"))
    {
        INFO("Stopping KernelToys driver...");

        SERVICE_STATUS serviceStopStatus = { 0 };

        SC_HANDLE driverServiceHandle = StopDriverService(&serviceStopStatus);

        PRINT("\n");

        PrintDriverServiceInformation(driverServiceHandle, NULL);

        PRINT("\n");

        INFO("Deleting driver service...");
        
        if(DeleteDriverService(driverServiceHandle))
        {
            OK("Driver service deleted");
        }
        else
        {
            returnValue = EXIT_FAILURE;
        }

    }
    else
    {
        BOOL toolHandlerReturnValue = FALSE;

        UINT toolIterator = 0;
        for(; toolIterator < ARRAYSIZE(tools); toolIterator++)
        {
            TOOL currentTool = tools[toolIterator];

            if(_wcsicmp(wargv[1], currentTool.CommandName))
            {
                continue;
            }
            
            if((UINT)(argc - 2) < currentTool.MinCommandArguments)
            {
                ERR("Missing arguments");
                INFO("Tool usage: '%ls %ls'", currentTool.CommandName, currentTool.CommandArguments);

                return EXIT_FAILURE;
            }

            
            if(currentTool.RequiresElevation && !IsOwnProcessTokenElevated())
            {
                ERR("This tool requires elevation");

                return FALSE;
            }


            INFO("Executing tool '%ls'...", tools[toolIterator].CommandName);

            toolHandlerReturnValue = tools[toolIterator].ToolHandlerRoutine(&wargv[1], argc - 1);

            break;
        }

        if(toolIterator == ARRAYSIZE(tools))
        {
            ERR("Unknown tool '%ls'", wargv[1]);

            returnValue = EXIT_FAILURE;
        }
        else if(toolHandlerReturnValue)
        {
            OK("The operation succeeded!");
        }
        else
        {
            returnValue = EXIT_FAILURE;
        }

    }

    PRINT("\n");
    INFO_NN("Exiting with exit code %d, bye bye (^-^*)/", returnValue);

    return returnValue;
}

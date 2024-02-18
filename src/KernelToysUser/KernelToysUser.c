// remove this define if you removed it in the driver
// #define KERNELTOYS_SECURE_DEVICE

#include "KernelToysUser.h"

void printUsage(char *argv[])
{

	printf("Usage: %s <option> (<arguments>)\n", argv[0]);
	printf("Driver Options:\n");
	printf("  -startdriver                         Starts the kerneltoys driver, this is REQUIRED before using any of the kernel options.\n");
	printf("  -stopdriver                          Stops the driver. This should be done if you are finished using KernelToys\n");
	printf("                                       but can be left on in case you need to use it again.\n");
	printf("Kernel Options:\n");
	printf("  deletesymblink <\"Native SymbolicLink path\">   Deletes the given symbolic link\n");
	printf("  terminate <PID>                               Terminates a process with the given PID\n");
	printf("  ppl <PID> <none|light|full|max> (<Hex:ProtectionMemberOffset>)   sets a protection level for the given process.\n");
	printf("  criticalthread <TID> <true|false>             Makes a thread critical or not critical\n");
	printf("  createfile <\"Full path to file\">              Creates a new file, if the file already exists it fails\n");
	printf("  copyfile <\"source file\"> <\"dest file\">        Copies a file, if the destination file already exists it will be overwritten.\n");
	printf("  deletefile <\"Full path to file\">              Force deletes nearly any file\n");
	printf("  createdir <\"Full path to directory\">          Creates a new directory, if the directory already exists it fails\n");
	printf("  createkey <\"Native NT path to registry key\">  Creates a registry key\n");
	printf("  deletekey <\"Native NT path to registry key\">  Force deletes nearly any registry key. Take care!\n");
	printf("  bugcheck <Hex:stopcode>                       Triggers a bugcheck with the given stopcode\n");
	printf("  unloaddriver <\"Service name\">                 Unloads (stops) the given driver, this sadly works for almost no driver.\n");

	printf("\nUser Options:\n");
	printf("  ntshutdown <shutdown|reboot|bios>             Shuts down / reboots the system using NtShutdownSystem. (unsaved data will be lost)\n");
	printf("  criticalprocess <PID> <true|false>            Makes a process critical or not critical\n");
	printf("  tokengrab <PID> <\"ImagePath\"> (<Privileges>)  Runs the given image file with the token of the Process whose PID you passed\n");
	printf("                                                optional: specify privileges seperated by commas or use -allprivileges.\n");
}

int main(int argc, char *argv[])
{
	// No argument was given...
	if (argc < 2)
	{
		printf("--Welcome to KernelToys---\n\n");

		printUsage(argv);
		return 0;
	}

	char *argv1ow = _strdup(argv[1]);

	_strlwr_s(argv1ow, strlen(argv[1]) + 1);

	if ((strcmp(argv1ow, "-startdriver") == 0) || (strcmp(argv1ow, "-sa") == 0))
	{
		// Creating the service and starting the driver requires elevation
		if (!amIElevated())
		{
			printError(EPVelevationRequired, 1, 0);
			return 1;
		}
		int writedse = 1;
		int successProvider = 1;
		int old;
		if (argc > 2)
		{
			char *argv2ow = _strdup(argv[2]);
			_strlwr_s(argv2ow, strlen(argv[2]) + 1);
			// if the argument "nodse" was provided we do not use kdu to temporarily write 0 to the dse flags
			if ((strcmp(argv2ow, "nodse") == 0))
			{
				writedse = 0;
			}
		}
		if (writedse)
		{

			if (!(FileExists("kdu.exe") && FileExists("drv64.dll") && FileExists("KernelToysDriver.sys")))
			{
				printf("kdu.exe, drv64.dll or KernelToysDriver.sys is missing\n");
				return 1;
			}
			printf("Writing 0 to the DSE flags in kernel memory...\n");

			// old: the old dse flags, we write 0 to the dse flags with provider 1
			old = writeDSEFlags(1, 0);
			if (old == -69)
			{
				printf("DSE patching failed\n\n");

				/*
				We skip some providers:

				0 	Intel 					IQVM64/Nal
				1 	MSI 					RTCore64       	Skipped: already failed before
				2 	Gigabyte 				Gdrv
				3 	ASUSTeK 				ATSZIO64
				4 	Patriot 				MsIo64
				5 	ASRock 					GLCKIO2
				6 	G.SKILL 				EneIo64
				7 	EVGA 					WinRing0x64 	Skipped: crashes the system
				8 	Thermaltake 			EneTechIo64
				9 	Huawei 					PhyMemx64
				10 	Realtek 				RtkIo64
				11 	MSI 					EneTechIo64
				12 	LG 						LHA 			Skipped: crashes the system
				13 	ASUSTeK 				AsIO2
				14 	PassMark 				DirectIo64
				15 	GMER 					GmerDrv
				16 	Dell 					DBUtil_2_3 		Skipped: crashes the system
				17 	Benjamin Delpy		 	Mimidrv 		Skipped: detected by defender
				18 	Wen Jia Liu 			KProcessHacker2
				19 	Microsoft 				ProcExp152
				20 	Dell 					DBUtilDrv2
				21 	DarkByte 				Dbk64
				22 	ASUSTeK 				AsIO3
				23 	Marvin 					Hw
				24 	CODESYS 				SysDrv3S
				25 	Zemana 					amsdk
				26 	HiRes Ent. 				inpoutx64
				27 	PassMark 				DirectIo64
				28 	ASRock 					AsrDrv106
				29 	Arthur 					Liberman
				30 	AMD 					AMDRyzenMasterDriver
				31 	Hilscher 				physmem
				32 	Lenovo				 	LDD
				33 	Dell 					pcdsrvc_x64
				34 	MSI 					winio
				35 	HP 						EtdSupport
				36 	Pavel Yosifovich 		KExplore
				37 	Pavel Yosifovich 		KObjExp
				38 	Pavel Yosifovich 		KRegExp
				39 	Inspect Element LTD 	EchoDrv
				40 	NVidia 					nvoclock
				41 	Binalyze 				IREC
				42 	DavidXXW 				PhyDMACC
				43 	Razer 					rzpnk
				44 	AMD 					PdFwKrnl
				45 	AMD 					AODDriver
				46 	Wincor Nixdorf 			wnBios64
				47 	EVGA 					EleetX1
				48 	ASRock 					AxtuDrv
				49 	ASRock 					AppShopDrv103
				50 	ASRock 					AsrDrv107n
				51 	ASRock 					AsrDrv107
				*/
				int providerBlacklist[] = {1, 7, 12, 16, 17};
				int providerArraySize = ARRAYLENGTH(providerBlacklist);

				// Loop trough the providers, try to use them for DSE patching and skip the blacklisted ones
				for (int i = 0; i < 52; i++)
				{
					int contin = 0;
					for (int j = 0; j < providerArraySize; j++)
					{
						if (i == providerBlacklist[j])
							contin = 1;
					}
					if (contin)
					{
						contin = 0;
						continue;
					}

					printf("trying different provider (%d/51)\n", i);
					old = writeDSEFlags(i, 0);
					if (old != -69)
					{
						printf("Success with provider %d!\n", i);
						successProvider = i;
						break;
					}
					else
					{
						printf("\nFailure!\n");

						if (i == 51)
						{
							printf("\nCould not write DSE flags, please read the section \"Manual driver setup:\" in the README.md\n");
							exit(1);
							break;
						}
					}
				}
			}
		}

		/* If we got here, the DSE patching succeeded, we get the full path of kerneltoysdriver.sys and create a serivce
		with it of type SERVICE_KERNEL_DRIVER and start it
		*/
		int startDriverExitCode = 0;
		char fullPath[MAX_PATH];
		DWORD result = GetFullPathNameA("KernelToysDriver.sys", MAX_PATH, fullPath, NULL);

		if (result == 0)
		{
			printf("Could not get the full path of KernelToysDriver.sys, please make sure to not rename, move or delete it and that the full file path doesn't exceed MAX_PATH (260) lasterror: %ld\n", GetLastError());
			if (writedse)
			{
				writeOldDseFlags(successProvider, old);
			}

			return 1;
		}

		// Open a handle to the SC manager, necessary to create services
		SC_HANDLE scManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE | SERVICE_QUERY_STATUS);
		if (scManager == NULL)
		{
			printf("Failed to open SC manager");
			return 1;
		}

		char *servName = "kerneltoys";

		// Create the service
		printf("Creating service...\n");
		SC_HANDLE hKernelToysDriver = CreateServiceA(scManager,
													 servName,
													 NULL,
													 SERVICE_QUERY_STATUS | DELETE | SERVICE_START,
													 SERVICE_KERNEL_DRIVER,
													 SERVICE_DEMAND_START,
													 SERVICE_ERROR_NORMAL,
													 fullPath,
													 NULL, NULL, NULL, NULL, NULL);

		if (hKernelToysDriver == NULL)
		{
			if (GetLastError() == 1073)
			{
				printf("The service already exists!\n");
				hKernelToysDriver = OpenServiceA(scManager, "kerneltoys", SERVICE_QUERY_STATUS | DELETE | SERVICE_START);
			}
			else
			{
				printf("CreateService failed with lasterror %ld\n", GetLastError());
				startDriverExitCode = 1;
				goto handle_cleanup_and_dse_fix;
			}
		}
		printf("Success!\n");
		
		// Start the service (the driver)
		printf("Starting driver...\n");
		if (StartServiceA(hKernelToysDriver, 0, NULL) == FALSE)
		{
			if (GetLastError() == ERROR_SERVICE_ALREADY_RUNNING)
			{
				printf("The driver is already running!\n");
			}
			else
			{
				printf("StartService failed to start the driver, lasterror: %ld\n", GetLastError());
				DeleteService(hKernelToysDriver);
			}
			startDriverExitCode = 1;
			goto handle_cleanup_and_dse_fix;
		}
		printf("Success!\n");

		// We get and print some information about the service and show it to the user
		SERVICE_STATUS driverStatus;
		QueryServiceStatus(hKernelToysDriver, &driverStatus);

		printf("Driver information:\n");
		printf("   SERVICE NAME:       %s\n", servName);
		PrintDriverStatus(0, "TYPE:", driverStatus.dwServiceType, BITSTRUCT_SERVICE_TYPE, BITSTRUCT_SERVICE_TYPE_BUFFER_LENGTH, BITSTRUCT_SERVICE_TYPE_PAIR_LENGTH);
		PrintDriverStatus(1, "CURRENT STATE:", driverStatus.dwCurrentState, VALUESTRUCT_SERVICE_CURRENT_STATE, 0, ARRAYLENGTH(VALUESTRUCT_SERVICE_CURRENT_STATE));
		PrintDriverStatus(0, "ACCEPTED CONTROLS:", driverStatus.dwControlsAccepted, BITSTRUCT_SERVICE_ACCEPTED_CONTROLS, BITSTRUCT_SERVICE_ACCEPTED_CONTROLS_BUFFER_LENGTH, BITSTRUCT_SERVICE_ACCEPTED_CONTROLS_PAIR_LENGTH);
		printf("   CHECKPOINT:         0x%lX (%lu)\n", driverStatus.dwCheckPoint, driverStatus.dwCheckPoint);
		printf("   WAIT HINT:          0x%lX (%lu)\n", driverStatus.dwWaitHint, driverStatus.dwWaitHint);
		printf("   WIN32 EXIT CODE:    0x%lX (%lu)\n", driverStatus.dwWin32ExitCode, driverStatus.dwWin32ExitCode);
		printf("   SPECIFIC EXIT CODE: 0x%lX (%lu)\n", driverStatus.dwServiceSpecificExitCode, driverStatus.dwServiceSpecificExitCode);

		// Cleanup
		handle_cleanup_and_dse_fix:
		CloseServiceHandle(hKernelToysDriver);
		CloseServiceHandle(scManager);
		if (writedse)
		{
			// If we patched the dse flags before, we now write the old flags back because otherwise the system crashes after some time
			writeOldDseFlags(successProvider, old);
		}
		printf("All done!");
		return startDriverExitCode;
	}

	// If the user wants to stop the driver...
	else if ((strcmp(argv1ow, "-stopdriver") == 0) || (strcmp(argv1ow, "-so") == 0))
	{
		// Also requires elevation
		if (!amIElevated())
		{
			printError(EPVelevationRequired, 1, 0);
			return 1;
		}
		// Stop the driver and delete the service (ik i have to implement my own method for this too)
		printf("Stopping driver...\n");
		system("sc stop kerneltoys");
		printf("Removing service...\n");
		system("sc delete kerneltoys");

		return 0;
	}

	else if (strcmp(argv1ow, "deletesymblink") == 0)
	{
		// Print usage if there arent enough arguments
		if (argc < 3)
		{
			printf("Usage: %s deletesymblink <Native NT symbolic link path>\n", argv[0]);
			return 1;
		}
		else
		{
			ShowEleveationInfoBasedOnDeviceSecurityDescriptor();
			printf("Sending the IOCTL to delete a symbolic link...\n");

			// Convert the symbolic link the user provided into a wide string
			WCHAR *symbLink;
			if (!StrToWStr(argv[2], &symbLink))
			{
				printError(EPVstringModify, 1, 0);
				return 1;
			}

			// send the information to the driver
			sendIOCTL(IOCTL_SYMBLINK, symbLink, WSTRING_LENGTH_NULLT(symbLink));
			free(symbLink);
		}
	}
	else if (strcmp(argv1ow, "terminate") == 0)
	{
		// Print usage if there arent enough arguments
		if (argc < 3)
		{
			printf("Usage: %s terminate <PID>\n", argv[0]);
			return 1;
		}
		else
		{
			ShowEleveationInfoBasedOnDeviceSecurityDescriptor();
			printf("Sending the IOCTL to terminate a process...\n");

			// Convert the pid argument into an ULONG
			ULONG PID = strtoul(argv[2], NULL, 10);
			if (PID == 0)
			{
				printf("Please pass a valid PID (number) as an argument\n");
				return 1;
			}

			sendIOCTL(IOCTL_TERMINATOR, &PID, sizeof(PID));
		}
	}
	else if (strcmp(argv1ow, "deletefile") == 0)
	{
		// Print usage if there arent enough arguments
		if (argc < 3)
		{
			printf("Usage: %s deletefile <\"Full path to file\">\n", argv[0]);
			return 1;
		}
		else
		{

			ShowEleveationInfoBasedOnDeviceSecurityDescriptor();
			WCHAR *widedPath;
			// Convert the ansi string argument into a unicode string
			if (!StrToWStr(argv[2], &widedPath))
			{
				printError(EPVinvalidInput, 1, 0);
				return 1;
			}
			// If its NULL, something went wrong
			if (widedPath == NULL)
			{
				printError(EPVmemoryAllocation, 1, 0);
				return 1;
			}

			// Set up the struct that we send to the driver
			struct DELETE_FILE_IOCTL delMsg = {0};
			delMsg.normalPath = widedPath;

			WCHAR *dosPath;
			// Prepend "\??\" to the unicode path to make it a full nt path
			if (!modifyWideStringWithErrorPrint(widedPath, L"\\??\\", STUPprepend, &dosPath))
			{
				return 1;
			}

			delMsg.dosPath = dosPath;
			printf("Sending the IOCTL to delete a file...\n");
			sendIOCTL(IOCTL_DELETEFILE, &delMsg, sizeof(struct DELETE_FILE_IOCTL));

			// Cleanup
			free(dosPath);
			free(widedPath);
		}
	}
	else if (strcmp(argv1ow, "bugcheck") == 0)
	{
		// Print usage if there arent enough arguments
		if (argc < 3)
		{
			printf("Usage: %s bugcheck <Hex:stopcode>\n", argv[0]);
			return 1;
		}
		else
		{
			ShowEleveationInfoBasedOnDeviceSecurityDescriptor();
			printf("Sending the IOCTL to trigger a bugcheck...\n");

			ULONG stopcode = strtoul(argv[2], NULL, 16);

			sendIOCTL(IOCTL_BUGCHECK, &stopcode, sizeof(ULONG));
		}
	}
	else if (strcmp(argv1ow, "ppl") == 0)
	{
		// Print usage if there arent enough arguments
		if (argc < 4)
		{
			printf("Usage: %s ppl <PID> <none|light|full|max> (<Hex:ProtectionOffset>)\n", argv[0]);
			return 1;
		}
		else
		{
			if (!ShowEleveationInfoBasedOnDeviceSecurityDescriptor())
			{
				return 1;
			}
			struct PP_INFO ppinf;
			ULONG PsProtectionOffset;
			if (argc > 4)
			{
				PsProtectionOffset = strtoul(argv[4], NULL, 16);
				if (PsProtectionOffset == 0)
				{
					printf("Please pass in a valid hexdecimal number as ProtectionOffset\n");
				}
			}
			else
			{
				PsProtectionOffset = autoProtectionOffset();
			}

			if (PsProtectionOffset == 0)
			{
				printf("Couldn't find the protection offset, please pass in the protection offset manually\n");
				return 1;
			}
			printf("Found ProtectionOffset: 0x%lx\n", PsProtectionOffset);
			int PID = atoi(argv[2]);
			if (PID == 0)
			{
				printf("Please pass a valid PID (number) as an argument\n");
				return 1;
			}

			char *argv3ow = _strdup(argv[3]);
			int lvl = 0;
			_strlwr_s(argv3ow, strlen(argv[3]) + 1);

			if (strcmp(argv3ow, "none") == 0)
			{
			}
			else if (strcmp(argv3ow, "light") == 0)
			{
				lvl = 1;
			}
			else if (strcmp(argv3ow, "full") == 0)
			{
				lvl = 2;
			}
			else if (strcmp(argv3ow, "max") == 0)
			{
				lvl = 3;
			}
			else
			{
				printf("Please use one of the valid protection levels: none, light, full, max\n");
				return 1;
			}

			ppinf.PID = &PID;
			ppinf.level = &lvl;
			ppinf.ProtectionOffset = PsProtectionOffset;

			printf("Sending the IOCTL to modify the EPROCESS of process %d\n", PID);
			sendIOCTL(IOCTL_PPL, &ppinf, sizeof(struct PP_INFO));
		}
	}
	else if (strcmp(argv1ow, "createfile") == 0)
	{
		// Print usage if there arent enough arguments
		if (argc < 3)
		{
			printf("Usage: %s createfile <\"Full path to file\">\n", argv[0]);
			return 1;
		}
		else
		{
			ShowEleveationInfoBasedOnDeviceSecurityDescriptor();
			printf("Sending the IOCTL to create a file...\n");

			WCHAR *widedPath;
			if (!StrToWStr(argv[2], &widedPath))
			{
				printf("Invalid file path\n");
				return 1;
			}

			const size_t arrayLen = wcslen(widedPath) + 5;
			WCHAR *FullPath = malloc(arrayLen * sizeof(WCHAR));

			if (FullPath == NULL)
			{
				printError(EPVmemoryAllocation, 1, 0);
				return 1;
			}
			if (wcscpy_s(FullPath, arrayLen, L"\\??\\"))
			{
				printError(EPVstringcopy, 1, 0);
				return 1;
			}
			if (wcscat_s(FullPath, arrayLen, widedPath))
			{
				printError(EPVstringconcatenate, 1, 0);
				return 1;
			}
			free(widedPath);
			size_t bufferSize = (wcslen(FullPath) + 1) * sizeof(WCHAR);
			sendIOCTL(IOCTL_CREATEFILE, FullPath, bufferSize);
			free(FullPath);
		}
	}
	else if (strcmp(argv1ow, "createdir") == 0)
	{
		// Print usage if there arent enough arguments
		if (argc < 3)
		{
			printf("Usage: %s createdir <\"Full path to directory\">\n", argv[0]);
			return 1;
		}
		else
		{
			ShowEleveationInfoBasedOnDeviceSecurityDescriptor();
			printf("Sending the IOCTL to create a directory...\n");

			WCHAR *widedPath;
			WCHAR *FullPath;

			if (!StrToWStr(argv[2], &widedPath))
			{
				printError(EPVstringModify, 1, 0);
				return 1;
			}

			if (!modifyWideStringWithErrorPrint(widedPath, L"\\??\\", STUPprepend, &FullPath))
			{
				return 1;
			}
			free(widedPath);

			size_t bufferSize = (wcslen(FullPath) + 1) * sizeof(WCHAR);

			sendIOCTL(IOCTL_CREATEDIRECTORY, FullPath, bufferSize);
			free(FullPath);
		}
	}
	else if (strcmp(argv1ow, "deletekey") == 0)
	{
		// Print usage if there arent enough arguments
		if (argc < 3)
		{
			printf("Usage: %s deletekey <\"Native NT path to registry key\">\n", argv[0]);
			return 1;
		}
		else
		{
			ShowEleveationInfoBasedOnDeviceSecurityDescriptor();
			printf("Sending the IOCTL to delete a key...\n");

			WCHAR *widedPath;
			if (!StrToWStr(argv[2], &widedPath))
			{
				printError(EPVstringModify, 1, 0);
				return 1;
			}

			size_t bufferSize = (wcslen(widedPath) + 1) * sizeof(WCHAR);
			sendIOCTL(IOCTL_DELETEKEY, widedPath, bufferSize);
		}
	}
	else if (strcmp(argv1ow, "createkey") == 0)
	{
		// Print usage if there arent enough arguments
		if (argc < 3)
		{
			printf("Usage: %s createkey <\"Native NT path to registry key\">\n", argv[0]);
			return 1;
		}
		else
		{
			ShowEleveationInfoBasedOnDeviceSecurityDescriptor();
			printf("Sending the IOCTL to create a key...\n");

			WCHAR *widedPath;
			if (!StrToWStr(argv[2], &widedPath))
			{
				printError(EPVstringModify, 1, 0);
				return 1;
			}
			size_t bufferSize = (wcslen(widedPath) + 1) * sizeof(WCHAR);

			sendIOCTL(IOCTL_CREATEKEY, widedPath, bufferSize);
		}
	}
	else if (strcmp(argv1ow, "unloaddriver") == 0)
	{
		// Print usage if there arent enough arguments
		if (argc < 3)
		{
			printf("Usage: %s unloaddriver <Drivername>\n", argv[0]);
			return 1;
		}
		else
		{
			ShowEleveationInfoBasedOnDeviceSecurityDescriptor();
			printf("Sending the IOCTL to unload a driver...\n");

			WCHAR *DriverName;
			if (!StrToWStr(argv[2], &DriverName))
			{
				printError(EPVstringModify, 1, 0);
				return 1;
			}
			if (DriverName == NULL)
			{
				printf("Invalid driver name\n");
				return 1;
			}
			WCHAR *FullPath;
			if (!modifyWideStringWithErrorPrint(L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\", DriverName, STUPappend, &FullPath))
			{
				return 1;
			}
			free(DriverName);
			size_t bufferSize = (wcslen(FullPath) + 1) * sizeof(WCHAR);
			sendIOCTL(IOCTL_UNLOADDRIVER, FullPath, bufferSize);
			free(FullPath);
		}
	}
	else if (strcmp(argv1ow, "ntshutdown") == 0)
	{
		// Print usage if there arent enough arguments
		if (argc < 3)
		{
			printf("Usage: %s ntshutdown <shutdown|reboot|bios>\n", argv[0]);
			return 1;
		}

		char *argv2ow = _strdup(argv[2]);
		int sdt = 0;
		_strlwr_s(argv2ow, strlen(argv[2]) + 1);

		if (strcmp(argv2ow, "shutdown") == 0)
		{
		}
		else if (strcmp(argv2ow, "reboot") == 0)
		{
			sdt = 1;
		}
		else if (strcmp(argv2ow, "bios") == 0)
		{
			sdt = 2;
		}

		else
		{
			printf("Please use one of the valid shutdown types: shutdown, reboot, bios\n");
			return 1;
		}

		HMODULE ntdll = LoadLibraryW(L"ntdll.dll");
		if (ntdll == NULL)
		{
			printf("Failed to load ntdll :(\n");
			return 1;
		}
		NtShutdownSystem ntshutsys = (NtShutdownSystem)GetProcAddress(ntdll, "NtShutdownSystem");
		if (ntshutsys == NULL)
		{
			printf("Failed to get NtShutdownSystem's address\n");
			return 1;
		}
		printf("Found syscall address: %p\n", ntshutsys);
		HANDLE hToken;
		if (!GetOwnToken(TOKEN_ADJUST_PRIVILEGES, &hToken))
		{
			printf("OpenProcessToken for own token failed\n");
			return 1;
		}

		if (!AddPrivilegeToTokenW(hToken, L"SeShutdownPrivilege"))
		{
			printf("Failed to get SeShutdownPrivilege\n");
			return 1;
		}
		printf("goodbye windows :)");
		ntshutsys(sdt);
	}
	else if (strcmp(argv1ow, "criticalprocess") == 0)
	{
		// Print usage if there arent enough arguments
		if (argc < 4)
		{
			printf("Usage: %s criticalprocess <PID> <true|false>\n", argv[0]);
			return 1;
		}

		if (!amIElevated())
		{
			printError(EPVelevationRequired, 1, 0);
			return 1;
		}

		// Create a copy of argv[3] that we will convert to lowercase so the user can do TRUE or true
		char *argv3ow = _strdup(argv[3]);
		ULONG newValue = 0;
		_strlwr_s(argv3ow, strlen(argv[3]) + 1);
		
		if (strcmp(argv3ow, "true") == 0)
		{
			// 1 means the process wil be set to critical, 0 is the opposite
			newValue = 1;
		}
		else if (strcmp(argv3ow, "false") == 0)
		{
		}
		else
		{
			printf("Please use one of the valid values: true, false\n");
			return 1;
		}

		HANDLE ownToken;

	
		if (!GetOwnToken(TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &ownToken))
		{
			printf("Failed to open own process\n");
		}

		if (!AddPrivilegeToTokenW(ownToken, L"SeDebugPrivilege"))
		{
			printf("Failed to enable SeDebugPrivilege for own process\n");
			return 1;
		}

		DWORD PID = strtoul(argv[2], NULL, 10);
		if (PID == 0)
		{
			printf("Invalid pid\n");
			return 1;
		}
		printf("Setting process information...\n");
		HANDLE targetProcess = OpenProcess(PROCESS_SET_INFORMATION, 0, PID);
		if (targetProcess == NULL)
		{
			printf("Failed to open target process");
			return 1;
		}
		NTSTATUS status = SetProcessIsCritical(targetProcess, newValue);

		if (status)
		{
			printf("Failed to set target process as critical, ntstatus of NtSetInformationProcess: %ld\n", status);
			return 1;
		}
		printf("The operation succeeded!");
	}
	else if (strcmp(argv1ow, "criticalthread") == 0)

	{
		// Print usage if there arent enough arguments
		if (argc < 4)
		{
			printf("Usage: %s criticalthread <TID> <true|false>\n", argv[0]);
			return 1;
		}
		ShowEleveationInfoBasedOnDeviceSecurityDescriptor();

		DWORD TID = strtoul(argv[2], NULL, 10);
		if (TID == 0)
		{
			printf("Invalid tid\n");
			return 1;
		}

		int critical = 0;
		_strlwr_s(argv[3], strlen(argv[3]) + 1);

		if (strcmp(argv[3], "true") == 0)
		{
			critical = 1;
		}
		else if (strcmp(argv[3], "false") == 0)
		{
		}
		else
		{
			printf("Please use one of the valid values: true, false\n");
			return 1;
		}
		struct CRITICAL_THREAD_INFO threadInfo;
		threadInfo.critical = critical;
		threadInfo.TID = TID;
		printf("Sending the IOCTL to modify %ld's thread information...\n", TID);
		sendIOCTL(IOCTL_CRITICALTHREAD, &threadInfo, sizeof(struct CRITICAL_THREAD_INFO));
	}
	else if (strcmp(argv1ow, "copyfile") == 0)
	{
		// Print usage if there arent enough arguments
		if (argc < 4)
		{
			printf("Usage: %s copyfile <\"Full path to source file\"> <\"Full path to destination file\">\n", argv[0]);
			return 1;
		}
		else
		{

			ShowEleveationInfoBasedOnDeviceSecurityDescriptor();

			PWSTR srcPath;
			PWSTR dstPath;

			if (!StrToWStr(argv[2], &srcPath))
			{
				printError(EPVinvalidInput, 1, 0);
				return 1;
			}

			if (srcPath == NULL)
			{
				printError(EPVmemoryAllocation, 1, 0);
				return 1;
			}
			if (!StrToWStr(argv[3], &dstPath))
			{
				printError(EPVinvalidInput, 1, 0);
				return 1;
			}

			if (srcPath == NULL)
			{
				printError(EPVmemoryAllocation, 1, 0);
				return 1;
			}
			PWSTR fullSrcPath;
			PWSTR fullDstPath;

			if (!modifyWideStringWithErrorPrint(srcPath, L"\\??\\", STUPprepend, &fullSrcPath))
			{
				return 1;
			}
			if (!modifyWideStringWithErrorPrint(dstPath, L"\\??\\", STUPprepend, &fullDstPath))
			{
				return 1;
			}

			struct COPY_FILE_IOCTL copyIoctl;
			copyIoctl.srcFile = fullSrcPath;
			copyIoctl.dstFile = fullDstPath;
			free(srcPath);
			free(dstPath);

			printf("Sending the IOCTL to copy a file...\n");
			sendIOCTL(IOCTL_COPYFILE, &copyIoctl, sizeof(struct COPY_FILE_IOCTL));
			free(fullSrcPath);
			free(fullDstPath);
		}
	}
	else if (strcmp(argv1ow, "tokengrab") == 0)
	{
		// Print usage if there arent enough arguments
		if (argc < 4)
		{
			printf("Usage: %s tokengrab <PID> <\"ExePath\"> (<Privilegies>)\n", argv[0]);
			return 1;
		}
		else
		{

			ShowEleveationInfoBasedOnDeviceSecurityDescriptor();
			// Convert the pid input into a DWORD (unsigned long)
			DWORD PID = strtoull(argv[2], NULL, 10);
			
			if (!PID)
			{
				printf("Invalid PID\n");
				return 1;
			}

			HANDLE hOwnToken;
			GetOwnToken(TOKEN_ADJUST_PRIVILEGES, &hOwnToken);

			// Enable SeDebugPrivilege for the own token so we can open nearly any process
			printf("Enabling SeDebugPrivilege for own token...\n");
			if (!AddPrivilegeToTokenW(hOwnToken, L"SeDebugPrivilege"))
			{
				printf("Failed to enable SeDebugPrivilege for own token");
				return 1;
			}
			CloseHandle(hOwnToken);

			// If we got SeDebugPrivilege, open the target process
			printf("Opening target process...\n");
			HANDLE hTargetProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, PID);
			if (hTargetProcess == NULL)
			{
				printf("Failed to open target process %lu", PID);
				return 1;
			}

			HANDLE hToken2;
			// Open the target process's token
			if (!OpenProcessToken(hTargetProcess, TOKEN_DUPLICATE, &hToken2))
			{
				printf("Failed to open %lu's token, lasterror %lu", PID, GetLastError());
				return 1;
			}

			HANDLE hDupToken;
			// Duplicate the token we opened
			if (!DuplicateTokenEx(hToken2, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hDupToken))
			{
				printf("Token duplication failed, lasterrror %lu", GetLastError());
				return 1;
			}


			/* If the user provided the optional privileges argument, check if it matches "allprivileges" or "-allprivileges"
			if so, enable every privilege
			*/ 
			if (argc > 4)
			{
			char* argv4low = _strlwr(argv[4]);
			if (!strcmp(argv4low, "allprivileges") || !strcmp(argv4low, "-allprivileges"))
			{
				printf("Adding all privileges...\n");
				int numPrivileges = ARRAYLENGTH(AllPrivs);
				for (int i = 0; i < numPrivileges; i++)
				{
					if (AddPrivilegeToTokenA(hDupToken, AllPrivs[i]))
					{
						printf("Added %s\n", AllPrivs[i]);
					}
					else
					{
						printf("Failed to add %s\n", AllPrivs[i]);
					}
				}

			// If the user doesnt want every privilege, split the argument for every comma and enable the privilege
			}else{
				printf("Adding privileges...\n");
				int count;
				char **substrings = splitString(argv[4], ",", &count);
				if (substrings != NULL)
				{
					for (int i = 0; i < count; i++)
					{
						if (AddPrivilegeToTokenA(hDupToken, substrings[i]))
						{
							printf("Added %s\n", substrings[i]);
						}
						else
						{
							printf("Failed to add %s\n", substrings[i]);
						}
					}
				}
			}
			}
			
			// Set the Desktop to Winsta0\Default, otherwise windows will we invisible
			STARTUPINFOW si = {0};
			si.lpDesktop = L"Winsta0\\Default";

			PROCESS_INFORMATION pi;

			// Turn the image path argument into a wide string (WCHAR* aka LPWSTR) because there is no ANSI version of CreateProcessWithToken
			LPWSTR wImagePath;
			if (!StrToWStr(argv[3], &wImagePath))
			{
				printError(EPVstringModify, 0, 0);
				return 1;
			}

			// Finally, create the process with the token we copied and modified
			if (!CreateProcessWithTokenW(hDupToken, LOGON_WITH_PROFILE, wImagePath, NULL, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi))
			{
				printf("Process creation failed with lasterror %lu", GetLastError());
				return 1;
			}


			// Cleanup
			free(wImagePath);

			CloseHandle(pi.hThread);
			CloseHandle(pi.hProcess);

			CloseHandle(hDupToken);
			CloseHandle(hToken2);
			CloseHandle(hTargetProcess);
		}
	}
	else
	{

		// If the option was invalid, just print the usage
		printUsage(argv);
		return 1;
	}

	return 0;
}

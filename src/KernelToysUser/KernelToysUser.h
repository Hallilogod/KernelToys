#ifndef KERNELTOYS_USER_H
#define KERNELTOYS_USER_H

#include <stdio.h>
#include <Windows.h>
#include "ntbuilds.h"

#define IOCTL_TERMINATOR CTL_CODE(FILE_DEVICE_UNKNOWN,        0x00000000, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SYMBLINK CTL_CODE(FILE_DEVICE_UNKNOWN,          0x00000001, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DELETEFILE CTL_CODE(FILE_DEVICE_UNKNOWN,        0x00000002, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_BUGCHECK CTL_CODE(FILE_DEVICE_UNKNOWN,          0x00000003, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_PPL CTL_CODE(FILE_DEVICE_UNKNOWN,               0x00000004, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CREATEFILE CTL_CODE(FILE_DEVICE_UNKNOWN,        0x00000005, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CREATEDIRECTORY CTL_CODE(FILE_DEVICE_UNKNOWN,   0x00000006, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DELETEKEY CTL_CODE(FILE_DEVICE_UNKNOWN,         0x00000007, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CREATEKEY CTL_CODE(FILE_DEVICE_UNKNOWN,         0x00000008, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_UNLOADDRIVER CTL_CODE(FILE_DEVICE_UNKNOWN,      0x00000009, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CRITICALTHREAD CTL_CODE(FILE_DEVICE_UNKNOWN,    0x0000000a, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_COPYFILE CTL_CODE(FILE_DEVICE_UNKNOWN,          0x0000000b, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define PS_REQUEST_BREAKAWAY 1
#define PS_NO_DEBUG_INHERIT 2
#define PS_INHERIT_HANDLES 4
#define PS_UNKNOWN_VALUE 8
#define PS_ALL_FLAGS PS_REQUEST_BREAKAWAY | PS_NO_DEBUG_INHERIT | PS_INHERIT_HANDLES | PS_UNKNOWN_VALUE

#define ARRAYLENGTH(x) (sizeof(x) / sizeof(x[0]))
#define STRING_LENGTH_NULLT(x) ((strlen(x) + 1))
#define WSTRING_LENGTH_NULLT(x) ((wcslen(x) + 1) * sizeof(WCHAR))



struct DELETE_FILE_IOCTL
{
	PWCHAR dosPath;
	PWCHAR normalPath;
};

struct PP_INFO
{
	int *PID;
	ULONG ProtectionOffset;
	int *level;
};

struct CRITICAL_THREAD_INFO {
	ULONG TID;
	int critical;
};

struct COPY_FILE_IOCTL {
	PWCHAR srcFile;
	PWCHAR dstFile;
};

typedef int(NTAPI *NtShutdownSystem)(int);

typedef NTSTATUS(NTAPI *NtSetInformationProcess)(
	HANDLE ProcessHandle,
	PROCESS_INFORMATION_CLASS ProcessInformationClass,
	PVOID ProcessInformation,
	ULONG ProcessInformationLength);

typedef NTSTATUS(NTAPI* NtSetInformationThread)(
   HANDLE               ThreadHandle,
   THREAD_INFORMATION_CLASS ThreadInformationClass,
   PVOID                ThreadInformation,
   ULONG                ThreadInformationLength);

enum errorPrintValue
{
	EPVmemoryAllocation,
	EPVstringcopy,
	EPVstringconcatenate,
	EPVinvalidInput,
	EPVstringModify,
	EPVelevationRequired
};

enum stringUpdate
{
	STUPprepend,
	STUPappend
};

// Helper funcs
BOOL getOwnToken(PHANDLE pHandle){
		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, pHandle))
		{
			return FALSE;
		}
	return TRUE;
}

int AddPrivilegeToToken(HANDLE token, LPCWSTR Privilege)
{
	TOKEN_PRIVILEGES tp;
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!LookupPrivilegeValueW(NULL, Privilege, &tp.Privileges[0].Luid))
	{

		return 0;
	}

	if (!AdjustTokenPrivileges(token, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
	{
		return 0;
	}
	if (GetLastError() != ERROR_SUCCESS)
	{
		return 0;
	}
	return 1;
}

void printError(enum errorPrintValue error, int newline, int ext)
{
	switch (error)
	{
	case EPVmemoryAllocation:
		printf("Memory allocation failed");
		break;
	case EPVstringcopy:
		printf("Error copying string");
		break;
	case EPVstringconcatenate:
		printf("Error concatenating strings");
		break;
	case EPVinvalidInput:
		printf("Invalid input");
		break;
	case EPVstringModify:
		printf("String modification failed");
		break;
	case EPVelevationRequired:
		printf("Admin privilegies are required for this!");
		break;
		default:
		break;

		
	}
	if (newline)
		{
			printf("\n");
		}
		if (ext)
		{
			ExitProcess(1);
		}
}

int modifyStringWithErrorPrint(char *inputString, char *secondString, enum stringUpdate option, char **outputString)
{

	const size_t inputLength = strlen(inputString);
	const size_t secondLength = strlen(secondString);
	const size_t outputLength = inputLength + secondLength + 1;
	*outputString = (char*)malloc(outputLength);
	if (*outputString == NULL)
	{
		printError(EPVmemoryAllocation, 1, 0);
		return 0;
	}
	switch (option)
	{
	case STUPprepend:

		if (strcpy_s(*outputString, outputLength, secondString))
		{
			printError(EPVstringcopy, 1, 0);
			return 0;
		}

		if (strcat_s(*outputString, outputLength, inputString))
		{
			printError(EPVstringconcatenate, 1, 0);
			return 0;
		}
		break;

	case STUPappend:
		if (strcpy_s(*outputString, outputLength, inputString))
		{
			printError(EPVstringcopy, 1, 0);
			return 0;
		}

		if (strcat_s(*outputString, outputLength, secondString))
		{
			printError(EPVstringconcatenate, 1, 0);
			return 0;
		}
		break;

	default:
		return 0;
		break;
	}

	return 1;
}

int modifyWideStringWithErrorPrint(LPWSTR inputString, LPWSTR secondString, enum stringUpdate option, LPWSTR *outputString)
{

	const size_t inputLength = wcslen(inputString) * sizeof(WCHAR);
	const size_t secondLength = wcslen(secondString) * sizeof(WCHAR);
	const size_t outputLength = inputLength + secondLength + sizeof(WCHAR);
	*outputString = (LPWSTR)malloc(outputLength);
	if (*outputString == NULL)
	{
		printError(EPVmemoryAllocation, 1, 0);
		return 0;
	}
	switch (option)
	{
	case STUPprepend:

		if (wcscpy_s(*outputString, outputLength, secondString))
		{
			printError(EPVstringcopy, 1, 0);
			return 0;
		}

		if (wcscat_s(*outputString, outputLength, inputString))
		{
			printError(EPVstringconcatenate, 1, 0);
			return 0;
		}
		break;

	case STUPappend:
		if (wcscpy_s(*outputString, outputLength, inputString))
		{
			printError(EPVstringcopy, 1, 0);
			return 0;
		}

		if (wcscat_s(*outputString, outputLength, secondString))
		{
			printError(EPVstringconcatenate, 1, 0);
			return 0;
		}
		break;

	default:
		return 0;
		break;
	}

	return 1;
}

int StrToWStr(LPSTR inputString, LPWSTR* outputString)
{

	int size = MultiByteToWideChar(CP_UTF8, 0, inputString, -1, NULL, 0);
	if (size == 0)
	{
		return 0;
	}
	*outputString = (LPWSTR)malloc(size * sizeof(WCHAR));

	if (outputString == NULL)
	{
		return 0;
	}
	return MultiByteToWideChar(CP_UTF8, 0, inputString, -1, *outputString, size);
}

BOOL amIElevated()
{

	HANDLE hToken;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
	{
		TOKEN_ELEVATION elevation;
		DWORD dwSize;
		if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize))
		{
			if (elevation.TokenIsElevated)
			{
				return TRUE;
			}
			else
			{
				return FALSE;
			}
		}
		else
		{
			return FALSE;
		}
		CloseHandle(hToken);
	}
	else
	{
		return FALSE;
	}
}

int writeDSEFlags(int prv, int x)
{

	int old = -69;
	// Run the external program and open a pipe to capture its output

	char kduCmdLine[100];
	sprintf_s(kduCmdLine, sizeof(kduCmdLine), "kdu.exe -prv %d -dse %d", prv, x);

	FILE *pipe = _popen(kduCmdLine, "r");

	if (pipe)
	{
		char buffer[256];
		while (fgets(buffer, sizeof(buffer), pipe) != NULL)
		{

			printf("kdu output: %s", buffer);
			const char *pattern = "value:";
			const char *start = strstr(buffer, pattern);

			if (start)
			{
				start += strlen(pattern);
				old = (int)strtol(start, NULL, 16);

				break;
			}
		}

		_pclose(pipe);
	}
	else
	{

		printf("Failed to open a pipe to kdu.exe\n");
	}
	return old;
}

void sendIOCTL(DWORD IOCTL_CODE, LPVOID ioctlInfo, DWORD size)
{

	HANDLE hDriver = CreateFileA("\\\\.\\kerneltoys", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

	if (hDriver == INVALID_HANDLE_VALUE)
	{

		DWORD err = GetLastError();
		printf("Failed to get a handle to the driver (\\\\.\\kerneltoys), lasterror: %ld\n", err);
		printf("Please make sure that the driver is running.\n");
		CloseHandle(hDriver);
		return;
	}
	DWORD dwBytesReturned;

	if (!DeviceIoControl(hDriver, IOCTL_CODE, ioctlInfo, size, NULL, 0, &dwBytesReturned, NULL))
	{

		printf("The operation failed! Lasterror: %ld\n", GetLastError());
	}
	else
	{

		printf("The operation succeeded!" /*, returned DWORD: %lu\n", dwBytesReturned*/);
	}
	CloseHandle(hDriver);
}

int getBuildNum()
{
	HKEY hKey;
	DWORD dwType = REG_SZ;
	wchar_t value[256];
	DWORD size = sizeof(value);

	if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, KEY_READ, &hKey) == ERROR_SUCCESS)
	{
		if (RegQueryValueExW(hKey, L"CurrentBuildNumber", NULL, &dwType, (LPBYTE)value, &size) == ERROR_SUCCESS)
		{
			return _wtoi(value);
		}
		RegCloseKey(hKey);
	}
	return 0;
}

ULONG autoProtectionOffset()

{

	ULONG Offset;
	switch (getBuildNum())
	{
	case NT_WIN8_BLUE:
		Offset = PsProtectionOffset_9600;
		break;
	case NT_WIN10_THRESHOLD1:
		Offset = PsProtectionOffset_10240;
		break;
	case NT_WIN10_THRESHOLD2:
		Offset = PsProtectionOffset_10586;
		break;
	case NT_WIN10_REDSTONE1:
		Offset = PsProtectionOffset_14393;
		break;
	case NT_WIN10_REDSTONE2:
	case NT_WIN10_REDSTONE3:
	case NT_WIN10_REDSTONE4:
	case NT_WIN10_REDSTONE5:
	case NT_WIN10_19H1:
	case NT_WIN10_19H2:
		Offset = PsProtectionOffset_15063;
		break;
	case NT_WIN10_20H1:
	case NT_WIN10_20H2:
	case NT_WIN10_21H1:
	case NT_WIN10_21H2:
	case NT_WIN10_22H2:
	case NT_WIN11_21H2:
	case NT_WIN11_22H2:
	case NT_WIN11_23H2:
	case NT_WIN11_24H2:
		Offset = PsProtectionOffset_19041;
		break;
	default:
		Offset = 0;
		break;
	}
	return Offset;
}

FARPROC GetProcAddressFromLib(LPSTR library, LPSTR function, int *success)
{
	HMODULE lib = LoadLibraryA(library);
	if (lib == NULL)
	{
		printf("Failed to load %s\n", library);
		success = 0;
	}
	FARPROC address = GetProcAddress(lib, function);
	if (address == NULL)
	{
		printf("Failed to get %s's address\n", function);
		*success = 0;
	}
	*success = 1;
	return address;
}

NTSTATUS SetProcessIsCritical(HANDLE Handle, ULONG newValue)
{
	int success = 0;
	NtSetInformationProcess ntSetInfo = (NtSetInformationProcess)GetProcAddressFromLib("ntdll.dll", "NtSetInformationProcess", &success);
	if (success)
	{
		return ntSetInfo(Handle, (PROCESS_INFORMATION_CLASS)0x1D, &newValue, sizeof(ULONG));
	}
	return 1;
}

int ShowEleveationInfoBasedOnDeviceSecurityDescriptor(){
	#ifdef KERNELTOYS_SECURE_DEVICE
	if(!amIElevated()){
		printError(EPVelevationRequired,0,1);
		return 0;
	}
	#endif
	return 1;
}

BOOL FileExists(PSTR Path)
{
  DWORD dwAttrib = GetFileAttributesA(Path);

  return (dwAttrib != INVALID_FILE_ATTRIBUTES && 
         !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

#endif
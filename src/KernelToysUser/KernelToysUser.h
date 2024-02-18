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

// Structs that we send to the driver if we need to pass multiple datatypes

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

// undocumented nt apis

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

char *AllPrivs[36] = { "SeCreateTokenPrivilege",
                       "SeAssignPrimaryTokenPrivilege",
                       "SeLockMemoryPrivilege",
                       "SeIncreaseQuotaPrivilege",
                       "SeUnsolicitedInputPrivilege",
                       "SeMachineAccountPrivilege",
                       "SeTcbPrivilege",
                       "SeSecurityPrivilege",
                       "SeTakeOwnershipPrivilege",
                       "SeLoadDriverPrivilege",
                       "SeSystemProfilePrivilege",
                       "SeSystemtimePrivilege",
                       "SeProfileSingleProcessPrivilege",
                       "SeIncreaseBasePriorityPrivilege",
                       "SeCreatePagefilePrivilege",
                       "SeCreatePermanentPrivilege",
                       "SeBackupPrivilege",
                       "SeRestorePrivilege",
                       "SeShutdownPrivilege",
                       "SeDebugPrivilege",
                       "SeAuditPrivilege",
                       "SeSystemEnvironmentPrivilege",
                       "SeChangeNotifyPrivilege",
                       "SeRemoteShutdownPrivilege",
                       "SeUndockPrivilege",
                       "SeSyncAgentPrivilege",
                       "SeEnableDelegationPrivilege",
                       "SeManageVolumePrivilege",
                       "SeImpersonatePrivilege",
                       "SeCreateGlobalPrivilege",
                       "SeTrustedCredManAccessPrivilege",
                       "SeRelabelPrivilege",
                       "SeIncreaseWorkingSetPrivilege",
                       "SeTimeZonePrivilege",
                       "SeCreateSymbolicLinkPrivilege",
                       "SeDelegateSessionUserImpersonatePrivilege"};
// Used for modifyStringWithErrorPrint() / modifyWideStringWithErrorPrint() 
enum errorPrintValue
{
	EPVmemoryAllocation,
	EPVstringcopy,
	EPVstringconcatenate,
	EPVinvalidInput,
	EPVstringModify,
	EPVelevationRequired
};
// Used for modifyString
enum stringUpdate
{
	STUPprepend,
	STUPappend
};

struct BitStruct{
 int value;
const char* string;
};


// structs used for printing the name of bits or values

struct BitStruct BITSTRUCT_SERVICE_TYPE[] =
	{		
{ 0x00000001, "SERVICE_KERNEL_DRIVER" },

{ 0x00000002, "SERVICE_FILE_SYSTEM_DRIVER" },

{ 0x00000010, "SERVICE_WIN32_OWN_PROCESS" },

{ 0x00000020, "SERVICE_WIN32_SHARE_PROCESS" },

{ 0x00000050, "SERVICE_USER_OWN_PROCESS" },

{ 0x00000060, "SERVICE_USER_SHARE_PROCESS" },

{ 0x00000100, "SERVICE_INTERACTIVE_PROCESS" }
};
#define BITSTRUCT_SERVICE_TYPE_BUFFER_LENGTH (strlen("SERVICE_KERNEL_DRIVER")\
 + strlen("SERVICE_FILE_SYSTEM_DRIVER")\
 + strlen("SERVICE_WIN32_OWN_PROCESS")\
 + strlen("SERVICE_WIN32_SHARE_PROCESS")\
 + strlen("SERVICE_USER_OWN_PROCESS")\
 + strlen("SERVICE_USER_SHARE_PROCESS")\
 + strlen("SERVICE_INTERACTIVE_PROCESS")+4)
#define BITSTRUCT_SERVICE_TYPE_PAIR_LENGTH ARRAYLENGTH(BITSTRUCT_SERVICE_TYPE)

struct BitStruct VALUESTRUCT_SERVICE_CURRENT_STATE[] =
	{		
{ 0x00000001, "SERVICE_STOPPED" },

{ 0x00000002, "SERVICE_START_PENDING" },

{ 0x00000003, "SERVICE_STOP_PENDING" },

{ 0x00000004, "SERVICE_RUNNING" },

{ 0x00000005, "SERVICE_CONTINUE_PENDING" },

{ 0x00000006, "SERVICE_PAUSE_PENDING" },

{ 0x00000007, "SERVICE_PAUSED" }
};

struct BitStruct BITSTRUCT_SERVICE_ACCEPTED_CONTROLS[] =
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

#define BITSTRUCT_SERVICE_ACCEPTED_CONTROLS_BUFFER_LENGTH (strlen("SERVICE_ACCEPT_STOP")\
+ strlen("SERVICE_ACCEPT_PAUSE_CONTINUE")\
+ strlen("SERVICE_ACCEPT_SHUTDOWN")\
+ strlen("SERVICE_ACCEPT_PARAMCHANGE")\
+ strlen("SERVICE_ACCEPT_NETBINDCHANGE")\
+ strlen("SERVICE_ACCEPT_HARDWAREPROFILECHANGE")\
+ strlen("SERVICE_ACCEPT_POWEREVENT")\
+ strlen("SERVICE_ACCEPT_SESSIONCHANGE")\
+ strlen("SERVICE_ACCEPT_PRESHUTDOWN")\
+ strlen("SERVICE_ACCEPT_TIMECHANGE")\
+ strlen("SERVICE_ACCEPT_TRIGGEREVENT")\
+ strlen("SERVICE_ACCEPT_USERMODEREBOOT")+4)
#define BITSTRUCT_SERVICE_ACCEPTED_CONTROLS_PAIR_LENGTH ARRAYLENGTH(BITSTRUCT_SERVICE_ACCEPTED_CONTROLS)


// Helper funcs

void PrintValueFlag(DWORD value, struct BitStruct pair[], int arrayLength){
for(DWORD i =0;i<arrayLength;i++){
	if(value == pair[i].value){
		printf("%s",pair[i].string);
		return;
	}
}
}

void PrintBitFlags(int flags, struct BitStruct pair[], int BUFLEN, int PAIRLEN)
{



    char buf[BUFLEN];
    char *write = buf;  
    int i;
    for (i = 0; i < PAIRLEN; i++)
    {
        if ((flags & pair[i].value) == pair[i].value)
        {
            size_t written = write - buf;
            write += _snprintf(write, BUFLEN-written, "%s%s",
                written > 0 ? " | " : "",
                pair[i].string); 
        }
    }
    if (write != buf) 
    {
        *write = '\0'; 

		printf("%s",buf);
       
    }
}

void PrintDriverStatus(BOOL singleValue, char* msg, DWORD flags, struct BitStruct pair[], int BUFLEN, int PAIRLEN){
	printf("   ");
	printf(msg);
	int spaceCount = 20-strlen(msg);
	while(spaceCount){
		printf(" ");
		spaceCount--;
	}
	if(singleValue){
	PrintValueFlag(flags,pair,PAIRLEN);
	}else{
	PrintBitFlags(flags,pair,BUFLEN,PAIRLEN);
	}
	
	printf(" (0x%lX)\n",flags);
}

BOOL GetOwnToken(DWORD DesiredAccess,PHANDLE pHandle){
		if (!OpenProcessToken(GetCurrentProcess(), DesiredAccess, pHandle))
		{
			return FALSE;
		}
	return TRUE;
}

BOOL AddPrivilegeToTokenA(HANDLE token, LPCSTR Privilege)
{
	TOKEN_PRIVILEGES tp;
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!LookupPrivilegeValueA(NULL, Privilege, &tp.Privileges[0].Luid))
	{

		return FALSE;
	}

	if (!AdjustTokenPrivileges(token, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
	{
		return FALSE;
	}
	return TRUE;
}

BOOL AddPrivilegeToTokenW(HANDLE token, LPCWSTR Privilege)
{
	TOKEN_PRIVILEGES tp;
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!LookupPrivilegeValueW(NULL, Privilege, &tp.Privileges[0].Luid))
	{

		return FALSE;
	}

	if (!AdjustTokenPrivileges(token, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
	{
		return FALSE;
	}
	return TRUE;
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

// Can prepend or append another string to the main string
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

// Can prepend or append another string to the main string
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

// Converts an ANSI string into a unicode string, returns FALSE (0) if it failed, TRUE otherwise
BOOL StrToWStr(LPSTR inputString, LPWSTR* outputString)
{

	int size = MultiByteToWideChar(CP_UTF8, 0, inputString, -1, NULL, 0);
	if (size == 0)
	{
		return FALSE;
	}
	*outputString = (LPWSTR)malloc(size * sizeof(WCHAR));

	if (outputString == NULL)
	{
		return FALSE;
	}
	return MultiByteToWideChar(CP_UTF8, 0, inputString, -1, *outputString, size);
}

// Checks if the own token is elevated
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

/* Used to write custom DSE flags with kdu, int prv = the provider (index of the vulnerable driver in drv64.dll)
   int x = the value to write
   returns the old value
*/
int writeDSEFlags(int prv, int x)
{

	int old = -69;

	// Run the external program and open a pipe to capture its output
	char kduCmdLine[100];
	sprintf_s(kduCmdLine, sizeof(kduCmdLine), "kdu.exe -prv %d -dse %d", prv, x);

	FILE *pipe = _popen(kduCmdLine, "r");

	if (pipe)
	{
		// so safe ikr
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
	printf("\n");
	return old;
}

// Same as writeDSEFlags, but with extra info print
int writeOldDseFlags(int successProvider, int old){
			
	printf("\nWriting back old DSE flags... (%d)\n", old);
	return writeDSEFlags(successProvider, old);
			
}

// Used to send the information to the driver via DeviceIoControl
void sendIOCTL(DWORD IOCTL_CODE, LPVOID ioctlInfo, DWORD size)
{
	// W is speed and speed is W
	HANDLE hDriver = CreateFileW(L"\\\\.\\kerneltoys", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

	if (hDriver == INVALID_HANDLE_VALUE)
	{

		printf("Failed to get a handle to the driver (\\\\.\\kerneltoys), lasterror: %ld\n", GetLastError());
		printf("Please make sure that the driver is running.\n");
		CloseHandle(hDriver);
		return;
	}
	DWORD dwBytesReturned;
	// Here we send the message to the driver
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

// Returns the system buildnumber from the registry (SOFTWARE\Microsoft\Windows NT\CurrentVersion\CurrentBuildNumber)
int getBuildNum()
{
	HKEY hKey;
	DWORD dwType = REG_SZ;
	wchar_t value[256];
	DWORD size = sizeof(value);
	// Open the key that contains CurrentBuildNumber
	if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, KEY_READ, &hKey) == ERROR_SUCCESS)
	{
		// Get the value
		if (RegQueryValueExW(hKey, L"CurrentBuildNumber", NULL, &dwType, (LPBYTE)value, &size) == ERROR_SUCCESS)
		{
			// return the value converted to an integer
			return _wtoi(value);
		}
		RegCloseKey(hKey);
	}
	return 0;
}

// Calculates and returns the offset of the Protection member in the EPROCESS struct (relative to the start address of the EPROCESS struct)
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

// Returns the address of a function in a specific library
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

// Sets a process as critical or not critical via NtSetInformationProcess
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

/* If KERNELTOYS_SECURE_DEVICE is set that means that the driver uses a security descriptor that doesnt allow kerneltoys
 to communicate with the driver without elevation, if it is set and we are not elevated, this function prints an error and exits the process*/
int ShowEleveationInfoBasedOnDeviceSecurityDescriptor(){
	#ifdef KERNELTOYS_SECURE_DEVICE
	if(!amIElevated()){
		printError(EPVelevationRequired,0,1);
		return 0;
	}
	#endif
	return 1;
}

// Checks if the given file exists
BOOL FileExists(PSTR Path)
{
  DWORD dwAttrib = GetFileAttributesA(Path);

  return (dwAttrib != INVALID_FILE_ATTRIBUTES && 
         !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

// Splits the input string for every delimiter char
char **splitString(const char *input, const char *delimiter, int *count)
{
    char **substrings = NULL;
    *count = 0;

    // Make a copy of the input string
    char *inputCopy = strdup(input);

    if (inputCopy == NULL)
    {
        printError(EPVmemoryAllocation,0,1);
        return NULL;
    }

    // Tokenize the input string
    char *token = strtok(inputCopy, delimiter);
    while (token != NULL)
    {
    
        (*count)++;

        substrings = (char **)realloc(substrings, sizeof(char *) * (*count));
        if (substrings == NULL)
        {
			free(inputCopy);
            printError(EPVmemoryAllocation,0,1);
            return NULL;
        }
        // Allocate memory for the current substring and copy it
        substrings[*count - 1] = strdup(token);

        token = strtok(NULL, delimiter);
    }

    free(inputCopy);
    return substrings;
}

#endif
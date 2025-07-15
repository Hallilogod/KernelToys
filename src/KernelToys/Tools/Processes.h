#pragma once

#define PROCESS_CREATE_FLAGS_MINIMAL 0x800  // bit 12
#define ProcessBreakOnTermination 0x1D

typedef struct _CRITICAL_THREAD_PARAMETER
{
	ULONG Tid;
	INT Critical;
} CRITICAL_THREAD_PARAMETER, *PCRITICAL_THREAD_PARAMETER;

typedef struct _PROTECT_PROCESS_PARAMETER
{
	ULONG Pid;
	ULONG ProtectionOffset;
	ULONG Level;
} PROTECT_PROCESS_PARAMETER, * PPROTECT_PROCESS_PARAMETER;

typedef struct _INJECT_SHELLCODE_PARAMETER
{
	ULONG Pid;
	PVOID ShellcodeBuffer;
	ULONG ShellcodeBufferSizeBytes;
	PVOID ShellcodeParameterBuffer;
	ULONG ShellcodeParameterBufferSizeBytes;
} INJECT_SHELLCODE_PARAMETER, * PINJECT_SHELLCODE_PARAMETER;

NTSTATUS NTAPI NtSetInformationProcess(
	HANDLE ProcessHandle,
	PROCESS_INFORMATION_CLASS ProcessInformationClass,
	PVOID ProcessInformation,
	ULONG ProcessInformationLength);

BOOL TerminateProcessToyHandler(LPWSTR arguments[], UINT argumentCount);

BOOL ProtectProcessToyHandler(LPWSTR arguments[], UINT argumentCount);

BOOL CriticalThreadToyHandler(LPWSTR arguments[], UINT argumentCount);

BOOL MinimalProcessToyHandler(LPWSTR arguments[], UINT argumentCount);

BOOL InjectShellcodeToyHandler(LPWSTR arguments[], UINT argumentCount);


BOOL CriticalProcessToyHandler(LPWSTR arguments[], UINT argumentCount);

BOOL TokengrabToyHander(LPWSTR arguments[], UINT argumentCount);

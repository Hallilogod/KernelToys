#pragma warning (disable : 4100 4047 4024)


//If you want the kerneltoys kernel options to be usable without admin privilegies, remove this define, remember that then unprivilegied normal processes can abuse this
#define KERNELTOYS_SECURE_DEVICE


#include <ntifs.h>
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


PDEVICE_OBJECT pDevObj;
UNICODE_STRING device, symbolicLink;

struct CRITICAL_THREAD_INFO {
	ULONG TID;
	int critical;
};

struct PP_INFO {
	int* PID;
	ULONG ProtectionOffset;
	int* level;
};

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

struct DELETE_FILE_IOCTL {
	PWCHAR dosPath;
	PWCHAR normalPath;

};

struct COPY_FILE_IOCTL {
	PWCHAR srcFile;
	PWCHAR dstFile;
};

;



NTSTATUS io_complete(PDEVICE_OBJECT pDeviceObject, PIRP pIrp, PVOID ctx) {

	pIrp->UserIosb->Status = pIrp->IoStatus.Status;
	pIrp->UserIosb->Information = pIrp->IoStatus.Information;

	KeSetEvent(pIrp->UserEvent, IO_NO_INCREMENT, FALSE);
	IoFreeIrp(pIrp);

	return STATUS_MORE_PROCESSING_REQUIRED;
}
// thx gabrik for this code
NTSTATUS sendDeleteFileIrp(PFILE_OBJECT file_object) {


	KEVENT event;
	PDEVICE_OBJECT device_object = IoGetBaseFileSystemDeviceObject(file_object);

	PIRP pIrp = IoAllocateIrp(device_object->StackSize, FALSE);

	// Set the complete routine that will free the IRP and signal the event
	KeInitializeEvent(&event, SynchronizationEvent, FALSE);
	IoSetCompletionRoutine(
		pIrp,
		io_complete,
		&event,
		TRUE, TRUE, TRUE);


	FILE_DISPOSITION_INFORMATION_EX dispositionInformation;
	dispositionInformation.Flags =
		FILE_DISPOSITION_DELETE |
		FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE |
		FILE_DISPOSITION_POSIX_SEMANTICS;


	IO_STATUS_BLOCK io_status_block;
	pIrp->AssociatedIrp.SystemBuffer = &dispositionInformation;
	pIrp->UserEvent = &event;
	pIrp->UserIosb = &io_status_block;
	pIrp->Tail.Overlay.OriginalFileObject = file_object;
	pIrp->Tail.Overlay.Thread = KeGetCurrentThread();
	pIrp->Flags = IRP_WRITE_OPERATION;
	pIrp->RequestorMode = KernelMode;

	PIO_STACK_LOCATION stack_location = IoGetNextIrpStackLocation(pIrp);
	stack_location->MajorFunction = IRP_MJ_SET_INFORMATION;
	stack_location->DeviceObject = device_object;
	stack_location->FileObject = file_object;
	stack_location->Flags |= SL_FORCE_DIRECT_WRITE;
	stack_location->Parameters.SetFile.Length = sizeof(FILE_DISPOSITION_INFORMATION_EX);
	stack_location->Parameters.SetFile.FileInformationClass = FileDispositionInformationEx;
	stack_location->Parameters.SetFile.FileObject = file_object;

	IofCallDriver(device_object, pIrp);
	KeWaitForSingleObject(&event, Executive, KernelMode, TRUE, NULL);

	return pIrp->IoStatus.Status;
}
NTSTATUS forceDeleteFile(PUNICODE_STRING dosPath, PUNICODE_STRING normalPath)
{
	UNREFERENCED_PARAMETER(normalPath);
	NTSTATUS status;
	OBJECT_ATTRIBUTES fileObjAttribs;
	HANDLE fileHandle;
	IO_STATUS_BLOCK ioBlock;

	InitializeObjectAttributes(&fileObjAttribs, dosPath,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL, NULL);

	status = IoCreateFileEx(&fileHandle,
		SYNCHRONIZE,
		&fileObjAttribs, &ioBlock,
		NULL, FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
		NULL, 0,
		CreateFileTypeNone, NULL,
		IO_IGNORE_SHARE_ACCESS_CHECK,
		NULL);



	if (!NT_SUCCESS(status)) {
		return status;
	}

	PFILE_OBJECT fileObject;

	status = ObReferenceObjectByHandleWithTag(fileHandle,
		SYNCHRONIZE, *IoFileObjectType,
		KernelMode, 'eliF',
		&fileObject, NULL);

	if (!NT_SUCCESS(status)) {

		ObCloseHandle(fileHandle, KernelMode);
		return status;
	}

	fileObject->SectionObjectPointer->ImageSectionObject = 0;
	fileObject->SharedDelete  = TRUE;
	fileObject->DeleteAccess  = TRUE;
	fileObject->WriteAccess   = TRUE;
	fileObject->ReadAccess    = TRUE;
	fileObject->DeletePending = FALSE;
	fileObject->Busy          = FALSE;


	if (!MmFlushImageSection(fileObject->SectionObjectPointer, MmFlushForDelete)) {

	}

	status = sendDeleteFileIrp(fileObject);

	ObfDereferenceObject(fileObject);
	ObCloseHandle(fileHandle, KernelMode);

	return status;
}

//COOL FUNCTIONS

NTSTATUS DeleteKeyFull(HANDLE ParentKey) {

	NTSTATUS					status;
	PKEY_BASIC_INFORMATION		keyInfo;
	ULONG						outLength;
	OBJECT_ATTRIBUTES			objectAttributes;
	UNICODE_STRING				objectName;
	HANDLE						childKey;


	status = STATUS_SUCCESS;
	ULONG idxKey = 0;
	ULONG sizeReturned;
	while (1) {

		ZwEnumerateKey(ParentKey, idxKey, KeyBasicInformation, NULL, 0, &sizeReturned);
		keyInfo = (PKEY_BASIC_INFORMATION)ExAllocatePool2(POOL_FLAG_NON_PAGED, (SIZE_T)sizeReturned, 'DLKY');
		if (!keyInfo) {
			return STATUS_INSUFFICIENT_RESOURCES;
		}
		status = ZwEnumerateKey(
			ParentKey,
			idxKey,
			KeyBasicInformation,
			keyInfo,
			sizeReturned,
			&outLength
		);


		idxKey++;
		if (status == STATUS_NO_MORE_ENTRIES) {
			status = STATUS_SUCCESS;
			break;
		}
		if (status != STATUS_SUCCESS) {

			ExFreePool(keyInfo);
			return STATUS_SUCCESS;
		}

		//	Open subkey
		objectName.Length = objectName.MaximumLength = (USHORT)keyInfo->NameLength;
		objectName.Buffer = keyInfo->Name;
		InitializeObjectAttributes(&objectAttributes,
			&objectName,
			OBJ_KERNEL_HANDLE,
			ParentKey,
			NULL
		);
		status = ZwOpenKey(&childKey, KEY_ALL_ACCESS, &objectAttributes);
		if (!NT_SUCCESS(status)) {

			continue;
		}

		status = DeleteKeyFull(childKey);
		if (!NT_SUCCESS(status)) {

			ZwClose(childKey);
			continue;
		}

		status = ZwDeleteKey(childKey);

		ZwClose(childKey);
		idxKey--;

	}

	ExFreePool(keyInfo);
	ZwDeleteKey(ParentKey);
	return STATUS_SUCCESS;
}

NTSTATUS MakeProcessPP(ULONG PID, ULONG_PTR ProtectionOffset, int level) {
	NTSTATUS status;

	PEPROCESS peprocess;
	status = PsLookupProcessByProcessId((HANDLE)PID, &peprocess);

	if (!NT_SUCCESS(status))return status;

	PVOID VirtualAddress = (PVOID)((ULONG_PTR)peprocess + ProtectionOffset);

	union _PS_PROTECTION un;
	switch (level) {
	case 0:
		un.Level = 0x0;
		un.Flags.Audit = 0x0;
		un.Flags.Signer = PsProtectedSignerNone;
		un.Flags.Type = PsProtectedTypeNone;
		break;
	case 1:
		un.Level = 0x61;
		un.Flags.Audit = 0x0;
		un.Flags.Signer = PsProtectedSignerWinTcb;
		un.Flags.Type = PsProtectedTypeProtectedLight;
		break;
	case 2:
		un.Level = 0x72;
		un.Flags.Audit = 0x0;
		un.Flags.Signer = PsProtectedSignerMax;
		un.Flags.Type = PsProtectedTypeProtected;
		break;
	case 3:
		un.Level = 0x72;
		un.Flags.Audit = 0x0;
		un.Flags.Signer = PsProtectedSignerMax;
		un.Flags.Type = PsProtectedTypeMax;
		break;
	default:
		un.Level = 0x0;

		un.Flags.Audit = 0x0;
		un.Flags.Signer = PsProtectedSignerNone;
		un.Flags.Type = PsProtectedTypeNone;
		break;

	}
	// dangerous AS FUCK but it works
	RtlCopyMemory(VirtualAddress, &un, sizeof(union _PS_PROTECTION));
	return status;

}

NTSTATUS OpenProcessbyPid(ULONG PID, PHANDLE pHandle) {
	NTSTATUS status;
	PEPROCESS peprocess;
	status = PsLookupProcessByProcessId((HANDLE)PID, &peprocess);

	if (!NT_SUCCESS(status))
		return status;


	status = ObOpenObjectByPointer(peprocess, OBJ_KERNEL_HANDLE, NULL,
		SYNCHRONIZE, NULL, KernelMode, pHandle);

	return status;
}

NTSTATUS OpenThreadByTid(ULONG TID, PHANDLE pHandle) {
	NTSTATUS status;
	PETHREAD pethread;
	status = PsLookupThreadByThreadId((HANDLE)TID, &pethread);

	if (!NT_SUCCESS(status))
		return status;


	status = ObOpenObjectByPointer(pethread, OBJ_KERNEL_HANDLE, NULL,
		SYNCHRONIZE, NULL, KernelMode, pHandle);

	return status;
}

NTSTATUS TerminateProcessByPid(ULONG PID) {
	NTSTATUS status;
	HANDLE procHandle;


	status = OpenProcessbyPid(PID, &procHandle);

	if (NT_SUCCESS(status)) {
		status = ZwTerminateProcess(procHandle, STATUS_SUCCESS);
		ObCloseHandle(procHandle, KernelMode);
	}

	return status;
}

NTSTATUS GetFileSize(HANDLE fileHandle, PLARGE_INTEGER size) {
	NTSTATUS status;
	IO_STATUS_BLOCK ioBlock;
	FILE_STANDARD_INFORMATION fileInfo;
	status = ZwQueryInformationFile(fileHandle, &ioBlock, &fileInfo, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);
	if (!NT_SUCCESS(status)) {
		return status;
	}
	*size = fileInfo.EndOfFile;

	return status;
}

NTSTATUS IOCTLHandler(PDEVICE_OBJECT DeviceObject, PIRP Irp) {

	IoSetCancelRoutine(Irp, NULL);
	NTSTATUS Status = STATUS_SUCCESS;

	PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(Irp);

	if (irpStack->Parameters.DeviceIoControl.IoControlCode == IOCTL_SYMBLINK) {

		WCHAR* str = (WCHAR*)Irp->AssociatedIrp.SystemBuffer;
		UNICODE_STRING symbolicLinkName;
		RtlInitUnicodeString(&symbolicLinkName, str);
		Status = IoDeleteSymbolicLink(&symbolicLinkName);

	}
	else if (irpStack->Parameters.DeviceIoControl.IoControlCode == IOCTL_TERMINATOR) {
		Status = TerminateProcessByPid(*((ULONG*)Irp->AssociatedIrp.SystemBuffer));
	}
	else if (irpStack->Parameters.DeviceIoControl.IoControlCode == IOCTL_DELETEFILE) {
		struct DELETE_FILE_IOCTL* delInfo = (struct DELETE_FILE_IOCTL*)Irp->AssociatedIrp.SystemBuffer;

		UNICODE_STRING normPath;
		UNICODE_STRING dosPath;

		dosPath.Buffer = delInfo->dosPath;
		dosPath.Length = (USHORT)(wcslen(delInfo->dosPath) * sizeof(WCHAR));
		dosPath.MaximumLength = dosPath.Length + sizeof(WCHAR);

		normPath.Buffer = delInfo->normalPath;
		normPath.Length = (USHORT)(wcslen(delInfo->normalPath) * sizeof(WCHAR));
		normPath.MaximumLength = normPath.Length + sizeof(WCHAR);

		Status = forceDeleteFile(&dosPath, &normPath);

	}
	else if (irpStack->Parameters.DeviceIoControl.IoControlCode == IOCTL_BUGCHECK) {
		KeBugCheck(*((unsigned long*)Irp->AssociatedIrp.SystemBuffer));
	}
	else if (irpStack->Parameters.DeviceIoControl.IoControlCode == IOCTL_PPL) {
		struct PP_INFO* PppInfo = (struct PP_INFO*)Irp->AssociatedIrp.SystemBuffer;
		Status = MakeProcessPP(*PppInfo->PID, PppInfo->ProtectionOffset, *PppInfo->level);


	}
	else if (irpStack->Parameters.DeviceIoControl.IoControlCode == IOCTL_CREATEFILE) {
		WCHAR* FPath = (WCHAR*)Irp->AssociatedIrp.SystemBuffer;

		HANDLE fileHandle;
		OBJECT_ATTRIBUTES fileObjAttribs;
		UNICODE_STRING Path;
		IO_STATUS_BLOCK ioStatus;

		RtlInitUnicodeString(&Path, FPath);


		InitializeObjectAttributes(&fileObjAttribs, &Path,
			OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
			NULL, NULL);


		Status = IoCreateFileEx(&fileHandle, SYNCHRONIZE, &fileObjAttribs, &ioStatus, NULL, FILE_ATTRIBUTE_NORMAL,
			FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
			FILE_CREATE, FILE_NON_DIRECTORY_FILE, NULL, 0, CreateFileTypeNone, NULL, IO_IGNORE_SHARE_ACCESS_CHECK, NULL);

		if (NT_SUCCESS(Status)) {
			ZwClose(fileHandle);
		}


	}
	else if (irpStack->Parameters.DeviceIoControl.IoControlCode == IOCTL_CREATEDIRECTORY) {
		WCHAR* FPath = (WCHAR*)Irp->AssociatedIrp.SystemBuffer;

		HANDLE fileHandle;
		OBJECT_ATTRIBUTES fileObjAttribs;
		UNICODE_STRING Path;
		IO_STATUS_BLOCK ioStatus;

		RtlInitUnicodeString(&Path, FPath);

		InitializeObjectAttributes(&fileObjAttribs, &Path,
			OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
			NULL, NULL);

		Status = IoCreateFileEx(&fileHandle, SYNCHRONIZE, &fileObjAttribs, &ioStatus, NULL, FILE_ATTRIBUTE_NORMAL,
			FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
			FILE_CREATE, FILE_DIRECTORY_FILE, NULL, 0, CreateFileTypeNone, NULL, IO_IGNORE_SHARE_ACCESS_CHECK, NULL);

		if (NT_SUCCESS(Status)) {
			ZwClose(fileHandle);
		}

	}
	else if (irpStack->Parameters.DeviceIoControl.IoControlCode == IOCTL_DELETEKEY) {
		UNICODE_STRING KeyToDelete;
		WCHAR* buffer = (WCHAR*)Irp->AssociatedIrp.SystemBuffer;
		RtlInitUnicodeString(&KeyToDelete, buffer);
		OBJECT_ATTRIBUTES KeyObjAttribs;
		InitializeObjectAttributes(&KeyObjAttribs, &KeyToDelete, OBJ_KERNEL_HANDLE, NULL, NULL);
		HANDLE KeyHandle;
		Status = ZwOpenKey(&KeyHandle, KEY_ALL_ACCESS, &KeyObjAttribs);
		if (NT_SUCCESS(Status)) {
			DeleteKeyFull(KeyHandle);
			ZwClose(KeyHandle);
		}



	}
	else if (irpStack->Parameters.DeviceIoControl.IoControlCode == IOCTL_CREATEKEY) {
		UNICODE_STRING KeyToCreate;
		WCHAR* buffer = (WCHAR*)Irp->AssociatedIrp.SystemBuffer;
		RtlInitUnicodeString(&KeyToCreate, buffer);
		OBJECT_ATTRIBUTES KeyObjAttribs;
		InitializeObjectAttributes(&KeyObjAttribs, &KeyToCreate, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
		HANDLE KeyHandle;
		ULONG option;
		Status = ZwCreateKey(&KeyHandle, KEY_ALL_ACCESS, &KeyObjAttribs, NULL, NULL, REG_OPTION_NON_VOLATILE, &option);
		DbgPrint("status: %lu\n", Status);
		if (NT_SUCCESS(Status)) {
			Status = (option == REG_CREATED_NEW_KEY) ? STATUS_SUCCESS : STATUS_OBJECT_NAME_EXISTS;
			ZwClose(KeyHandle);
		}



	}
	else if (irpStack->Parameters.DeviceIoControl.IoControlCode == IOCTL_UNLOADDRIVER) {
		WCHAR* Buffer = (WCHAR*)Irp->AssociatedIrp.SystemBuffer;
		UNICODE_STRING DriverPath;
		RtlInitUnicodeString(&DriverPath, Buffer);
		Status = ZwUnloadDriver(&DriverPath);
	}
	else if (irpStack->Parameters.DeviceIoControl.IoControlCode == IOCTL_CRITICALTHREAD) {
		struct CRITICAL_THREAD_INFO* threadInfo = (struct CRITICAL_THREAD_INFO*)Irp->AssociatedIrp.SystemBuffer;
		HANDLE threadHandle;
		Status = OpenThreadByTid(threadInfo->TID, &threadHandle);
		if (NT_SUCCESS(Status)) {
			Status = ZwSetInformationThread(threadHandle, ThreadBreakOnTermination, &threadInfo->critical, sizeof(int));
			ZwClose(threadHandle);
		}


	}
	else if (irpStack->Parameters.DeviceIoControl.IoControlCode == IOCTL_COPYFILE) {


		struct COPY_FILE_IOCTL* Buffer = (struct COPY_FILE_IOCTL*)Irp->AssociatedIrp.SystemBuffer;
		UNICODE_STRING sourcePath;
		UNICODE_STRING destPath;
		OBJECT_ATTRIBUTES destFileObjAttribs;
		OBJECT_ATTRIBUTES sourceFileObjAttribs;
		HANDLE srcHandle;
		HANDLE dstHandle;
		IO_STATUS_BLOCK srcBlock;
		IO_STATUS_BLOCK dstBlock;
		RtlInitUnicodeString(&sourcePath, Buffer->srcFile);
		RtlInitUnicodeString(&destPath, Buffer->dstFile);


		InitializeObjectAttributes(&sourceFileObjAttribs, &sourcePath,
			OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
			NULL, NULL);
		InitializeObjectAttributes(&destFileObjAttribs, &destPath,
			OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
			NULL, NULL);





		Status = IoCreateFileEx(&srcHandle,
			FILE_READ_DATA | SYNCHRONIZE,
			&sourceFileObjAttribs, &srcBlock,
			NULL, FILE_ATTRIBUTE_NORMAL,
			FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
			FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
			NULL, 0,
			CreateFileTypeNone, NULL,
			IO_IGNORE_SHARE_ACCESS_CHECK,
			NULL);
		if (!NT_SUCCESS(Status)) {
			IoCompleteRequest(Irp, IO_NO_INCREMENT);
			return Status;
		}
		Status = IoCreateFileEx(&dstHandle,
			FILE_WRITE_DATA | SYNCHRONIZE,
			&destFileObjAttribs, &dstBlock,
			NULL, FILE_ATTRIBUTE_NORMAL,
			0,
			FILE_SUPERSEDE, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
			NULL, 0,
			CreateFileTypeNone, NULL,
			IO_IGNORE_SHARE_ACCESS_CHECK,
			NULL);

		if (!NT_SUCCESS(Status)) {
			ZwClose(srcHandle);
			IoCompleteRequest(Irp, IO_NO_INCREMENT);
			return Status;
		}
		LARGE_INTEGER fileSize;
		Status = GetFileSize(srcHandle, &fileSize);

		if (!NT_SUCCESS(Status)) {
			ZwClose(srcHandle);
			ZwClose(dstHandle);
			IoCompleteRequest(Irp, IO_NO_INCREMENT);
			return Status;
		}
		
		PVOID readDataBuffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, fileSize.QuadPart, 'YPOC');
		if (readDataBuffer == NULL) {
			ZwClose(srcHandle);
			ZwClose(dstHandle);
			IoCompleteRequest(Irp, IO_NO_INCREMENT);
			return Status;
		}

		IO_STATUS_BLOCK readInformation;
		Status = ZwReadFile(srcHandle, NULL, NULL, NULL, &readInformation, readDataBuffer, (ULONG)fileSize.QuadPart, NULL, NULL);
		if (!NT_SUCCESS(Status) && Status != STATUS_END_OF_FILE) {
			ExFreePool(readDataBuffer);
			ZwClose(srcHandle);
			ZwClose(dstHandle);
			IoCompleteRequest(Irp, IO_NO_INCREMENT);
			return Status;
		}
		IO_STATUS_BLOCK writeInformation;
		Status = ZwWriteFile(dstHandle, NULL, NULL, NULL, &writeInformation, readDataBuffer, (ULONG)fileSize.QuadPart, NULL, NULL);
		DbgPrint("Status: %X\n", Status);
		ZwClose(srcHandle);
		ZwClose(dstHandle);
		ExFreePool(readDataBuffer);
	}


	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Status;

}




NTSTATUS Create(PDEVICE_OBJECT pDeviceObject, PIRP irp) {

	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;
	IoCompleteRequest(irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS Close(PDEVICE_OBJECT pDeviceObject, PIRP irp) {
	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}



void DriverUnload(IN PDRIVER_OBJECT pDriverObj)
{

	IoDeleteSymbolicLink(&symbolicLink);
	IoDeleteDevice(pDriverObj->DeviceObject);
	pDriverObj->DriverUnload = NULL;


}



#ifdef KERNELTOYS_SECURE_DEVICE
#pragma comment(lib,"Wdmsec.lib")
#include <wdmsec.h>
#endif
NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverObj, IN PUNICODE_STRING RegistryPath)
{

	
	DbgPrint("nya the driver got started, KEWWNEL POWAHHH!!!! >w<\n");

	RtlInitUnicodeString(&device, L"\\Device\\kerneltoys");
	RtlInitUnicodeString(&symbolicLink, L"\\DosDevices\\kerneltoys");
    #ifdef KERNELTOYS_SECURE_DEVICE
	UNICODE_STRING deviceSecurityDescriptor = SDDL_DEVOBJ_SYS_ALL_ADM_ALL;
	WdmlibIoCreateDeviceSecure(pDriverObj, 0, &device, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &deviceSecurityDescriptor, NULL, &pDevObj);
	#else
	IoCreateDevice(pDriverObj, 0, &device, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pDevObj);
	#endif
	IoCreateSymbolicLink(&symbolicLink, &device);

	pDriverObj->MajorFunction[IRP_MJ_CREATE] = Create;
	pDriverObj->MajorFunction[IRP_MJ_CLOSE] = Close;
	pDriverObj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IOCTLHandler;


	pDevObj->Flags |= DO_DIRECT_IO;
	pDevObj->Flags &= ~DO_DEVICE_INITIALIZING;

	pDriverObj->DriverUnload = DriverUnload;

	return STATUS_SUCCESS;

}
#include "Main.h"

NTSTATUS GetFileSize(HANDLE fileHandle, PLARGE_INTEGER pFileSizeBytes)
{
	NTSTATUS status = STATUS_SUCCESS;
	FILE_STANDARD_INFORMATION fileStandardInfo;
	IO_STATUS_BLOCK ioBlock = { 0 };

	status = ZwQueryInformationFile(fileHandle, &ioBlock, &fileStandardInfo, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);

	if (!NT_SUCCESS(status))
	{
		DBGERRNTSTATUS("ZwQueryInformationFile", status);
		return status;
	}

	*pFileSizeBytes = fileStandardInfo.EndOfFile;

	return status;
}


NTSTATUS DeleteFile_IoComplete(PDEVICE_OBJECT pDeviceObject, PIRP pIrp, PVOID ctx)
{

	pIrp->UserIosb->Status = pIrp->IoStatus.Status;
	pIrp->UserIosb->Information = pIrp->IoStatus.Information;

	KeSetEvent(pIrp->UserEvent, IO_NO_INCREMENT, FALSE);

	return STATUS_MORE_PROCESSING_REQUIRED;
}

// thx gabrik for this code
NTSTATUS DeleteFile_SendIrp(PFILE_OBJECT pFileObject)
{
	NTSTATUS status = STATUS_SUCCESS;;
	KEVENT irpCompletionEvent = { 0 };

	PDEVICE_OBJECT pBaseFsDeviceObject = IoGetBaseFileSystemDeviceObject(pFileObject);

	PIRP pIrp = IoAllocateIrp(pBaseFsDeviceObject->StackSize, FALSE);

	// Set the complete routine that will free the IRP and signal the event
	KeInitializeEvent(&irpCompletionEvent, SynchronizationEvent, FALSE);

	IoSetCompletionRoutine(
		pIrp,
		DeleteFile_IoComplete,
		&irpCompletionEvent,
		TRUE,
		TRUE,
		TRUE);


	FILE_DISPOSITION_INFORMATION_EX dispositionInformation = { 0 };

	dispositionInformation.Flags =
		FILE_DISPOSITION_DELETE |
		FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE |
		FILE_DISPOSITION_POSIX_SEMANTICS;


	IO_STATUS_BLOCK irpIoStatusBlock = { 0 };
	pIrp->AssociatedIrp.SystemBuffer = &dispositionInformation;
	pIrp->UserEvent = &irpCompletionEvent;

	pIrp->UserIosb = &irpIoStatusBlock;
	pIrp->Tail.Overlay.OriginalFileObject = pFileObject;
	pIrp->Tail.Overlay.Thread = KeGetCurrentThread();
	pIrp->Flags = IRP_WRITE_OPERATION;
	pIrp->RequestorMode = KernelMode;

	PIO_STACK_LOCATION pIoNextStackLocation = IoGetNextIrpStackLocation(pIrp);
	pIoNextStackLocation->MajorFunction = IRP_MJ_SET_INFORMATION;
	pIoNextStackLocation->DeviceObject = pBaseFsDeviceObject;
	pIoNextStackLocation->FileObject = pFileObject;
	pIoNextStackLocation->Flags |= SL_FORCE_DIRECT_WRITE;
	pIoNextStackLocation->Parameters.SetFile.Length = sizeof(FILE_DISPOSITION_INFORMATION_EX);
	pIoNextStackLocation->Parameters.SetFile.FileInformationClass = FileDispositionInformationEx;
	pIoNextStackLocation->Parameters.SetFile.FileObject = pFileObject;

	DBGINFO("Sending delete file irp to base filesystem device object %p", pBaseFsDeviceObject);

	status = IoCallDriver(pBaseFsDeviceObject, pIrp);

	if (status == STATUS_PENDING)
	{
		KeWaitForSingleObject(&irpCompletionEvent, Executive, KernelMode, TRUE, NULL);
	}

	status = pIrp->IoStatus.Status;

	IoFreeIrp(pIrp);

	return status;
}


NTSTATUS ForceDeleteFile(PUNICODE_STRING pFullFilePath)
{
	NTSTATUS status = STATUS_SUCCESS;
	OBJECT_ATTRIBUTES fileObjAttribs;
	PFILE_OBJECT pFileObject = NULL;
	IO_STATUS_BLOCK ioBlock = { 0 };
	HANDLE fileHandle = NULL;

	InitializeObjectAttributes(&fileObjAttribs, pFullFilePath,
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


	if (!NT_SUCCESS(status))
	{
		DBGERRNTSTATUS("IoCreateFileEx", status);
		return status;
	}

	status = ObReferenceObjectByHandleWithTag(fileHandle,
		SYNCHRONIZE, *IoFileObjectType,
		KernelMode, 'eliF',
		&pFileObject, NULL);


	if (!NT_SUCCESS(status))
	{
		DBGERRNTSTATUS("ObReferenceObjectByHandleWithTag", status);

		ObCloseHandle(fileHandle, KernelMode);
		return status;
	}

	DBGOK("Got FILE_OBJECT %p of file to delete", pFileObject);


	pFileObject->SectionObjectPointer->ImageSectionObject = 0;
	pFileObject->SharedDelete = TRUE;
	pFileObject->DeleteAccess = TRUE;
	pFileObject->WriteAccess = TRUE;
	pFileObject->ReadAccess = TRUE;
	pFileObject->DeletePending = FALSE;
	pFileObject->Busy = FALSE;


	MmFlushImageSection(pFileObject->SectionObjectPointer, MmFlushForDelete);

	status = DeleteFile_SendIrp(pFileObject);

	if (!NT_SUCCESS(status))
	{
		DBGERRNTSTATUS("DeleteFile_SendIrp", status);
	}

	ObfDereferenceObject(pFileObject);
	ObCloseHandle(fileHandle, KernelMode);

	return status;
}



NTSTATUS CreateFileIoctlHandler(PIRP pIrp)
{
	NTSTATUS status = STATUS_SUCCESS;
	HANDLE fileHandle;
	OBJECT_ATTRIBUTES fileObjectAttributes;
	UNICODE_STRING unicodeFilePath;
	IO_STATUS_BLOCK ioStatusBlock;
	WCHAR* filePath = (WCHAR*)pIrp->AssociatedIrp.SystemBuffer;

	RtlInitUnicodeString(&unicodeFilePath, filePath);

	InitializeObjectAttributes(
		&fileObjectAttributes,
		&unicodeFilePath,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,
		NULL);

	status = IoCreateFileEx(
		&fileHandle,
		SYNCHRONIZE,
		&fileObjectAttributes,
		&ioStatusBlock,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		FILE_CREATE,
		FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0,
		CreateFileTypeNone,
		NULL,
		IO_IGNORE_SHARE_ACCESS_CHECK,
		NULL);


	if (!NT_SUCCESS(status))
	{
		DBGERRNTSTATUS("IoCreateFileEx", status);
	}
	else
	{
		ZwClose(fileHandle);
	}

	return status;
}

NTSTATUS CreateDirectoryIoctlHandler(PIRP pIrp)
{
	NTSTATUS status = STATUS_SUCCESS;
	HANDLE fileHandle;
	OBJECT_ATTRIBUTES fileObjectAttributes;
	UNICODE_STRING unicodeFilePath;
	IO_STATUS_BLOCK ioStatusBlock;
	WCHAR* filePath = (WCHAR*)pIrp->AssociatedIrp.SystemBuffer;

	RtlInitUnicodeString(&unicodeFilePath, filePath);

	InitializeObjectAttributes(
		&fileObjectAttributes,
		&unicodeFilePath,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,
		NULL);

	status = IoCreateFileEx(
		&fileHandle,
		SYNCHRONIZE,
		&fileObjectAttributes,
		&ioStatusBlock,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		FILE_CREATE,
		FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0,
		CreateFileTypeNone,
		NULL,
		IO_IGNORE_SHARE_ACCESS_CHECK,
		NULL);

	if (NT_SUCCESS(status))
	{
		DBGERRNTSTATUS("IoCreateFileEx", status);
		ZwClose(fileHandle);
	}

	return status;
}

NTSTATUS CopyFileIoctlHandler(PIRP pIrp)
{
	NTSTATUS status = STATUS_SUCCESS;
	UNICODE_STRING sourcePath;
	UNICODE_STRING destPath;
	OBJECT_ATTRIBUTES destFileObjAttribs;
	OBJECT_ATTRIBUTES sourceFileObjAttribs;
	HANDLE srcHandle;
	HANDLE dstHandle;
	LARGE_INTEGER sourceFileSize = { 0 };
	PVOID sourceFileReadDataBuffer = NULL;
	IO_STATUS_BLOCK srcBlock;
	IO_STATUS_BLOCK dstBlock;
	IO_STATUS_BLOCK readInformation;
	IO_STATUS_BLOCK writeInformation;

	PCOPY_FILE_PARAMETER pCopyFileParameter = (PCOPY_FILE_PARAMETER)pIrp->AssociatedIrp.SystemBuffer;

	RtlInitUnicodeString(&sourcePath, pCopyFileParameter->sourceFilePath);
	RtlInitUnicodeString(&destPath, pCopyFileParameter->destinationFilePath);


	InitializeObjectAttributes(
		&sourceFileObjAttribs,
		&sourcePath,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,
		NULL);

	InitializeObjectAttributes(
		&destFileObjAttribs,
		&destPath,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,
		NULL);

	status = IoCreateFileEx(
		&srcHandle,
		FILE_READ_DATA | SYNCHRONIZE,
		&sourceFileObjAttribs,
		&srcBlock,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		FILE_OPEN,
		FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0,
		CreateFileTypeNone,
		NULL,
		IO_IGNORE_SHARE_ACCESS_CHECK,
		NULL);


	if (!NT_SUCCESS(status))
	{
		DBGERRNTSTATUS("IoCreateFileEx", status);
		return status;
	}


	status = IoCreateFileEx(
		&dstHandle,
		FILE_WRITE_DATA | SYNCHRONIZE,
		&destFileObjAttribs,
		&dstBlock,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		0,
		FILE_SUPERSEDE,
		FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0,
		CreateFileTypeNone,
		NULL,
		IO_IGNORE_SHARE_ACCESS_CHECK,
		NULL);


	if (!NT_SUCCESS(status))
	{
		DBGERRNTSTATUS("IoCreateFileEx", status);

		ZwClose(srcHandle);

		return status;
	}


	status = GetFileSize(srcHandle, &sourceFileSize);


	if (!NT_SUCCESS(status))
	{

		DBGERRNTSTATUS("GetFileSize", status);

		ZwClose(srcHandle);
		ZwClose(dstHandle);

		return status;
	}


	sourceFileReadDataBuffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, sourceFileSize.QuadPart, 'YPOC');


	if (sourceFileReadDataBuffer == NULL)
	{

		DBGERR("Failed to allocate pool buffer");

		ZwClose(srcHandle);
		ZwClose(dstHandle);

		return status;
	}


	status = ZwReadFile(srcHandle, NULL, NULL, NULL, &readInformation, sourceFileReadDataBuffer, (ULONG)sourceFileSize.QuadPart, NULL, NULL);


	if (!NT_SUCCESS(status) && status != STATUS_END_OF_FILE)
	{

		DBGERRNTSTATUS("ZwReadFile", status);

		ExFreePool(sourceFileReadDataBuffer);

		ZwClose(srcHandle);
		ZwClose(dstHandle);

		return status;
	}


	status = ZwWriteFile(dstHandle, NULL, NULL, NULL, &writeInformation, sourceFileReadDataBuffer, (ULONG)sourceFileSize.QuadPart, NULL, NULL);

	if (!NT_SUCCESS(status))
	{
		DBGERRNTSTATUS("ZwWriteFile", status);
	}

	ZwClose(srcHandle);
	ZwClose(dstHandle);

	ExFreePool(sourceFileReadDataBuffer);

	return status;
}


NTSTATUS DeleteFileIoctlHandler(PIRP pIrp)
{
	UNICODE_STRING filePath = { 0 };

	LPWSTR fileToDelete = (LPWSTR)pIrp->AssociatedIrp.SystemBuffer;

	RtlInitUnicodeString(&filePath, fileToDelete);

	return ForceDeleteFile(&filePath);
}
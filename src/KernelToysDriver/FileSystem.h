#pragma once

typedef struct _COPY_FILE_PARAMETER
{
	LPWSTR sourceFilePath;
	LPWSTR destinationFilePath;
} COPY_FILE_PARAMETER, * PCOPY_FILE_PARAMETER;


NTSTATUS CreateFileIoctlHandler(PIRP pIrp);

NTSTATUS CreateDirectoryIoctlHandler(PIRP pIrp);

NTSTATUS CopyFileIoctlHandler(PIRP pIrp);

NTSTATUS DeleteFileIoctlHandler(PIRP pIrp);
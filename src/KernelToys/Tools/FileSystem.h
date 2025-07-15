#pragma once

typedef struct _COPY_FILE_PARAMETER
{
	LPWSTR sourceFilePath;
	LPWSTR destinationFilePath;
} COPY_FILE_PARAMETER, *PCOPY_FILE_PARAMETER;

BOOL CreateFileToyHandler(LPWSTR arguments[], UINT argumentCount);

BOOL CreateDirectoryToyHandler(LPWSTR arguments[], UINT argumentCount);

BOOL CopyFileToyHandler(LPWSTR arguments[], UINT argumentCount);

BOOL DeleteFileToyHandler(LPWSTR arguments[], UINT argumentCount);

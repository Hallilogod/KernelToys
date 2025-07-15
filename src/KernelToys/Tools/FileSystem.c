#include "../Main.h"

BOOL CreateFileToyHandler(LPWSTR arguments[], UINT argumentCount)
{
    INFO("Sending device control to create file '%ls'...", arguments[1]);

    return DeviceControlDriver(IOCTL_CREATE_FILE, arguments[1], (wcslen(arguments[1]) + 1) * sizeof(WCHAR));
}

BOOL CreateDirectoryToyHandler(LPWSTR arguments[], UINT argumentCount)
{
    INFO("Sending device control to create directory '%ls'...", arguments[1]);

    return DeviceControlDriver(IOCTL_CREATE_DIRECTORY, arguments[1], (wcslen(arguments[1]) + 1) * sizeof(WCHAR));
}

BOOL CopyFileToyHandler(LPWSTR arguments[], UINT argumentCount)
{
    COPY_FILE_PARAMETER deviceControlParameters = { arguments[1], arguments[2] };

    INFO("Sending device control to copy file...");
 
    return DeviceControlDriver(IOCTL_COPY_FILE, &deviceControlParameters, sizeof(deviceControlParameters));
}

BOOL DeleteFileToyHandler(LPWSTR arguments[], UINT argumentCount)
{
    INFO("Sending device control to delete file '%ls'...", arguments[1]);

    return DeviceControlDriver(IOCTL_DELETE_FILE, arguments[1], (wcslen(arguments[1]) + 1) * sizeof(WCHAR));
}

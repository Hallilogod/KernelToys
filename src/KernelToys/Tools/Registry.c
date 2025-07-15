#include "../Main.h"

BOOL CreateKeyToyHandler(LPWSTR arguments[], UINT argumentCount)
{
    INFO("Sending device control to create key '%ls'...", arguments[1]);

    return DeviceControlDriver(IOCTL_CREATE_KEY, arguments[1], (wcslen(arguments[1]) + 1) * sizeof(WCHAR));
}

BOOL DeleteKeyToyHandler(LPWSTR arguments[], UINT argumentCount)
{
    INFO("Sending device control to delete key '%ls'...", arguments[1]);

    return DeviceControlDriver(IOCTL_DELETE_KEY, arguments[1], (wcslen(arguments[1]) + 1) * sizeof(WCHAR));
}

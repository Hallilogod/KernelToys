#include "../Main.h"

BOOL DeleteSymbLinkToyHandler(LPWSTR arguments[], UINT argumentCount)
{
    INFO("Sending device control to delete symbolic link '%ls'...", arguments[1]);

    return DeviceControlDriver(IOCTL_DELETE_LINK, arguments[1], (wcslen(arguments[1]) + 1) * sizeof(WCHAR));
}

BOOL BugCheckToyHandler(LPWSTR arguments[], UINT argumentCount)
{
    ULONG bugCheckCode = wcstoul(arguments[1], 0, 16);

    if(bugCheckCode == 0)
    {
        ERR("Invalid bugcheck code '%ls'", arguments[1]);

        return FALSE;
    }

    INFO("Sending device control to bugcheck the system...");

    return DeviceControlDriver(IOCTL_BUGCHECK, &bugCheckCode, sizeof(bugCheckCode));
}

BOOL UnloadDriverToyHandler(LPWSTR arguments[], UINT argumentCount)
{
    INFO("Sending device control to unload driver '%ls'...", arguments[1]);

    return DeviceControlDriver(IOCTL_UNLOAD_DRIVER, arguments[1], (wcslen(arguments[1]) + 1) * sizeof(WCHAR));
}

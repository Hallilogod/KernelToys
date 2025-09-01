#include "../Main.h"

BOOL DeleteSymbLinkToyHandler(LPWSTR arguments[], UINT argumentCount)
{
    INFO("Sending device control to delete symbolic link '%ls'...", arguments[1]);

    return DeviceControlDriver(IOCTL_DELETE_LINK, arguments[1], (wcslen(arguments[1]) + 1) * sizeof(WCHAR), NULL, 0);
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

    return DeviceControlDriver(IOCTL_BUGCHECK, &bugCheckCode, sizeof(bugCheckCode), NULL, 0);
}

BOOL UnloadDriverToyHandler(LPWSTR arguments[], UINT argumentCount)
{
    INFO("Sending device control to unload driver '%ls'...", arguments[1]);

    return DeviceControlDriver(IOCTL_UNLOAD_DRIVER, arguments[1], (wcslen(arguments[1]) + 1) * sizeof(WCHAR), NULL, 0);
}

BOOL PortIoToyHandler(LPWSTR arguments[], UINT argumentCount)
{
    PORT_IO_PARAMETER portIoIoctlParameters = { 0 };
    union
    {
        UINT32 InputDword;
		UINT16 InputWord;
		UINT8  InputByte;
    } portInputData = { 0 };
    ULONG dataSize = 0;
    ULONG portAddress = 0;
    ULONG portOutputData = 0;


    if(wcsicmp(arguments[2], L"byte") == 0)
    {
        dataSize = sizeof(UINT8);
    }
    else if(wcsicmp(arguments[2], L"word") == 0)
    {
        dataSize = sizeof(UINT16);
    }
    else if(wcsicmp(arguments[2], L"dword") == 0)
    {
        dataSize = sizeof(UINT32);
    }
    else
    {
        ERR("Invalid port data size '%ls'", arguments[2]);

        return FALSE;
    }

    portIoIoctlParameters.Size = dataSize;

    WCHAR* endPtr = NULL;

    portAddress = wcstoul(arguments[3], &endPtr, 16);

    if((portAddress == 0 && endPtr == arguments[3]) || portAddress == ULONG_MAX)
    {
        ERR("Invalid I/O port address '%ls'", arguments[3]);

        return FALSE;
    }

    portIoIoctlParameters.PortAddress = (UINT16)portAddress;

    if(wcsicmp(arguments[1], L"in") == 0)
    {
        portIoIoctlParameters.In = TRUE;

        portIoIoctlParameters.PortData.pInputDword = &portInputData.InputDword;

        INFO("Sending device control to read from I/O port 0x%04X...", (UINT16)portAddress);

        if(!DeviceControlDriver(IOCTL_PORT_IO, &portIoIoctlParameters, sizeof(portIoIoctlParameters), NULL, 0))
        {
            return FALSE;
        }

        switch(dataSize)
        {
            case sizeof(UINT8):
                INFO("READ [Port 0x%04X, Byte] = 0x%02X", portIoIoctlParameters.PortAddress, portInputData.InputByte);
            break;

            case sizeof(UINT16):
                INFO("READ [Port 0x%04X, Word] = 0x%04X", portIoIoctlParameters.PortAddress, portInputData.InputWord);
            break;

            case sizeof(UINT32):
                INFO("READ [Port 0x%04X, Dword] = 0x%08X", portIoIoctlParameters.PortAddress, portInputData.InputDword);
            break;
        }

        return TRUE;
    }
    else if(wcsicmp(arguments[1], L"out") == 0)
    {
        if(argumentCount < 5)
        {
            ERR("Missing argument for port data");

            return FALSE;
        }

        portIoIoctlParameters.In = FALSE;
        
        portOutputData = wcstoul(arguments[4], &endPtr, 16);

        if((portOutputData == 0 && endPtr == arguments[4]) || portOutputData == ULONG_MAX)
        {
            ERR("Invalid port data '%ls'", arguments[4]);

            return FALSE;
        }

        switch(dataSize)
        {
            case sizeof(UINT8):
                portIoIoctlParameters.PortData.OutputByte = (UINT8)portOutputData;
            break;

            case sizeof(UINT16):
                portIoIoctlParameters.PortData.OutputWord = (UINT16)portOutputData;
            break;

            case sizeof(UINT32):
                portIoIoctlParameters.PortData.OutputDword = (UINT32)portOutputData;
            break;
        }

        INFO("Sending device control to write 0x%lX to I/O port 0x%04X...", portOutputData, (UINT16)portAddress);

        if(!DeviceControlDriver(IOCTL_PORT_IO, &portIoIoctlParameters, sizeof(portIoIoctlParameters), NULL, 0))
        {
            return FALSE;
        }
        
        return TRUE;
    }
    else
    {
        ERR("Invalid port operation '%ls'", arguments[1]);

        return FALSE;
    }

}
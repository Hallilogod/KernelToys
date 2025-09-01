#pragma once

typedef struct _PORT_IO_PARAMETER
{
	ULONG Size;

	union
	{
		/*Input is what's read FROM the I/O port, Output what is written to it (just like with the in/out instructions)*/
		PUINT32 pInputDword;
		PUINT16 pInputWord;
		PUINT8  pInputByte;

		UINT32 OutputDword;
		UINT16 OutputWord;
		UINT8  OutputByte;
	} PortData;

	UINT16 PortAddress;
	BOOLEAN In;
} PORT_IO_PARAMETER, *PPORT_IO_PARAMETER;

BOOL DeleteSymbLinkToyHandler(LPWSTR arguments[], UINT argumentCount);

BOOL BugCheckToyHandler(LPWSTR arguments[], UINT argumentCount);

BOOL UnloadDriverToyHandler(LPWSTR arguments[], UINT argumentCount);

BOOL PortIoToyHandler(LPWSTR arguments[], UINT argumentCount);
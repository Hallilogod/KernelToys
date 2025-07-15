#pragma once

#pragma warning (disable : 4100)

#include <ntifs.h>

#define PRINTF_FUNCTION DbgPrint

#include "../Shared.h"

#if KERNELTOYS_SECURE_DEVICE
	#pragma comment(lib, "Wdmsec.lib")
	#include <wdmsec.h>
#endif


#define DBGERRNTSTATUS(functionName, ntStatus)	DBGERR("%s failed with NTSTATUS %08lX", functionName, ntStatus)


#include "DeviceControlHandler.h"
#include "Processes.h"
#include "FileSystem.h"
#include "Registry.h"
#include "Power.h"
#include "System.h"
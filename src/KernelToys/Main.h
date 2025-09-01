#pragma once
#define _CRT_NON_CONFORMING_WCSTOK

#include <stdio.h>
#include <Windows.h>
#include "NTBuilds.h"

/*
Whether you want to enable ANSI color codes in the console
*/
#define SUPPORT_COLORS 1

#define PRINTF_FUNCTION printf

#include "../Shared.h"



typedef BOOL (*TOOL_HANDLER_ROUTINE)(LPWSTR arguments[], UINT argumentCount);

typedef struct _TOOL
{
    LPWSTR CommandName;
    LPWSTR CommandArguments;
    UINT MinCommandArguments;
    LPWSTR CommandDescription;
    BOOL IsKernelTool;
    BOOL RequiresElevation;
    TOOL_HANDLER_ROUTINE ToolHandlerRoutine;
} TOOL, *PTOOL;

#define MAKE_KERNEL_TOOL(commandName, commandArguments, minCommandArguments, commandDescription, toolHandlerRoutine) \
    {commandName, commandArguments, minCommandArguments, commandDescription, TRUE, KERNELTOYS_SECURE_DEVICE, toolHandlerRoutine} 
    
#define MAKE_USER_TOOL(commandName, commandArguments, minCommandArguments, commandDescription, requiresElevation, toolHandlerRoutine) \
    {commandName, commandArguments, minCommandArguments, commandDescription, FALSE, requiresElevation, toolHandlerRoutine} 


BOOL AdjustPrivilegeForToken(HANDLE tokenHandle, LPWSTR privilegeName);

BOOL IsOwnProcessTokenElevated();

#include "DriverControl.h"
#include "DsePatch.h"
#include "Tools/Processes.h"
#include "Tools/System.h"
#include "Tools/Registry.h"
#include "Tools/Power.h"
#include "Tools/FileSystem.h"

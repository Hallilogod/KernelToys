#include "Main.h"


int providerBlacklist[] = {1, 7, 12, 16, 17};


// Checks if the given file exists
BOOL FileExists(LPSTR filePath)
{
	DWORD dwAttrib = GetFileAttributesA(filePath);

	return (dwAttrib != INVALID_FILE_ATTRIBUTES &&
			!(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}


BOOL KduWriteDseFlags(UINT provider, ULONG newFlags, PULONG pOldFlags)
{
	LONG oldFlags = 0;

	// Run the external program and open a pipe to capture its output
	char kduCmdLine[100];

	sprintf_s(kduCmdLine, sizeof(kduCmdLine), "kdu.exe -prv %u -dse %lu", provider, newFlags);

	FILE *kduPipe = _popen(kduCmdLine, "r");

	if (!kduPipe)
	{
        ERR("Failed to open a pipe to kdu.exe");
        return FALSE;
    }

    char kduOutputBuffer[256];
    while (fgets(kduOutputBuffer, sizeof(kduOutputBuffer), kduPipe) != NULL)
    {

        INFO_NN("kdu output: %s", kduOutputBuffer);

        LPSTR valuePattern = "value:";


        if( strstr(kduOutputBuffer, "Unable to load vulnerable driver") ||
            strstr(kduOutputBuffer, "Cannot query DSE state") ||
            strstr(kduOutputBuffer, "selected provider does not support changing DSE"))
        {
            pclose(kduPipe);
            return FALSE;
        }

        LPSTR valueStart = strstr(kduOutputBuffer, valuePattern);

        if (valueStart)
        {
            valueStart += strlen(valuePattern);
            oldFlags = strtol(valueStart, NULL, 16);

            break;
        }
    }

    _pclose(kduPipe);

    *pOldFlags = (ULONG)oldFlags;
    
	return TRUE;
}

/*
Patches the system's DSE flags.

@param newDseFlags New DSE flags to write
@param pOldDseFlags Pointer to a DWORD to recieve the old DSE flags

@return TRUE on success, FALSE otherwise
*/
BOOL PatchDse(DWORD newDseFlags, _Out_opt_ PDWORD pOldDseFlags)
{
    BOOL dseOverwritten = FALSE;
    ULONG oldDseFlags = 0;

    if (!(FileExists("kdu.exe") && FileExists("drv64.dll") && FileExists("KernelToysDriver.sys")))
    {
        ERR("kdu.exe, drv64.dll or KernelToysDriver.sys is missing");
        return FALSE;
    }

    INFO("Writing 0x%08lX to the DSE flags in kernel memory...\n", newDseFlags);

    for(UINT i = DSE_PROVIDER_MIN; i <= ARRAYSIZE(providerBlacklist); i++)
    {
        if(KduWriteDseFlags(i, newDseFlags, &oldDseFlags))
        {
            dseOverwritten = TRUE;
            break;
        }

        WARN("Failure, trying different provider (%u / %u)", i, DSE_PROVIDER_MAX);

    }

    if(!dseOverwritten)
    {
        ERR("Failed to write to system DSE flags");
        return FALSE;
    }

    if(pOldDseFlags != NULL)
    {
        *pOldDseFlags = oldDseFlags;
    }

    return TRUE;
}

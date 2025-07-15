#include "Main.h"


NTSTATUS DeleteLinkIoctlHandler(PIRP pIrp)
{
	UNICODE_STRING symbolicLinkName = { 0 };
	LPWSTR symbolicLinkToDelete = (LPWSTR)pIrp->AssociatedIrp.SystemBuffer;

	RtlInitUnicodeString(&symbolicLinkName, symbolicLinkToDelete);

	return IoDeleteSymbolicLink(&symbolicLinkName);
}

NTSTATUS BugCheckIoctlHandler(PIRP pIrp)
{
	KeBugCheck(*((PULONG)pIrp->AssociatedIrp.SystemBuffer));
}

NTSTATUS UnloadDriverIoctlHandler(PIRP pIrp)
{
	UNICODE_STRING unicodeStrDriverPath;

	WCHAR* driverPath = (WCHAR*)pIrp->AssociatedIrp.SystemBuffer;
	
	RtlInitUnicodeString(&unicodeStrDriverPath, driverPath);
	
	return ZwUnloadDriver(&unicodeStrDriverPath);
}


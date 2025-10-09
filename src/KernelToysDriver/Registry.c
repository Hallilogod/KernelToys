#include "Main.h"

NTSTATUS DeleteKeyFull(HANDLE parentKeyHandle)
{

	NTSTATUS					status = STATUS_SUCCESS;
	PKEY_BASIC_INFORMATION		keyInfo = NULL;
	ULONG						outLength = 0;
	OBJECT_ATTRIBUTES			objectAttributes = { 0 };
	UNICODE_STRING				objectName = { 0 };
	HANDLE						childKey = NULL;
	ULONG						sizeReturned = 0;

	while (1)
	{
		status = ZwEnumerateKey(parentKeyHandle, 0, KeyBasicInformation, NULL, 0, &sizeReturned);

		if (!NT_SUCCESS(status))
		{
			if (status == STATUS_NO_MORE_ENTRIES)
			{
				status = STATUS_SUCCESS;
				break;
			}

			return status;
		}

		keyInfo = (PKEY_BASIC_INFORMATION)ExAllocatePool2(POOL_FLAG_NON_PAGED, (SIZE_T)sizeReturned, 'DLKY');

		if (!keyInfo)
		{
			DBGERR("Failed to allocate pool memory");

			return STATUS_INSUFFICIENT_RESOURCES;
		}

		status = ZwEnumerateKey(
			parentKeyHandle,
			0,
			KeyBasicInformation,
			keyInfo,
			sizeReturned,
			&outLength);

		if(!NT_SUCCESS(status))
		{
			ExFreePool(keyInfo);

			return status;
		}

		//	Open subkey
		objectName.Length = objectName.MaximumLength = (USHORT)keyInfo->NameLength;
		objectName.Buffer = keyInfo->Name;

		InitializeObjectAttributes(
			&objectAttributes,
			&objectName,
			OBJ_KERNEL_HANDLE,
			parentKeyHandle,
			NULL);

		status = ZwOpenKey(&childKey, DELETE | KEY_ENUMERATE_SUB_KEYS, &objectAttributes);

		ExFreePool(keyInfo);


		if (!NT_SUCCESS(status))
		{
			return status;
		}


		status = DeleteKeyFull(childKey);


		if (!NT_SUCCESS(status))
		{
			ZwClose(childKey);

			return status;
		}


		ZwClose(childKey);
	}
	
	return ZwDeleteKey(parentKeyHandle);
}




NTSTATUS CreateKeyIoctlHandler(PIRP pIrp)
{

	NTSTATUS status = STATUS_SUCCESS;
	HANDLE keyHandle = NULL;
	ULONG disposition = 0;
	UNICODE_STRING unicodeStrKeyToCreate = { 0 };
	OBJECT_ATTRIBUTES keyObjectAttributes = { 0 };

	WCHAR* keyToCreate = (WCHAR*)pIrp->AssociatedIrp.SystemBuffer;

	RtlInitUnicodeString(&unicodeStrKeyToCreate, keyToCreate);

	InitializeObjectAttributes(&keyObjectAttributes, &unicodeStrKeyToCreate, OBJ_KERNEL_HANDLE, NULL, NULL);

	status = ZwCreateKey(&keyHandle, KEY_ALL_ACCESS, &keyObjectAttributes, 0, NULL, REG_OPTION_NON_VOLATILE, &disposition);

	if (!NT_SUCCESS(status))
	{
		DBGERRNTSTATUS("ZwCreateKey", status);

		return status;
	}

	ZwClose(keyHandle);

	status = (disposition == REG_CREATED_NEW_KEY) ? STATUS_SUCCESS : STATUS_OBJECT_NAME_EXISTS;

	return status;
}

NTSTATUS DeleteKeyIoctlHandler(PIRP pIrp)
{
	NTSTATUS status = STATUS_SUCCESS;
	HANDLE keyHandle = NULL;
	UNICODE_STRING unicodeStrKeyToDelete = { 0 };
	OBJECT_ATTRIBUTES keyObjectAttributes = { 0 };

	WCHAR* keyToDelete = (WCHAR*)pIrp->AssociatedIrp.SystemBuffer;

	RtlInitUnicodeString(&unicodeStrKeyToDelete, keyToDelete);

	InitializeObjectAttributes(&keyObjectAttributes, &unicodeStrKeyToDelete, OBJ_KERNEL_HANDLE, NULL, NULL);

	status = ZwOpenKey(&keyHandle, KEY_ALL_ACCESS, &keyObjectAttributes);

	if (!NT_SUCCESS(status))
	{
		DBGERRNTSTATUS("ZwOpenKey", status);

		return status;
	}

	status = DeleteKeyFull(keyHandle);

	if (!NT_SUCCESS(status))
	{
		DBGERRNTSTATUS("DeleteKeyFull", status);
	}

	ZwClose(keyHandle);

	return status;
}

NTSTATUS SetKeyValueIoctlHandler(PIRP pIrp)
{
	return STATUS_NOT_IMPLEMENTED;
}
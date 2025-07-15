#pragma once


NTSTATUS CreateKeyIoctlHandler(PIRP pIrp);

NTSTATUS DeleteKeyIoctlHandler(PIRP pIrp);

NTSTATUS SetKeyValueIoctlHandler(PIRP pIrp);
#pragma once


NTSTATUS DeleteLinkIoctlHandler(PIRP pIrp);

NTSTATUS BugCheckIoctlHandler(PIRP pIrp);

NTSTATUS UnloadDriverIoctlHandler(PIRP pIrp);
